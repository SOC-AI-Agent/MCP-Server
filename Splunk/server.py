"""
Splunk, behind a small HTTP API for the backend.

The backend plans a search and writes the SPL itself (Backend:
modules/enrichment/spl.ts); this service runs it at POST /query, after checking it
again (spl.check_query): a read-only search over an allowed index, nothing else.
Nothing here builds a search from parameters.

There is no MCP layer and no model in this service. It used to publish searches as MCP
tools for an agent, then as parameter routes for the backend; both are gone. What is
left is /query, the operator's /catalog, and the connection check.
"""

import json
import logging

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

import spl
from auth import BearerAuthMiddleware
from config import settings, validate_startup
from splunk_api import SplunkError, splunk

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("server")

_routes: list[Route] = []


def route(path: str, methods: list[str]):
    """Register a handler. Collected here and handed to Starlette at the bottom."""

    def register(handler):
        _routes.append(Route(path, handler, methods=methods))
        return handler

    return register


def _flag(request: Request, name: str) -> bool:
    return request.query_params.get(name, "").lower() in ("1", "true", "yes")


def _int_param(request: Request, name: str, default: int, ceiling: int) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        return max(1, min(int(raw), ceiling))
    except ValueError:
        return default


@route("/catalog", methods=["GET"])
# Named for what it is rather than for its path: `catalog` is the module that
# holds the curated file, and a route function of the same name shadows it.
async def catalog_route(request: Request) -> JSONResponse:
    include_values = _flag(request, "values")
    sample = _int_param(request, "sample", 200, CATALOG_MAX_SAMPLE)
    max_sourcetypes = _int_param(request, "max_sourcetypes", 50, CATALOG_MAX_SOURCETYPES)
    only_index = request.query_params.get("index")

    # Enumerating an estate is worth an audit line, and so is asking for values.
    logger.info(
        "catalog requested from %s — values=%s sample=%d max_sourcetypes=%d index=%s",
        request.client, include_values, sample, max_sourcetypes, only_index or "*",
    )

    try:
        scope = spl.index_clause(only_index) if only_index else spl.index_clause(None)
    except spl.QueryError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    result: dict = {
        "allowed_indexes": "*" if settings.index_restriction_disabled
        else settings.allowed_indexes,
        "values_included": include_values,
        "sample_per_sourcetype": sample,
    }

    try:
        models = await splunk.search("| rest /services/data/models | table title",
                                     "-1m", "now", 200)
        names = [r["title"] for r in models if r.get("title")]
        result["data_models"] = names
        # Whether the estate is CIM-normalised decides how much mapping work is
        # left, so say it rather than making the reader infer it from a list.
        result["cim_normalised"] = any(not n.startswith("internal_") for n in names)

        rows = await splunk.search(
            f"| tstats count where {scope} by index, sourcetype", "-30d", "now", 1000
        )
    except SplunkError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=502)

    indexes: dict[str, list] = {}
    pairs: list[tuple[str, str]] = []
    for row in rows:
        index, sourcetype = row.get("index"), row.get("sourcetype")
        if not index or not sourcetype:
            continue
        indexes.setdefault(index, []).append(
            {"sourcetype": sourcetype, "events": int(row.get("count", 0))}
        )
        pairs.append((index, sourcetype))

    result["indexes"] = indexes
    result["sourcetype_count"] = len(pairs)
    result["truncated"] = len(pairs) > max_sourcetypes

    fields: dict[str, dict] = {}
    for index, sourcetype in pairs[:max_sourcetypes]:
        query = (
            f"search index={spl.quote_value(index)} sourcetype={spl.quote_value(sourcetype)} "
            f"| head {sample} | fieldsummary maxvals=3"
        )
        try:
            summary = await splunk.search(query, "-30d", "now", 500)
        except SplunkError as exc:
            fields[f"{index}/{sourcetype}"] = {"error": str(exc)}
            continue

        described: dict[str, dict] = {}
        for row in summary:
            name = row.get("field", "")
            if not name or name.startswith("_") or name in CATALOG_SKIP_FIELDS:
                continue
            entry: dict = {"distinct": row.get("distinct_count")}
            if include_values:
                try:
                    entry["examples"] = [
                        str(v["value"])[:40] for v in json.loads(row.get("values", "[]"))[:3]
                    ]
                except (ValueError, TypeError, KeyError):
                    entry["examples"] = []
            described[name] = entry
        fields[f"{index}/{sourcetype}"] = described

    result["fields"] = fields
    if not include_values:
        result["note"] = (
            "Example values omitted. Add ?values=true to include them — they are "
            "real data from the index, so treat the reply accordingly."
        )
    return JSONResponse(result)


# ── Query ───────────────────────────────────────────────────────────────────
# The backend writes the SPL (Backend: modules/enrichment/spl.ts — the index
# allowlist, the field checks, the quoting) and sends it here to be run. This route
# does not trust that: check_query refuses anything that is not a read-only search
# over an allowed index, whoever is asking. It is the same rule set, checked twice.
#
#   POST /query  {"spl": "search index=\"main\" srcip=\"10.1.100.11\" | head 20",
#                 "earliest": "-24h", "latest": "now", "count": 20}
#   -> {"results": [...], "count": 20, "earliest": ..., "latest": ..., "limit": 20}
#
# Rows are returned as Splunk gave them. Trimming them for a small model, and
# working out what they mean, is the caller's job.
#
# Behind the same bearer middleware as everything except /health.

@route("/query", methods=["POST"])
async def query_route(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)

    try:
        query = spl.check_query(body.get("spl"))
        earliest = spl.check_time(body.get("earliest") or "-24h", "earliest")
        latest = spl.check_time(body.get("latest") or "now", "latest")
        count = spl.check_count(int(body.get("count") or 20))
        rows = await splunk.search(query, earliest, latest, count)
    except (TypeError, ValueError) as exc:
        # ValueError is also what QueryError is: int() of a count that is not a
        # number lands here too, and is the caller's mistake either way.
        return JSONResponse({"error": str(exc)}, status_code=400)
    except SplunkError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)
    except Exception as exc:  # noqa: BLE001 — the caller needs the reason, not a 500
        logger.exception("query failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)

    return JSONResponse(
        {"results": rows, "count": len(rows), "earliest": earliest, "latest": latest, "limit": count}
    )


@route("/check-connection", methods=["GET"])
async def check_connection_route(_: Request) -> JSONResponse:
    """
    Whether this connector can reach and use Splunk, and where it stops if not.

    Behind the bearer token, unlike /health: each call goes out to Splunk with
    the service token and runs a search, and an open route would let anyone who
    can reach this port make it do that. 200 when connected, 502 when Splunk is
    the problem.

        GET /check-connection
    """
    result = await splunk.check()
    return JSONResponse(result, status_code=200 if result["connected"] else 502)


@route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {"status": "ok", "server": settings.MCP_SERVER_NAME, "splunk": await splunk.reachable()}
    )


validate_startup()

# No per-client session state, so any replica can serve any request.
app = Starlette(routes=_routes)
app.add_middleware(BearerAuthMiddleware, token=settings.MCP_AUTH_TOKEN)

logger.info(
    "%s ready on :%d — indexes=%s",
    settings.MCP_SERVER_NAME,
    settings.MCP_PORT,
    settings.SPLUNK_ALLOWED_INDEXES,
)
