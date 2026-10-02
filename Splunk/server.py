"""
Splunk for the backend, over MCP — shaped like Splunk's own MCP Server.

The backend's Splunk stage sends each requirement, as text, to `saia_generate_spl`
(Text-to-SPL), and runs the SPL that comes back with `splunk_run_query`. Those are
the names Splunk's MCP Server app gives these tools, served at the path it serves
them (/services/mcp), so moving the backend to real Splunk is a change of URL and
token, not of code — see README "Production".

SPLUNK_MODE=mock answers both tools from mock.py. live runs splunk_run_query against
SPLUNK_BASE_URL; Text-to-SPL itself only exists in Splunk. Either way a search is
checked before it runs (spl.check_readonly): nothing that writes, deletes, sends or
executes, and only allowed indexes.

No model runs here and no agent calls these tools: the backend calls them, one
requirement at a time. The plain routes stay — POST /query (SPL the backend wrote,
under the stricter spl.check_query), the operator's /catalog and the connection
check.
"""

import json
import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

import mock
import spl
from auth import BearerAuthMiddleware
from config import settings, validate_startup
from splunk_api import SplunkError, splunk

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("server")

mcp = MCPServer(settings.MCP_SERVER_NAME)


# ── MCP tools ──────────────────────────────────────────────────────────────────
# Named, and argued, as Splunk's MCP Server names them.

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)
# Splunk's own guardrail fails a search that answers more than 1000 events.
MAX_EVENTS = 1000


@mcp.tool(annotations=_READ_ONLY)
async def saia_generate_spl(prompt: str) -> dict:
    """Generate SPL from a natural-language search request (Splunk AI Assistant for SPL)."""
    if not prompt or not prompt.strip():
        raise ToolError("prompt is required")
    if not settings.mock:
        raise ToolError(
            "Text-to-SPL is Splunk AI Assistant for SPL, served by Splunk's own MCP server. "
            "This connector only imitates it in SPLUNK_MODE=mock; point the backend's "
            "SPLUNK_MCP_URL at https://<splunk>:8089/services/mcp instead."
        )
    generated = mock.generate_spl(prompt)
    logger.info("saia_generate_spl (mock) -> %s", generated["spl"])
    return generated


@mcp.tool(annotations=_READ_ONLY)
async def splunk_run_query(query: str, workload_pool: str | None = None) -> dict:
    """Execute a Splunk search query (SPL) and return the results.

    workload_pool is accepted for compatibility with Splunk's MCP Server and unused here.
    """
    try:
        checked = spl.check_readonly(query)
    except spl.QueryError as exc:
        raise ToolError(str(exc)) from exc

    limit = min(MAX_EVENTS, settings.SPLUNK_MAX_COUNT)
    if settings.mock:
        rows = mock.run_query(checked, limit)
    else:
        search = checked if checked.startswith(("search", "|")) else f"search {checked}"
        try:
            # The search's own earliest=/latest= win over this default window.
            rows = await splunk.search(search, "-24h", "now", limit)
        except SplunkError as exc:
            raise ToolError(str(exc)) from exc
    logger.info("splunk_run_query (%s) -> %d row(s): %s", settings.SPLUNK_MODE, len(rows), checked)
    return {"results": rows, "count": len(rows), "limit": limit, "mock": settings.mock}


# ── Plain routes ───────────────────────────────────────────────────────────────

CATALOG_MAX_SAMPLE = 5000
CATALOG_MAX_SOURCETYPES = 200
# Splunk bookkeeping. None of it helps anyone decide which field means "source
# IP", and punct is noisy enough to bury what does.
CATALOG_SKIP_FIELDS = frozenset({"punct", "linecount", "eventtype", "tag", "index", "splunk_server"})


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


@mcp.custom_route("/catalog", methods=["GET"])
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
# SPL an operator writes by hand, run in live mode — the stage-2 path is the MCP
# tools above. check_query refuses anything that is not a read-only search over an
# allowed index, whoever is asking.
#
#   POST /query  {"spl": "search index=\"main\" srcip=\"10.1.100.11\" | head 20",
#                 "earliest": "-24h", "latest": "now", "count": 20}
#   -> {"results": [...], "count": 20, "earliest": ..., "latest": ..., "limit": 20}
#
# Rows are returned as Splunk gave them. Trimming them for a small model, and
# working out what they mean, is the caller's job.
#
# Behind the same bearer middleware as everything except /health.

@mcp.custom_route("/query", methods=["POST"])
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


@mcp.custom_route("/check-connection", methods=["GET"])
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


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {"status": "ok", "server": settings.MCP_SERVER_NAME, "splunk": await splunk.reachable()}
    )


validate_startup()

app = mcp.streamable_http_app(
    # Where Splunk's MCP Server answers, so the backend's URL keeps the same shape.
    streamable_http_path="/services/mcp",
    # No per-client session state, so any replica can serve any request.
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(allowed_hosts=settings.allowed_hosts),
)
app.add_middleware(BearerAuthMiddleware, token=settings.MCP_AUTH_TOKEN)

if settings.mock:
    logger.warning(
        "%s ready on :%d — SPLUNK_MODE=mock: MCP tools answer from mock.py, not Splunk",
        settings.MCP_SERVER_NAME, settings.MCP_PORT,
    )
else:
    logger.info(
        "%s ready on :%d — live, indexes=%s",
        settings.MCP_SERVER_NAME, settings.MCP_PORT, settings.SPLUNK_ALLOWED_INDEXES,
    )
