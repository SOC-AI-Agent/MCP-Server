"""
Splunk, behind a small HTTP API for the backend.

Every route takes structured parameters and builds its own SPL — see spl.py for why
a caller never gets to hand this service a search string. The backend plans the
search (which index, which sourcetype, which fields carry the indicator) from the
data catalogue, and this runs it: the same allowlist, the same field checks and the
same quoting whoever is asking.

There is no MCP layer and no model in this service. It used to publish the same
searches as MCP tools for an agent to call; the backend now runs every planned search
directly, so those tools, the transport and the curated catalogue file that described
them for a model are gone. What is left is what the backend calls.
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

# A 7b model runs on a 4k context. Whole Splunk events do not fit, so trim each
# one to the fields that carry meaning plus a bounded slice of _raw.
MAX_RAW_CHARS = 800
# Splunk bookkeeping. Dropped because none of it helps read an event, and two
# of them actively mislead: `host` on forwarded syslog is the forwarder, not the
# machine the alert is about, and `source` is a file path on that forwarder.
# Leaving them in put 192.168.65.1 in front of an analyst as if it meant
# something.
DROPPED_FIELDS = frozenset({
    "_bkt", "_cd", "_indextime", "_serial", "_si", "_sourcetype", "_kv",
    "linecount", "punct", "splunk_server", "eventtype", "tag", "timestamp",
    "host", "source",
})

_routes: list[Route] = []


def route(path: str, methods: list[str]):
    """Register a handler. Collected here and handed to Starlette at the bottom."""

    def register(handler):
        _routes.append(Route(path, handler, methods=methods))
        return handler

    return register


def _trim(event: dict) -> dict:
    trimmed = {}
    for key, value in event.items():
        if key in DROPPED_FIELDS:
            continue
        if key == "_raw" and isinstance(value, str) and len(value) > MAX_RAW_CHARS:
            value = value[:MAX_RAW_CHARS] + f"… [{len(value) - MAX_RAW_CHARS} chars truncated]"
        trimmed[key] = value
    return trimmed


async def _run(spl_query: str, earliest: str, latest: str, count: int) -> list[dict]:
    # A SplunkError is left to propagate: the routes answer it with a 502, which
    # says the platform is the problem. It used to be turned into a ToolError for
    # a model to read, and a route then reported a Splunk outage as a 400.
    rows = await splunk.search(spl_query, earliest, latest, count)
    return [_trim(r) for r in rows]


async def _summarise(
    index: str,
    group_by: list[str],
    metrics: list[dict],
    earliest: str,
    latest: str,
    sourcetype: str | None,
    filters: dict[str, str] | None,
    span: str | None,
    sort: str | None,
    max_rows: int,
) -> dict:
    """What the /summarise route runs."""
    count = spl.check_count(max_rows)
    earliest = spl.check_time(earliest, "earliest")
    latest = spl.check_time(latest, "latest")
    group_by = list(group_by or [])

    terms = [spl.index_clause(index)]
    scoped = {"sourcetype": sourcetype, **(filters or {})}
    equality = spl.equality_terms({k: v for k, v in scoped.items() if v is not None})
    if equality:
        terms.append(equality)

    pipeline = f"search {' '.join(terms)} "
    if span:
        # Bucketing goes before stats, and _time joins the grouping — otherwise
        # the bin is computed and then thrown away by the aggregation.
        pipeline += f"| bin _time span={spl.check_span(span)} "
        group_by = ["_time", *group_by]

    pipeline += f"| {spl.stats_clause(metrics, group_by)} "

    produced = {"count"} | {
        f"{m.get('field')}_{m.get('fn')}" for m in metrics if m.get("field")
    } | set(group_by)
    pipeline += spl.sort_clause(sort, produced)
    pipeline += f"| head {count}"

    rows = await _run(pipeline, earliest, latest, count)
    return {
        "index": index,
        "sourcetype": sourcetype,
        "group_by": group_by,
        "rows": rows,
        "count": len(rows),
        # Same reason as the event searches: a row count at the ceiling is a
        # floor, not a total, and reading it as a total is the mistake.
        "capped": len(rows) >= count,
        "limit": count,
        "earliest": earliest,
        "latest": latest,
        "spl": pipeline.strip(),
    }


async def _alert_frequency(
    alert_name: str,
    days: int,
    earliest: str | None = None,
    latest: str | None = None,
) -> dict:
    """
    What the /frequency route runs.

    `earliest`/`latest` override the relative window. The caller usually has
    them: a window read as `-7d` at execution time drifts away from the alert
    exactly as `-24h` did, just more slowly, and "has not fired in 7 days" is
    the kind of wrong answer that reads as reassurance.
    """
    if not 1 <= days <= 90:
        raise spl.QueryError("days must be between 1 and 90")
    name_field = spl.check_field(settings.SPLUNK_ALERT_NAME_FIELD)
    query = (
        f"search {spl.index_clause(settings.SPLUNK_ALERT_INDEX)} "
        f"{name_field}={spl.quote_value(alert_name)} "
        f"| bin _time span=1d | stats count by _time | sort _time"
    )
    window_from = spl.check_time(earliest, "earliest") if earliest else f"-{days}d@d"
    window_to = spl.check_time(latest, "latest") if latest else "now"
    rows = await _run(query, window_from, window_to, 100)

    per_day = {r["_time"]: int(r["count"]) for r in rows if r.get("_time")}
    total = sum(per_day.values())
    return {
        "alert_name": alert_name,
        "window_days": days,
        "total": total,
        "days_seen": len(per_day),
        "mean_per_active_day": round(total / len(per_day), 2) if per_day else 0,
        "per_day": per_day,
        "earliest": window_from,
        "latest": window_to,
        "spl": query,
    }


async def _indicator_search(
    indicator: str,
    indicator_type: str,
    fields: list[str],
    earliest: str,
    latest: str,
    max_count: int,
    index: str | None = None,
    sourcetype: str | None = None,
) -> dict:
    """
    One indicator across the fields that carry it — what the /search route runs.
    The backend has already worked out which fields, and which index and
    sourcetype; this validates them, builds the SPL and returns the events.
    """
    count = spl.check_count(max_count)
    earliest = spl.check_time(earliest, "earliest")
    latest = spl.check_time(latest, "latest")

    terms = [spl.index_clause(index), spl.any_of_terms(fields, indicator)]
    if sourcetype:
        terms.append(spl.equality_terms({"sourcetype": sourcetype}))

    query = f"search {' '.join(t for t in terms if t)} | head {count}"
    events = await _run(query, earliest, latest, count)

    # Which field each event matched on. The search is an OR across every field
    # that could carry this indicator, so "2 events" alone does not say whether
    # the host reached out or was reached — and for an address that is the
    # difference between a beacon and a scan. Cheap to answer here, impossible
    # to answer from the count afterwards.
    for event in events:
        event["matched_on"] = [f for f in fields if str(event.get(f, "")) == indicator]

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        # Saying which fields were searched turns an empty result from "nothing
        # happened" into something checkable.
        "fields_searched": fields,
        "index": index,
        "sourcetype": sourcetype,
        "count": len(events),
        # `| head N` stops at N and says nothing. A count of 20 out of 20 is
        # indistinguishable from a count of 20 out of four thousand, and a
        # reader who cannot see the cut will take the first as the whole.
        "capped": len(events) >= count,
        "limit": count,
        "earliest": earliest,
        "latest": latest,
        "events": events,
        "spl": query,
    }


# ── Catalog ─────────────────────────────────────────────────────────────────
# What indexes, sourcetypes and fields this token can actually see.
#
# An operator pulls this once and a person writes the data catalogue from it
# (docs/splunk-catalog.md); the backend then plans its searches from that file.
# Example values are real data, which is why they are behind a flag.
#
#   GET /catalog                          field names and cardinality
#   GET /catalog?values=true              also example values — real data
#   GET /catalog?index=fortigate&sample=1000
#
# Behind the bearer middleware: /health is the only unauthenticated path.

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


# ── Planned search ──────────────────────────────────────────────────────────
# The backend already knows what it wants: which indicator, which kind, which
# fields carry it here, which index and sourcetype. Handing that to a model so
# it could write the same parameters back out cost 488 seconds per lookup on
# CPU-only inference, of which Splunk used 0.4 — which is why no model is asked.
#
# The caller is the backend executing a plan a person can read beforehand, not a
# model choosing.
#
# Behind the same bearer middleware as everything except /health. Every value
# still goes through spl.py — the index allowlist, the field-name check and the
# quoting are not skipped because the caller is trusted.

@route("/search", methods=["POST"])
async def search_route(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)

    indicator = (body.get("indicator") or "").strip()
    indicator_type = (body.get("indicator_type") or "").strip()
    fields = body.get("fields") or []
    if not indicator or not indicator_type:
        return JSONResponse(
            {"error": "indicator and indicator_type are required"}, status_code=400
        )
    if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
        return JSONResponse({"error": "fields must be a list of strings"}, status_code=400)
    if not fields:
        # The caller resolves fields from the catalog; falling back to a guess
        # here is what produced confident empty answers before.
        return JSONResponse(
            {"error": f"no fields given for indicator_type={indicator_type!r}"},
            status_code=400,
        )

    try:
        result = await _indicator_search(
            indicator,
            indicator_type,
            fields,
            body.get("earliest") or "-24h",
            body.get("latest") or "now",
            int(body.get("max_count") or 20),
            body.get("index"),
            body.get("sourcetype"),
        )
    except spl.QueryError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except SplunkError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)
    except Exception as exc:  # noqa: BLE001 — the caller needs the reason, not a 500
        logger.exception("planned search failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)

    return JSONResponse(result)


@route("/summarise", methods=["POST"])
async def summarise_route(request: Request) -> JSONResponse:
    """
    Group and count instead of listing: how many distinct destinations a host
    reached, how often something happened per hour, how many were blocked against
    allowed. Listing twenty raw events answers none of those — a host that
    contacted five hundred addresses and one that contacted one both return
    twenty lines.
    """
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)

    index = (body.get("index") or "").strip()
    if not index:
        return JSONResponse({"error": "index is required"}, status_code=400)
    metrics = body.get("metrics") or [{"fn": "count"}]
    if not isinstance(metrics, list):
        return JSONResponse({"error": "metrics must be a list"}, status_code=400)

    try:
        result = await _summarise(
            index,
            body.get("group_by") or [],
            metrics,
            body.get("earliest") or "-24h",
            body.get("latest") or "now",
            body.get("sourcetype"),
            body.get("filters"),
            body.get("span"),
            body.get("sort"),
            int(body.get("max_rows") or 50),
        )
    except spl.QueryError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except SplunkError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)
    except Exception as exc:  # noqa: BLE001
        logger.exception("planned summary failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)

    return JSONResponse(result)


@route("/frequency", methods=["POST"])
async def frequency_route(request: Request) -> JSONResponse:
    """
    How often one alert has fired.

    The backend has the alert name and the window from the moment the alert
    arrived. Handing those to an agent so it could ask the same question back
    took 109 seconds of the 111 a whole lookup cost.
    """
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)

    alert_name = (body.get("alert_name") or "").strip()
    if not alert_name:
        return JSONResponse({"error": "alert_name is required"}, status_code=400)
    try:
        days = int(body.get("days") or 7)
    except (TypeError, ValueError):
        return JSONResponse({"error": "days must be a number"}, status_code=400)

    try:
        return JSONResponse(
            await _alert_frequency(
                alert_name, days, body.get("earliest"), body.get("latest")
            )
        )
    except spl.QueryError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except SplunkError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)
    except Exception as exc:  # noqa: BLE001
        logger.exception("planned frequency check failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)


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
