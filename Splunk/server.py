"""
MCP server exposing Splunk to the SOC agent (../../ai-service).

This is the *server* half: it publishes tools over MCP streamable HTTP. The
client half lives in ai-service, which discovers these tools at runtime and
never imports anything from this directory.

Every tool takes structured parameters and builds its own SPL — see spl.py for
why the model never gets to write a search string itself.
"""

import json
import logging
from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

import catalog
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

mcp = MCPServer(settings.MCP_SERVER_NAME)


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
    try:
        rows = await splunk.search(spl_query, earliest, latest, count)
    except SplunkError as exc:
        # ToolError, not a bare raise: the SDK puts its message in the tool
        # result for the model to read, where an unexpected exception would be
        # masked to "Error executing tool" and leave it guessing.
        raise ToolError(str(exc)) from exc
    return [_trim(r) for r in rows]


@mcp.tool()
async def list_indexes() -> dict:
    """
    What data this Splunk holds: the indexes you may search, what each one is
    for, and which field carries which meaning.

    ALWAYS call this first. Field names differ between sourcetypes, and a search
    on the wrong field returns nothing — which reads exactly like "there is
    nothing to find". `key_fields` maps a meaning to the field name to use: if
    it says `src_ip: srcip`, then filter on `srcip`, not on `src_ip` or `host`.

    Use `describe_sourcetype` when you need the full field list for one of them.
    """
    if catalog.loaded():
        return {
            "indexes": catalog.summary(),
            "usage": "Filter with the field names in key_fields. A field not "
                     "listed there may still exist — describe_sourcetype shows all of them.",
        }

    # No catalog: the names are all there is to offer, and nothing here knows
    # what any field means. Say so rather than let the model assume CIM.
    if settings.index_restriction_disabled:
        rows = await _run("| eventcount summarize=false index=*", "-24h", "now", 100)
        names = sorted({r["index"] for r in rows if r.get("index")})
    else:
        names = settings.allowed_indexes
    return {
        "indexes": names,
        "warning": "No data catalog is configured, so field names are unknown. "
                   "Look at an event with search_events before assuming a field name.",
    }


@mcp.tool()
async def describe_sourcetype(sourcetype: str) -> dict:
    """
    The fields in one sourcetype, and what they mean.

    Call this before filtering on a field you have not seen used, especially
    when a search came back empty — an empty result usually means the field name
    was wrong, not that the data is absent.

    Args:
        sourcetype: Name as it appears in list_indexes.
    """
    entry = catalog.sourcetype(sourcetype)
    if entry is None:
        known = [
            st for index in catalog.indexes().values()
            for st in (index.get("sourcetypes") or {})
        ]
        raise ToolError(
            f"sourcetype {sourcetype!r} is not in the data catalog"
            + (f"; known: {', '.join(known)}" if known else " (no catalog configured)")
        )

    return {
        "index": entry["index"],
        "sourcetype": entry["sourcetype"],
        "purpose": entry.get("purpose", ""),
        "key_fields": {r: f for r, f in (entry.get("roles") or {}).items() if r in catalog.ROLES},
        "fields": entry.get("fields", []),
        # The gotchas are the whole reason a person writes this file rather than
        # a script generating it.
        "notes": entry.get("notes", []),
    }


@mcp.tool()
async def search_events(
    index: str,
    earliest: str = "-24h",
    latest: str = "now",
    sourcetype: str | None = None,
    host: str | None = None,
    filters: dict[str, str] | None = None,
    max_count: int = 20,
) -> dict:
    """
    Search raw events in one index over a time range.

    Args:
        index: Index to search. Must be one returned by list_indexes.
        earliest: Start of the window, e.g. "-24h", "-7d@d", or an ISO timestamp.
        latest: End of the window, e.g. "now".
        sourcetype: Optional sourcetype to narrow to.
        host: Optional hostname to narrow to.
        filters: Optional extra field=value pairs, all of which must match.
        max_count: Maximum events to return.
    """
    count = spl.check_count(max_count)
    earliest = spl.check_time(earliest, "earliest")
    latest = spl.check_time(latest, "latest")

    terms = [spl.index_clause(index)]
    scoped = {"sourcetype": sourcetype, "host": host, **(filters or {})}
    equality = spl.equality_terms({k: v for k, v in scoped.items() if v is not None})
    if equality:
        terms.append(equality)

    query = f"search {' '.join(terms)} | head {count}"
    events = await _run(query, earliest, latest, count)
    return {"count": len(events), "events": events, "spl": query}


@mcp.tool()
async def summarise_events(
    index: str,
    group_by: list[str],
    metrics: list[dict],
    earliest: str = "-24h",
    latest: str = "now",
    sourcetype: str | None = None,
    filters: dict[str, str] | None = None,
    span: str | None = None,
    sort: str | None = None,
    max_rows: int = 50,
) -> dict:
    """
    Count and group events instead of listing them.

    Use this when the question is about shape rather than instances — how many
    distinct destinations a host reached, how often something happened per
    hour, how many were blocked against allowed. Listing twenty raw events
    answers none of those: a host that contacted five hundred addresses and one
    that contacted one both return twenty lines.

    Args:
        index: Index to search.
        group_by: Fields to group by, e.g. ["dstip"] or ["action"].
        metrics: What to compute, e.g. [{"fn": "count"},
            {"fn": "distinct_count", "field": "dstport"}].
            fn is one of: count, distinct_count, sum, avg, min, max, values.
        earliest: Start of the window.
        latest: End of the window.
        sourcetype: Optional sourcetype to narrow to.
        filters: Optional field=value pairs, all of which must match.
        span: Bucket results by time, e.g. "5m", "1h". Adds _time to the groups.
        sort: Column to sort by, "-" first for descending, e.g. "-count".
        max_rows: Maximum rows to return.
    """
    return await _summarise(
        index, group_by, metrics, earliest, latest, sourcetype, filters, span, sort, max_rows
    )


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
    """Shared by the tool and the /summarise route, so the two cannot drift."""
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


@mcp.tool()
async def alert_frequency(alert_name: str, days: int = 7) -> dict:
    """
    Count how often an alert or correlation search has fired recently.

    Use this to judge whether an alert is routine noise or unusual. A high,
    steady daily count suggests a known false-positive pattern; a first-ever
    occurrence deserves closer reading.

    Args:
        alert_name: Alert / correlation-search name exactly as Splunk stores it.
        days: How many days back to count over (1-90).
    """
    if not 1 <= days <= 90:
        raise ToolError("days must be between 1 and 90")

    return await _alert_frequency(alert_name, days)


async def _alert_frequency(
    alert_name: str,
    days: int,
    earliest: str | None = None,
    latest: str | None = None,
) -> dict:
    """
    Shared by the tool and the /frequency route, so the two cannot drift.

    `earliest`/`latest` override the relative window. The caller usually has
    them: a window read as `-7d` at execution time drifts away from the alert
    exactly as `-24h` did, just more slowly, and "has not fired in 7 days" is
    the kind of wrong answer that reads as reassurance.
    """
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


@mcp.tool()
async def related_events(
    indicator: str,
    indicator_type: Literal["ip", "host", "user", "hash", "domain"],
    earliest: str = "-24h",
    latest: str = "now",
    max_count: int = 20,
) -> dict:
    """
    Find events across all allowed indexes mentioning one indicator.

    Use this to pull context around an entity named in an alert — what else the
    source IP touched, what else the user did, where a hash appeared.

    Args:
        indicator: The value to look for, e.g. "10.1.2.3" or "jdoe".
        indicator_type: Which kind of entity `indicator` is.
        earliest: Start of the window, e.g. "-24h".
        latest: End of the window, e.g. "now".
        max_count: Maximum events to return.
    """
    # Field names come from the data catalog, not from a guess. The CIM names
    # this used to hardcode (src_ip, dest_ip) do not exist in raw vendor logs,
    # so the search matched nothing and the answer read as "no related activity"
    # — a wrong answer with no error to notice.
    fields = catalog.fields_for_indicator(indicator_type)
    if not fields:
        raise ToolError(
            f"no field is mapped to indicator_type={indicator_type!r}. "
            "Add it to the data catalog (SPLUNK_CATALOG_FILE)."
        )
    return await _indicator_search(
        indicator, indicator_type, fields, earliest, latest, max_count
    )


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
    One indicator across the fields that carry it.

    Shared by the tool above and the /search route below, so the two cannot
    drift: the same validation, the same SPL construction, the same shape back.
    Only the caller differs — a model choosing for itself, or the backend
    running a plan it already worked out.
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
# Deliberately a custom route and NOT a tool. A tool would put "enumerate every
# field in every index, with example values" in the hands of a model that reads
# attacker-influenced alert text — one injected instruction away from paging
# real data into a summary an analyst reads. Routes do not appear in tools/list,
# so the agent cannot reach this at all; an operator pulls the catalog once and
# whatever should reach the model gets written into its prompt by a person.
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
    except ToolError as exc:
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
# it can write the same parameters back out cost 488 seconds per lookup on
# CPU-only inference, of which Splunk used 0.4. This route is the same search
# without the transcription.
#
# A route rather than a tool, for the reason /catalog is: the caller is the
# backend executing a plan a person can read beforehand, not a model choosing.
# The agent keeps related_events for the cases nobody planned for.
#
# Behind the same bearer middleware as everything except /health. Every value
# still goes through spl.py — the index allowlist, the field-name check and the
# quoting are not skipped because the caller is trusted.

@mcp.custom_route("/search", methods=["POST"])
async def search_route(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)

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
    except ToolError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001 — the caller needs the reason, not a 500
        logger.exception("planned search failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)

    return JSONResponse(result)


@mcp.custom_route("/summarise", methods=["POST"])
async def summarise_route(request: Request) -> JSONResponse:
    """
    The planned form of summarise_events.

    Same reason /search exists: when the caller already knows what it wants
    grouped and counted, a model in the middle only retypes it.
    """
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)

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
    except ToolError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        logger.exception("planned summary failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)

    return JSONResponse(result)


@mcp.custom_route("/frequency", methods=["POST"])
async def frequency_route(request: Request) -> JSONResponse:
    """
    How often one alert has fired — planned, so no model is needed to ask.

    The backend has the alert name and the window from the moment the alert
    arrived. Sending those to an agent so it can call alert_frequency with them
    took 109 seconds of the 111 a whole lookup now costs.
    """
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)

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
    except ToolError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        logger.exception("planned frequency check failed")
        return JSONResponse({"error": f"{type(exc).__name__}: {exc}"}, status_code=502)


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {"status": "ok", "server": settings.MCP_SERVER_NAME, "splunk": await splunk.reachable()}
    )


validate_startup()
catalog.load()

app = mcp.streamable_http_app(
    # No per-client session state to keep, so any replica can serve any request
    # — that is what lets this connector scale on its own.
    stateless_http=True,
    transport_security=TransportSecuritySettings(allowed_hosts=settings.allowed_hosts),
)
app.add_middleware(BearerAuthMiddleware, token=settings.MCP_AUTH_TOKEN)

logger.info(
    "%s ready on :%d — indexes=%s",
    settings.MCP_SERVER_NAME,
    settings.MCP_PORT,
    settings.SPLUNK_ALLOWED_INDEXES,
)
