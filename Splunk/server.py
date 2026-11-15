"""
Splunk for the backend, over MCP.

The backend's Splunk stage sends each requirement stage 1 stored — the question, the
details from the alert, where to look — to one tool, `splunk_lookup`, and gets back
the SPL that ran and its rows. Everything Splunk-shaped happens here (lookup.py): the
prompt, Text-to-SPL, the read-only check, the search, trimming the rows.
`splunk_text_to_spl` is the first half alone, with nothing searched.

Who writes the SPL is the caller's choice. Left to this service, Text-to-SPL is a
template or Splunk AI Assistant (below). Or the caller has an agent of its own write
it: `splunk_prompt` gives the text to show that agent, and its reply goes back in as
the `spl` argument of the other two tools, to be read, checked and run like any other
SPL. No model is called from here either way.

Under them are the two tools Splunk's own MCP Server app publishes, by the same names
at the same path (/services/mcp): `saia_generate_spl` (Text-to-SPL) and
`splunk_run_query`.

Where the SPL comes from and where it runs:

  SPLUNK_MODE=mock   a template writes it; a fixed set of events answers (mock.py).
  SPLUNK_MODE=live   it runs against SPLUNK_BASE_URL — the Splunk container in
                     external/splunk, or the company's. A template writes it
                     (text_to_spl.py), or Splunk AI Assistant for SPL does when
                     SPLUNK_SAIA_MCP_URL names a Splunk MCP server (saia.py).

Either way a search is checked before it runs (spl.check_readonly): nothing that
writes, deletes, sends or executes, and only allowed indexes.

No model runs here and no agent calls these tools: the backend calls them, one
requirement at a time. The plain routes stay — POST /query (SPL an operator wrote,
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

import lookup
import mock
import saia
import spl
import text_to_spl
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


async def _text_to_spl(prompt: str) -> dict:
    """Text-to-SPL, by whoever does it in this mode. Raises ToolError."""
    if settings.mock:
        return mock.generate_spl(prompt)
    if not settings.saia:
        return text_to_spl.generate(prompt)
    try:
        answered = await saia.generate(prompt)
    except saia.SaiaError as exc:
        raise ToolError(str(exc)) from exc
    return answered if isinstance(answered, dict) else {"spl": lookup.spl_of(answered), "text": str(answered)}


async def _run(query: str) -> tuple[str, list[dict], int]:
    """Check a search and run it: (the SPL that ran, its rows, the row limit). Raises ToolError."""
    try:
        checked = spl.check_readonly(query)
    except spl.QueryError as exc:
        raise ToolError(str(exc)) from exc

    limit = _limit()
    if settings.mock:
        rows = mock.run_query(checked, limit)
    else:
        search = checked if checked.startswith(("search", "|")) else f"search {checked}"
        try:
            # The search's own earliest=/latest= win over this default window.
            rows = await splunk.search(search, "-24h", "now", limit)
        except SplunkError as exc:
            raise ToolError(str(exc)) from exc
    return checked, rows, limit


@mcp.tool(annotations=_READ_ONLY)
async def saia_generate_spl(prompt: str) -> dict:
    """Generate SPL from a natural-language search request (Splunk AI Assistant for SPL)."""
    if not prompt or not prompt.strip():
        raise ToolError("prompt is required")
    generated = await _text_to_spl(prompt)
    logger.info("saia_generate_spl (%s) -> %s", settings.SPLUNK_MODE, generated.get("spl"))
    return generated


@mcp.tool(annotations=_READ_ONLY)
async def splunk_run_query(query: str, workload_pool: str | None = None) -> dict:
    """Execute a Splunk search query (SPL) and return the results.

    workload_pool is accepted for compatibility with Splunk's MCP Server and unused here.
    """
    checked, rows, limit = await _run(query)
    logger.info("splunk_run_query (%s) -> %d row(s): %s", settings.SPLUNK_MODE, len(rows), checked)
    return {"results": rows, "count": len(rows), "limit": limit, "mock": settings.mock}


# ── The backend's tools ────────────────────────────────────────────────────────
# One requirement in, as stage 1 stored it. A requirement that cannot be answered
# is an answer too: `error` says why and `prompt` what was asked, so the backend
# can keep it beside the ones that worked. Only a question that cannot be read at
# all is a tool error.

def _limit() -> int:
    return min(MAX_EVENTS, settings.SPLUNK_MAX_COUNT)


def _question(question: lookup.Question) -> None:
    if not question.requirement.strip():
        raise ToolError("question.requirement is required")


async def _draft(question: lookup.Question, written: str | None = None) -> dict:
    """Text-to-SPL — or the SPL the caller had written — and the check.
    {prompt, generated, spl} or {prompt, generated?, refused|error}, with who wrote it."""
    _question(question)
    prompt, earliest, latest = lookup.build_prompt(question)
    if written is not None:
        # An agent's reply, as it came: the SPL is found in it, never taken on trust.
        draft = {"prompt": prompt, "written_by": "caller"}
        generated = lookup.spl_of(written)
        if not generated:
            return {**draft, "error": "no SPL in what was written for this requirement: "
                                      f"{' '.join(written.split())[:200] or '(empty)'}"}
    else:
        draft = {"prompt": prompt, "written_by": "assistant" if settings.saia else "template"}
        try:
            generated = lookup.spl_of(await _text_to_spl(prompt))
        except ToolError as exc:
            return {**draft, "error": str(exc)}
        if not generated:
            return {**draft, "error": f"Text-to-SPL returned no SPL for: {prompt}"}
    try:
        checked = spl.check_readonly(
            lookup.with_all_fields(lookup.with_time_window(generated, earliest, latest), _limit())
        )
    except spl.QueryError as exc:
        return {**draft, "generated": generated, "refused": str(exc)}
    return {**draft, "generated": generated, "spl": checked}


@mcp.tool(annotations=_READ_ONLY)
async def splunk_prompt(question: lookup.Question) -> dict:
    """What to show an agent that writes the SPL for one requirement. Nothing is run.

    Returns prompt (the request: the requirement, the details, where to search, the
    time range) and writer_prompt (the same, followed by the answer format). Send
    writer_prompt to the agent and pass its reply as `spl` to splunk_lookup or
    splunk_text_to_spl.
    """
    _question(question)
    prompt, earliest, latest = lookup.build_prompt(question)
    return {
        "prompt": prompt,
        "writer_prompt": lookup.writer_prompt(prompt, _limit()),
        "earliest": earliest,
        "latest": latest,
    }


@mcp.tool(annotations=_READ_ONLY)
async def splunk_text_to_spl(question: lookup.Question, spl: str | None = None) -> dict:
    """The SPL for one requirement, and whether it would be run. Nothing is searched.

    Returns prompt (the text sent to Text-to-SPL), generated (the SPL as written) and
    either spl (what would run, with the time window added) or refused (why not).
    Pass `spl` — an agent's reply to splunk_prompt, as it came — to have that checked
    instead of this service's own Text-to-SPL.
    """
    draft = await _draft(question, spl)
    logger.info("splunk_text_to_spl (%s, %s) -> %s", settings.SPLUNK_MODE, draft["written_by"],
                draft.get("spl") or draft.get("refused") or draft.get("error"))
    return {**draft, "searched": False, "mock": settings.mock}


@mcp.tool(annotations=_READ_ONLY)
async def splunk_lookup(question: lookup.Question, spl: str | None = None) -> dict:
    """Answer one requirement from Splunk: write the SPL, check it, run it.

    Returns prompt, spl (what ran), rows (trimmed for a small model), count, capped,
    limit, mock and answer (the rows as text). A requirement that could not be
    answered returns prompt and error instead. Pass `spl` — an agent's reply to
    splunk_prompt, as it came — to have that checked and run instead of this
    service's own Text-to-SPL.
    """
    draft = await _draft(question, spl)
    if "spl" not in draft:
        reason = draft.get("error") or f"the generated SPL was refused: {draft['refused']}"
        return {**draft, "error": reason, "mock": settings.mock}
    try:
        ran, found, limit = await _run(draft["spl"])
    except ToolError as exc:
        return {**draft, "error": str(exc), "mock": settings.mock}

    rows = [lookup.trim_row(r) for r in found[:limit]]
    capped = len(found) >= limit
    logger.info("splunk_lookup (%s, %s) -> %d row(s): %s",
                settings.SPLUNK_MODE, draft["written_by"], len(rows), ran)
    return {
        "prompt": draft["prompt"],
        "written_by": draft["written_by"],
        "generated": draft["generated"],
        "spl": ran,
        "rows": rows,
        "count": len(rows),
        "capped": capped,
        "limit": limit,
        "mock": settings.mock,
        "answer": lookup.render(ran, rows, capped, limit, settings.mock),
    }


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
        "%s ready on :%d — live, splunk=%s indexes=%s text-to-spl=%s",
        settings.MCP_SERVER_NAME, settings.MCP_PORT, settings.SPLUNK_BASE_URL,
        settings.SPLUNK_ALLOWED_INDEXES,
        f"Splunk AI Assistant at {saia.endpoint()}" if settings.saia else "template",
    )
