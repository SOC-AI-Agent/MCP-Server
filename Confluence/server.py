"""
Confluence playbook connector.

Answers one question well: which playbook covers this alert, and what does it
say. The backend asks it over a plain route at the start of triage, before any
model runs, because matching an alert name to a runbook has one right answer
and should not cost an inference.

    POST /match     {"alert_name": "..."}   -> the playbook, or an honest miss
    POST /sync                              -> re-read the space now
    GET  /health

The MCP tools are for an agent that wants to look further: read a playbook it
was not given, or list what exists. Neither can write.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

import confluence_api
import playbooks as pb
from auth import BearerAuthMiddleware
from config import missing_settings, settings
from router import AlertRouter

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("server")

@asynccontextmanager
async def lifespan(_server):
    """
    Read the playbooks once at boot, then keep them fresh.

    On MCPServer rather than on the Starlette app: the SDK builds the app
    itself and Starlette 1.6 has no add_event_handler, so this is the only
    hook. The first sync happens before the first request, which matters —
    an empty corpus answers every match with "no playbook covers this",
    and that is indistinguishable from a real gap in the wiki.
    """
    await sync()
    task = asyncio.create_task(_periodic())
    try:
        yield {}
    finally:
        task.cancel()


mcp = MCPServer(settings.MCP_SERVER_NAME, lifespan=lifespan)

# The corpus and the router built from it. Replaced wholesale on each sync so a
# half-finished refresh can never be served: a partial corpus would report "no
# playbook" for alerts that have one, which reads as a gap in the wiki.
_router: AlertRouter = AlertRouter([], settings.FUZZY_CUTOFF)
_last_sync: dict = {"at": None, "source": "none", "error": None, "count": 0}


async def sync() -> dict:
    """Re-read the playbooks and rebuild the router."""
    global _router, _last_sync
    loaded: list[pb.Playbook] = []
    source, error = "file", None

    if settings.configured:
        source = "confluence"
        try:
            base = settings.CONFLUENCE_BASE_URL.rstrip("/")
            for page in await confluence_api.fetch_pages():
                rows = confluence_api.rows_from_storage(
                    (page.get("body", {}).get("storage", {}) or {}).get("value", "")
                )
                url = base + (page.get("_links", {}) or {}).get("webui", "")
                record = pb.from_rows(page.get("id", ""), rows, url=url)
                if record:
                    loaded.append(record)
        except confluence_api.ConfluenceError as exc:
            # The previous corpus is kept. Serving yesterday's playbooks is far
            # better than serving none: a miss makes every alert look
            # uncovered, and nothing distinguishes that from a real gap.
            error = str(exc)
            logger.error("sync failed, keeping %d playbook(s): %s", len(_router.by_page), error)
            _last_sync = {**_last_sync, "error": error}
            return _last_sync
    else:
        # Startup validation refuses this, so it is only reached if that was
        # bypassed. Nothing is loaded and nothing is invented: /match answers
        # "not configured", which is a fact, where a sample playbook would be
        # a fabrication wearing the shape of one.
        error = (
            "CONFLUENCE_BASE_URL and CONFLUENCE_API_TOKEN are not set, so there "
            "is nothing to read. No playbooks are loaded."
        )
        logger.error("%s", error)
        _last_sync = {"at": None, "source": "unconfigured", "error": error, "count": 0}
        _router = AlertRouter([], settings.FUZZY_CUTOFF)
        return _last_sync

    _router = AlertRouter(loaded, settings.FUZZY_CUTOFF)
    _last_sync = {
        "at": asyncio.get_running_loop().time(),
        "source": source,
        "error": None,
        "count": len(loaded),
        **_router.stats,
    }
    logger.info("sync: %d playbook(s) from %s", len(loaded), source)
    return _last_sync


async def _periodic() -> None:
    while True:
        await asyncio.sleep(max(settings.SYNC_INTERVAL_MINUTES, 1) * 60)
        try:
            await sync()
        except Exception:  # noqa: BLE001 — a failed refresh must not kill the loop
            logger.exception("periodic sync failed")


# ── Routes: the backend's path, no MCP session and no model ─────────────────

@mcp.custom_route("/match", methods=["POST"])
async def match_route(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)

    alert_name = (body.get("alert_name") or "").strip()
    if not alert_name:
        return JSONResponse({"error": "alert_name is required"}, status_code=400)

    if not settings.configured:
        # Not a miss. A miss means the wiki was searched and covers nothing;
        # this means the wiki was never reached, and an analyst reading "no
        # playbook" should not be told the first when it is the second.
        return JSONResponse(
            {
                "matched": False,
                "how": "unconfigured",
                "playbook": None,
                "note": (
                    "This connector is not configured for Confluence, so no playbook "
                    "was searched for. This is not the same as no playbook covering "
                    "the alert. Set CONFLUENCE_BASE_URL and CONFLUENCE_API_TOKEN."
                ),
            },
            status_code=503,
        )

    result = _router.match(alert_name)
    # Said with the answer, not left for someone to ask: a match against a
    # corpus that failed to refresh is a match against yesterday's wiki.
    result["corpus"] = {
        "playbooks": len(_router.by_page),
        "source": _last_sync.get("source"),
        "stale": bool(_last_sync.get("error")),
        "error": _last_sync.get("error"),
    }
    return JSONResponse(result)


@mcp.custom_route("/sync", methods=["POST"])
async def sync_route(_: Request) -> JSONResponse:
    return JSONResponse(await sync())


@mcp.custom_route("/check-connection", methods=["GET"])
async def check_connection_route(_: Request) -> JSONResponse:
    """
    Whether this connector can reach and read Confluence, and where it stops if not.

    Behind the bearer token, unlike /health: each call goes out to Confluence
    with the service account, and an open route would let anyone who can reach
    this port make it do that. 200 when connected, 502 when Confluence is the
    problem.

        GET /check-connection
    """
    result = await confluence_api.check()
    return JSONResponse(result, status_code=200 if result["connected"] else 502)


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "server": settings.MCP_SERVER_NAME,
            "playbooks": len(_router.by_page),
            "source": _last_sync.get("source"),
            "stale": bool(_last_sync.get("error")),
            "confluence": await confluence_api.reachable(),
        }
    )


# ── Tools: for an agent that wants to look further ──────────────────────────

@mcp.tool()
async def find_playbook(alert_name: str) -> dict:
    """
    The playbook covering an alert, by its name.

    Returns what the detection is for, what makes it a true positive, what
    makes it noise, and the remediation steps. Says plainly when no playbook
    covers the alert — that is a fact worth reporting, not a reason to guess.

    Args:
        alert_name: The alert or use-case name, as the detection calls it.
    """
    return _router.match(alert_name)


@mcp.tool()
async def list_playbooks() -> dict:
    """
    Every playbook that exists, by name and category.

    Use it to see what is covered before concluding an alert has no runbook.
    """
    return {
        "count": len(_router.by_page),
        "playbooks": [
            {
                "alert_name": p.alert_name,
                "use_case_category": p.use_case_category,
                "version": p.version,
                "aliases": p.aliases,
            }
            for p in _router.by_page.values()
        ],
    }


# Refused at boot, like the other two connectors. This used to log a warning and
# carry on, which for an unset CONFLUENCE_MCP_AUTH_TOKEN meant a bearer gate whose
# token was empty — and an empty "Authorization: Bearer " header matches it.
if missing := missing_settings():
    raise RuntimeError("refusing to start, unset required env: " + ", ".join(missing))

app = mcp.streamable_http_app(stateless_http=True)
app.add_middleware(BearerAuthMiddleware, token=settings.CONFLUENCE_MCP_AUTH_TOKEN)

logger.info(
    "%s ready on :%d (confluence=%s)",
    settings.MCP_SERVER_NAME,
    settings.CONFLUENCE_MCP_PORT,
    "configured" if settings.configured else "NOT CONFIGURED — it will serve nothing",
)
