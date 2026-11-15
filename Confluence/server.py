"""
Confluence for the stack, over MCP: the playbook space, read-only.

Holds the Confluence credentials and is the one thing that talks to Confluence.
It reads pages and hands them over as Confluence stores them; what a page means —
which fields make a playbook, which playbook covers an alert — is decided by
soc-ai, which extracts, embeds and matches them.

MCP tools, at /mcp:

    confluence_read_pages    every page that is read, with its body (storage XHTML)
    confluence_list_pages    the same pages without their bodies
    confluence_get_page      one page of the space, as storage XHTML or plain text

Plain routes:

    GET /pages               what confluence_read_pages returns, for a caller
                             that would rather not speak MCP for megabytes of XHTML
    GET /check-connection    can Confluence be read right now, and where it stops if not
    GET /health

Nothing here writes to Confluence, keeps a copy of it, or runs a model. There is
no mock: an unconfigured connector refuses to start rather than serve a made-up
playbook (config.validate_startup).
"""

import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

import confluence_api
from auth import BearerAuthMiddleware
from config import settings, validate_startup
from confluence_api import ConfluenceError

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("server")

mcp = MCPServer(settings.CONFLUENCE_MCP_SERVER_NAME)

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)


def _listing(pages: list[dict]) -> dict:
    return {"space_key": settings.space_key, "count": len(pages), "pages": pages}


# ── MCP tools ──────────────────────────────────────────────────────────────────

@mcp.tool(annotations=_READ_ONLY)
async def confluence_read_pages() -> dict:
    """Every current page of the playbook space, with its body.

    Returns space_key, count and pages: [{id, title, version, url, body}]. body is
    Confluence's storage-format XHTML, unparsed. Large: a space of a few hundred
    pages is megabytes. An error, never an empty list, when the space cannot be read.
    """
    try:
        pages = await confluence_api.read_pages(body=True)
    except ConfluenceError as exc:
        raise ToolError(str(exc)) from exc
    logger.info("confluence_read_pages -> %d page(s)", len(pages))
    return _listing(pages)


@mcp.tool(annotations=_READ_ONLY)
async def confluence_list_pages() -> dict:
    """The pages of the playbook space, without their bodies.

    Returns space_key, count and pages: [{id, title, version, url}] — what exists,
    and the id to read one with confluence_get_page.
    """
    try:
        pages = await confluence_api.read_pages(body=False)
    except ConfluenceError as exc:
        raise ToolError(str(exc)) from exc
    logger.info("confluence_list_pages -> %d page(s)", len(pages))
    return _listing(pages)


@mcp.tool(annotations=_READ_ONLY)
async def confluence_get_page(page_id: str, format: str = "storage") -> dict:
    """One page of the playbook space, by its id.

    format "storage" (the default) returns body as Confluence's storage-format
    XHTML; "text" returns it as plain text, a line per block. A page outside the
    playbook space is refused.
    """
    if format not in ("storage", "text"):
        raise ToolError('format must be "storage" or "text"')
    try:
        page = await confluence_api.read_page(page_id)
    except ConfluenceError as exc:
        raise ToolError(str(exc)) from exc
    if format == "text":
        page["body"] = confluence_api.text_of(page["body"])
    logger.info("confluence_get_page %s (%s) -> %d char(s)", page["id"], format, len(page["body"]))
    return {**page, "format": format}


# ── Plain routes ───────────────────────────────────────────────────────────────

@mcp.custom_route("/pages", methods=["GET"])
async def pages_route(_: Request) -> JSONResponse:
    """
    Every current page that is read, as Confluence stores it.

        GET /pages -> {space_key, count, pages: [{id, title, version, url, body}]}

    502 when Confluence cannot be read — never an empty list, which the caller
    would take for an empty space.
    """
    try:
        pages = await confluence_api.read_pages(body=True)
    except ConfluenceError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)
    return JSONResponse(_listing(pages))


@mcp.custom_route("/check-connection", methods=["GET"])
async def check_connection_route(_: Request) -> JSONResponse:
    """
    Whether this connector can reach and read Confluence, and where it stops if not.

    Behind the bearer token, unlike /health: each call goes out to Confluence
    with the service account, and an open route would let anyone who can reach
    this port make it do that. 200 when connected, 502 when Confluence is the
    problem.
    """
    result = await confluence_api.check()
    return JSONResponse(result, status_code=200 if result["connected"] else 502)


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "server": settings.CONFLUENCE_MCP_SERVER_NAME,
        "confluence": await confluence_api.reachable(),
    })


validate_startup()

app = mcp.streamable_http_app(
    # No per-client session state, so any replica can serve any request.
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(allowed_hosts=settings.allowed_hosts),
)
app.add_middleware(BearerAuthMiddleware, token=settings.CONFLUENCE_MCP_AUTH_TOKEN)

logger.info(
    "%s ready on :%d — %s, space %s, api %s%s",
    settings.CONFLUENCE_MCP_SERVER_NAME, settings.CONFLUENCE_MCP_PORT, settings.base_url,
    settings.space_key, settings.api_version,
    ", through a proxy" if settings.CONFLUENCE_PROXY.strip() else "",
)
