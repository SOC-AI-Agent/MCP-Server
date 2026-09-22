"""
soc-mcp-threatq — indicator reputation, two ways in.

    POST /lookup            many indicators at once, for the core backend
    tool lookup_indicator   one indicator, for an agent mid-analysis

The split is the point. The backend checks every external indicator in an alert
before any model runs: that is exact work with one right answer, so there is
nothing to decide and deciding would only be a chance to skip it. It calls the
route, over plain HTTP, with no MCP session to hold.

The tool covers what the backend cannot know in advance. An agent searching
Splunk turns up addresses that were not in the original alert, and those have
never been checked. One tool, one indicator at a time — not an interface for
enumerating the platform.

Nothing here writes to ThreatQ. Its operations can add indicators, change
status and fire actions, and the alert text steering the model is
attacker-influenced; a read-only account is the second layer under that.
"""

import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth import BearerAuthMiddleware
from config import settings, validate_startup
from threatq_api import ThreatQError, threatq_auth, threatq_lookup

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("server")

mcp = MCPServer(settings.MCP_SERVER_NAME)

INDICATOR_TYPES = ("ip", "domain", "url", "hash", "email")


@mcp.tool()
async def lookup_indicator(value: str, indicator_type: str = "ip") -> dict:
    """
    What threat intelligence knows about one indicator.

    The indicators in the alert have already been checked before you were
    called — their results are in the context you were given. Use this for one
    that turned up since: an address a log search returned, a domain named in an
    event you retrieved.

    A missing record means ThreatQ has not seen it. That is UNKNOWN, not clean:
    intelligence trails an attacker, and infrastructure stood up this week has
    no record yet.

    Args:
        value: The indicator, e.g. "45.83.122.9" or "cdn.example.com".
        indicator_type: One of ip, domain, url, hash, email.
    """
    if indicator_type not in INDICATOR_TYPES:
        raise ToolError(f"indicator_type must be one of {', '.join(INDICATOR_TYPES)}")
    if not value.strip():
        raise ToolError("value must not be empty")

    try:
        record = await threatq_lookup(indicator_type, value.strip())
    except ThreatQError as exc:
        # ToolError so the message reaches the model, which can usually carry on
        # without this one lookup.
        raise ToolError(str(exc)) from exc

    if not record.get("found"):
        record["note"] = (
            "No record in ThreatQ. This means unknown, not safe — say so rather "
            "than describing the indicator as clean."
        )
    return record


@mcp.custom_route("/lookup", methods=["POST"])
async def lookup_route(request: Request) -> JSONResponse:
    """
    Many indicators at once, for the core backend's enrichment step.

    A route rather than a tool: nothing the model chooses should be able to
    enumerate the platform, and the backend needs no MCP session to ask a
    question with one right answer.

        POST /lookup  {"indicators": [{"type": "ip", "value": "45.83.122.9"}]}
    """
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"detail": "body must be JSON"}, status_code=400)

    raw = body.get("indicators")
    if not isinstance(raw, list) or not raw:
        return JSONResponse(
            {"detail": "indicators must be a non-empty array of {type, value}"},
            status_code=400,
        )
    if len(raw) > settings.THREATQ_LOOKUP_MAX:
        return JSONResponse(
            {"detail": f"at most {settings.THREATQ_LOOKUP_MAX} indicators per call"},
            status_code=400,
        )

    wanted = [
        {"type": str(i.get("type", "")), "value": str(i.get("value", "")).strip()}
        for i in raw
        if isinstance(i, dict) and str(i.get("value", "")).strip()
    ]
    logger.info("lookup requested for %d indicators from %s", len(wanted), request.client)

    records: list[dict] = []
    for item in wanted:
        try:
            records.append(await threatq_lookup(item["type"], item["value"]))
        except ThreatQError as exc:
            # One indicator failing must not lose the rest: the caller reports
            # what it could check and says so for the remainder.
            records.append({**item, "found": False, "error": str(exc)})

    return JSONResponse({"records": records, "checked": len(wanted)})


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "server": settings.MCP_SERVER_NAME,
            "threatq": await threatq_auth.reachable(),
        }
    )


validate_startup()

app = mcp.streamable_http_app(
    # No per-client session state to keep, so any replica can serve any request.
    stateless_http=True,
    transport_security=TransportSecuritySettings(allowed_hosts=settings.allowed_hosts),
)
app.add_middleware(BearerAuthMiddleware, token=settings.THREATQ_MCP_AUTH_TOKEN)

logger.info(
    "%s ready on :%d — upstream=%s",
    settings.MCP_SERVER_NAME,
    settings.THREATQ_MCP_PORT,
    settings.THREATQ_BASE_URL,
)
