"""Bearer-token gate in front of the MCP transport."""

import logging
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("auth")

# Unauthenticated so a container healthcheck does not need the token.
PUBLIC_PATHS = frozenset({"/health"})


class BearerAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, token: str) -> None:
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")

        # compare_digest keeps the check constant-time; a plain == leaks the
        # token one character at a time to anything that can measure latency.
        # Compared as bytes: given a str with a non-ASCII character it raises
        # TypeError, which an unauthenticated caller could use to get a 500.
        if scheme.lower() != "bearer" or not secrets.compare_digest(
            presented.encode(), self._token.encode()
        ):
            logger.warning("rejected unauthenticated request from %s", request.client)
            return JSONResponse({"detail": "unauthorized"}, status_code=401)

        return await call_next(request)
