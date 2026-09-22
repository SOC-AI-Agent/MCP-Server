"""
Auth against the ThreatQ platform, shared by both modes.

This module holds the credentials and nothing else. Neither mode builds its own
HTTP session against ThreatQ without going through `auth_header()`, so there is
one place where a token is minted, cached and refreshed.

UNVERIFIED: the OAuth2 password grant below follows ThreatQ's documented REST
scheme (POST /api/token with grant_type=password + client_id). It has not been
exercised against a live instance from this repo. If your deployment issues
flat API tokens instead, set THREATQ_AUTH_MODE=bearer and skip all of this.
"""

import logging
import time

from typing import Any

import httpx

from config import settings

logger = logging.getLogger("threatq")

# Refresh this many seconds before the server's stated expiry, so a token never
# expires mid-flight on a slow search.
EXPIRY_MARGIN_SECONDS = 60


class ThreatQError(RuntimeError):
    """Anything that stops ThreatQ from answering."""


class ThreatQAuth:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.THREATQ_BASE_URL.rstrip("/"),
            verify=settings.THREATQ_VERIFY_SSL,
            timeout=settings.THREATQ_TIMEOUT,
        )
        self._token: str | None = None
        self._expires_at: float = 0.0

    async def auth_header(self, force_refresh: bool = False) -> dict[str, str]:
        """Bearer header for ThreatQ. Mints or refreshes the token as needed."""
        if settings.THREATQ_AUTH_MODE == "bearer":
            return {"Authorization": f"Bearer {settings.THREATQ_TOKEN}"}

        if force_refresh or self._token is None or time.monotonic() >= self._expires_at:
            await self._mint()
        return {"Authorization": f"Bearer {self._token}"}

    async def _mint(self) -> None:
        try:
            resp = await self._client.post(
                settings.THREATQ_TOKEN_PATH,
                data={
                    "grant_type": "password",
                    "client_id": settings.THREATQ_CLIENT_ID,
                    "email": settings.THREATQ_EMAIL,
                    "password": settings.THREATQ_PASSWORD,
                },
            )
        except httpx.HTTPError as exc:
            raise ThreatQError(
                f"cannot reach ThreatQ at {settings.THREATQ_BASE_URL}: {exc}"
            ) from exc

        if resp.status_code in (400, 401):
            # Deliberately does not echo the body: a failed password grant can
            # repeat the submitted credentials back.
            raise ThreatQError(
                "ThreatQ rejected the credentials (%d) — check THREATQ_CLIENT_ID, "
                "THREATQ_EMAIL and THREATQ_PASSWORD" % resp.status_code
            )
        if resp.status_code >= 400:
            raise ThreatQError(f"ThreatQ token endpoint returned {resp.status_code}")

        try:
            body = resp.json()
        except ValueError as exc:
            raise ThreatQError("ThreatQ token endpoint returned a non-JSON body") from exc

        token = body.get("access_token")
        if not token:
            raise ThreatQError("ThreatQ token response carried no access_token")

        self._token = token
        self._expires_at = time.monotonic() + max(
            int(body.get("expires_in", 3600)) - EXPIRY_MARGIN_SECONDS, 60
        )
        logger.info("minted ThreatQ access token")

    async def reachable(self) -> bool:
        """
        Health only — never raises, so a dead ThreatQ still reports status.

        Under oauth the token exchange is itself the probe. Under bearer there
        is nothing to exchange, so the platform is asked directly: any HTTP
        answer means it is up, and only a transport error means it is not. This
        reports reachability, not whether the token is accepted.
        """
        try:
            if settings.THREATQ_AUTH_MODE == "oauth":
                await self.auth_header()
                return True
            resp = await self._client.get("/")
            return resp.status_code < 500
        except (ThreatQError, httpx.HTTPError):
            return False

    async def aclose(self) -> None:
        await self._client.aclose()


threatq_auth = ThreatQAuth()


# Looking up by value is POST /api/indicators/search, not a GET on the
# collection — GET /api/indicators takes only limit, offset, sort and with.
# Criteria follow ThreatQ's SOLR-like convention, e.g.
#   {"+and": [{"source_name": "Analyst"}]}
# A single field is the simple case of that.
#
# Confirmed against the REST API Reference v5.12; the exact criteria key for an
# indicator's value is the one part still inferred, so it is a setting.
async def threatq_lookup(indicator_type: str, value: str) -> dict:
    """
    One indicator's reputation.

    Returns a record with `found` either way: "ThreatQ has never seen this" is
    an answer the caller needs, and is not the same as "clean".
    """
    headers = await threatq_auth.auth_header()
    criteria: dict[str, Any] = {"value": value}
    if indicator_type:
        criteria["type"] = indicator_type

    async with httpx.AsyncClient(
        base_url=settings.THREATQ_BASE_URL.rstrip("/"),
        verify=settings.THREATQ_VERIFY_SSL,
        timeout=settings.THREATQ_TIMEOUT,
    ) as client:
        try:
            resp = await client.post(
                settings.THREATQ_SEARCH_PATH,
                params={"with": settings.THREATQ_SEARCH_WITH, "limit": 1},
                json={"criteria": criteria},
                headers=headers,
            )
            if resp.status_code == 401:
                # The token expired between minting and using it. One retry on a
                # fresh token, because the alternative is reporting an indicator
                # as unknown for a reason that has nothing to do with ThreatQ.
                headers = await threatq_auth.auth_header(force_refresh=True)
                resp = await client.post(
                    settings.THREATQ_SEARCH_PATH,
                    params={"with": settings.THREATQ_SEARCH_WITH, "limit": 1},
                    json={"criteria": criteria},
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            raise ThreatQError(f"cannot reach ThreatQ: {exc}") from exc

    # 404 is documented as "Object not found".
    if resp.status_code == 404:
        return {"type": indicator_type, "value": value, "found": False}
    if resp.status_code == 401:
        raise ThreatQError("ThreatQ rejected the credentials (401)")
    if resp.status_code >= 400:
        raise ThreatQError(f"ThreatQ returned {resp.status_code}: {resp.text[:200]}")

    try:
        body = resp.json()
    except ValueError as exc:
        raise ThreatQError("ThreatQ returned a non-JSON body") from exc

    # Records come back under `data`. An empty array is the other way a miss is
    # reported, so both shapes mean the same thing here.
    data = body.get("data") if isinstance(body, dict) else None
    entry = (data[0] if isinstance(data, list) and data else None) or (
        data if isinstance(data, dict) else None
    )
    if not isinstance(entry, dict) or not entry:
        return {"type": indicator_type, "value": value, "found": False}

    return _record(indicator_type, value, entry)


def _name(item: Any) -> Any:
    """Related objects come back as objects with a `name`; some deployments
    flatten them to strings."""
    return item.get("name", item) if isinstance(item, dict) else item


def _record(indicator_type: str, value: str, entry: dict) -> dict:
    # `score` is an object when asked for by name, a number when the deployment
    # flattens it.
    score = entry.get("score")
    if isinstance(score, dict):
        score = score.get("generated_score", score.get("score", score.get("value")))

    attributes = {
        a.get("name"): a.get("value")
        for a in (entry.get("attributes") or [])
        if isinstance(a, dict) and a.get("name")
    }

    return {
        "type": indicator_type,
        "value": value,
        "found": True,
        "id": entry.get("id"),
        "score": score,
        "status": _name(entry.get("status")),
        "sources": [_name(s) for s in (entry.get("sources") or [])],
        "adversaries": [_name(a) for a in (entry.get("adversaries") or [])],
        "attributes": attributes,
        "first_seen": entry.get("created_at") or entry.get("first_seen"),
        "last_seen": entry.get("updated_at") or entry.get("last_seen"),
    }
