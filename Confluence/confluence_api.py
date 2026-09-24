"""
Reading playbook pages out of Confluence.

Playbooks are authored with a Page Properties macro, which stores each field as
a row in a table. The REST API returns the page body as storage-format XHTML,
so the rows are parsed out of that rather than fetched as structured data —
Confluence has no endpoint that hands back page properties as fields.
"""

from __future__ import annotations

import base64
import logging
import re
import time
from typing import Any

import httpx

from config import settings

logger = logging.getLogger("confluence")


# A connection check that hangs for CONFLUENCE_TIMEOUT on a host that silently
# drops packets is not answering the question it was asked.
CHECK_TIMEOUT_SECONDS = 10


class ConfluenceError(RuntimeError):
    pass


def _auth_header() -> dict[str, str]:
    # Cloud uses email + API token as basic auth. A Server/DC personal access
    # token is sent as a bearer instead, which is why the email is optional.
    if settings.CONFLUENCE_EMAIL:
        raw = f"{settings.CONFLUENCE_EMAIL}:{settings.CONFLUENCE_API_TOKEN}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    return {"Authorization": f"Bearer {settings.CONFLUENCE_API_TOKEN}"}


_ROW = re.compile(r"<tr>(.*?)</tr>", re.S | re.I)
_CELL = re.compile(r"<t[hd][^>]*>(.*?)</t[hd]>", re.S | re.I)


def rows_from_storage(html: str) -> dict[str, str]:
    """
    The Page Properties table as {label: value}.

    Only two-column rows are taken. A row with one cell is a heading and a row
    with three is a different table that happens to be on the page; neither is
    a property, and treating them as one would put junk in the record.
    """
    out: dict[str, str] = {}
    for row in _ROW.findall(html or ""):
        cells = _CELL.findall(row)
        if len(cells) != 2:
            continue
        label = re.sub(r"<[^>]+>", " ", cells[0])
        label = re.sub(r"\s+", " ", label).replace("&nbsp;", " ").strip()
        if label:
            out[label] = cells[1]
    return out


async def fetch_pages() -> list[dict[str, Any]]:
    """
    Every page in the space, with its body.

    Paged through to the end rather than taking the first batch: a space that
    grew past one page of results would otherwise lose playbooks silently, and
    the alerts they cover would start reporting "no playbook".
    """
    if not settings.configured:
        raise ConfluenceError("CONFLUENCE_BASE_URL and CONFLUENCE_API_TOKEN are not set")

    base = settings.CONFLUENCE_BASE_URL.rstrip("/") + settings.CONFLUENCE_API_PATH
    pages: list[dict[str, Any]] = []
    start = 0

    async with httpx.AsyncClient(
        timeout=settings.CONFLUENCE_TIMEOUT, verify=settings.CONFLUENCE_VERIFY_SSL
    ) as client:
        while True:
            try:
                resp = await client.get(
                    f"{base}/content",
                    params={
                        "spaceKey": settings.CONFLUENCE_SPACE_KEY,
                        "type": "page",
                        "status": "current",
                        "expand": "body.storage,version",
                        "limit": settings.CONFLUENCE_PAGE_LIMIT,
                        "start": start,
                    },
                    headers=_auth_header(),
                )
            except httpx.HTTPError as exc:
                raise ConfluenceError(f"could not reach Confluence: {exc}") from exc

            if resp.status_code == 401:
                raise ConfluenceError("Confluence rejected the credentials (401)")
            if resp.status_code == 404:
                raise ConfluenceError(
                    f"space {settings.CONFLUENCE_SPACE_KEY!r} not found (404)"
                )
            if resp.status_code >= 400:
                raise ConfluenceError(f"Confluence returned {resp.status_code}: {resp.text[:200]}")

            # A 200 is not proof of JSON: an SSO gateway in front of Confluence
            # answers 200 with its login page. That has to be the sync error
            # the caller already handles, and not an exception that ends the
            # process at boot.
            try:
                payload = resp.json()
            except ValueError as exc:
                raise ConfluenceError(
                    "Confluence returned a non-JSON body (200) — is CONFLUENCE_BASE_URL "
                    "behind a login page?"
                ) from exc
            batch = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(batch, list):
                raise ConfluenceError("Confluence returned JSON without a results list")
            pages.extend(batch)
            if len(batch) < settings.CONFLUENCE_PAGE_LIMIT:
                break
            start += len(batch)

    logger.info("read %d page(s) from space %s", len(pages), settings.CONFLUENCE_SPACE_KEY)
    return pages


async def check() -> dict:
    """
    Can this connector use Confluence right now? Never raises.

    One authenticated read of the space the playbooks live in, and the answer
    says where it stopped:

        config  there is nothing to connect with
        reach   no answer, or an answer that is not Confluence's REST API —
                including the login page an SSO gateway sends with a 200
        auth    the credentials were refused (401)
        read    authenticated, but the space is not visible to this account

    Reads the space's own record and nothing from inside it: no page is
    fetched and nothing is written.
    """
    started = time.monotonic()

    def outcome(failed_at: str | None = None, error: str | None = None) -> dict:
        result: dict[str, Any] = {
            "connected": failed_at is None,
            "base_url": settings.CONFLUENCE_BASE_URL,
            "space_key": settings.CONFLUENCE_SPACE_KEY,
            "latency_ms": int((time.monotonic() - started) * 1000),
        }
        if failed_at:
            result["failed_at"] = failed_at
            result["error"] = error
        return result

    if not settings.configured:
        return outcome("config", "CONFLUENCE_BASE_URL and CONFLUENCE_API_TOKEN are not set")

    path = f"{settings.CONFLUENCE_API_PATH}/space/{settings.CONFLUENCE_SPACE_KEY}"
    try:
        async with httpx.AsyncClient(
            timeout=min(settings.CONFLUENCE_TIMEOUT, CHECK_TIMEOUT_SECONDS),
            verify=settings.CONFLUENCE_VERIFY_SSL,
        ) as client:
            resp = await client.get(
                settings.CONFLUENCE_BASE_URL.rstrip("/") + path, headers=_auth_header()
            )
    except httpx.HTTPError as exc:
        return outcome("reach", f"cannot reach Confluence at {settings.CONFLUENCE_BASE_URL}: "
                                f"{type(exc).__name__}: {exc}")

    if resp.status_code == 401:
        return outcome("auth", "Confluence rejected the credentials (401)")
    if resp.status_code == 403:
        return outcome("read", f"Confluence refused the read (403) — the account cannot "
                               f"see space {settings.CONFLUENCE_SPACE_KEY!r}")
    if resp.status_code == 404:
        return outcome("read", f"space {settings.CONFLUENCE_SPACE_KEY!r} not found (404) — the "
                               "key is wrong, the account cannot see it, or CONFLUENCE_BASE_URL "
                               "is missing a path such as /wiki")

    # Only 2xx with a space in it counts. A redirect to a login page is not an
    # API answer, and neither is a 200 that carries the login page itself.
    body = None
    if 200 <= resp.status_code < 300:
        try:
            body = resp.json()
        except ValueError:
            body = None
    if isinstance(body, dict) and body.get("key"):
        return outcome()
    return outcome("reach", f"Confluence's REST API did not answer properly: {resp.status_code} "
                            f"for GET {path} — is CONFLUENCE_BASE_URL behind a login page, or "
                            "missing a path such as /wiki?")


async def reachable() -> bool:
    """A real call, not a guess. /health must not claim a connection it has not made."""
    if not settings.configured:
        return False
    base = settings.CONFLUENCE_BASE_URL.rstrip("/") + settings.CONFLUENCE_API_PATH
    try:
        async with httpx.AsyncClient(
            timeout=10, verify=settings.CONFLUENCE_VERIFY_SSL
        ) as client:
            resp = await client.get(
                f"{base}/space",
                params={"limit": 1},
                headers=_auth_header(),
            )
        return resp.status_code < 400
    except httpx.HTTPError:
        return False
