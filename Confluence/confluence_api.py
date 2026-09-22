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
from typing import Any

import httpx

from config import settings

logger = logging.getLogger("confluence")


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

            payload = resp.json()
            batch = payload.get("results", [])
            pages.extend(batch)
            if len(batch) < settings.CONFLUENCE_PAGE_LIMIT:
                break
            start += len(batch)

    logger.info("read %d page(s) from space %s", len(pages), settings.CONFLUENCE_SPACE_KEY)
    return pages


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
