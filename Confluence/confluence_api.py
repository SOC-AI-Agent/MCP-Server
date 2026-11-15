"""
Reading the playbook space out of Confluence. Read-only: nothing here writes.

Two REST APIs, picked by CONFLUENCE_API: v2 for Cloud, where Atlassian is retiring
v1, and v1 for Server/Data Center, which has nothing else. Both are paged through
to the end rather than taking the first batch — a space that grew past one batch
would otherwise lose playbooks silently, and the alerts they cover would start
reporting "no playbook".

The same reading the backend does itself (Backend:
modules/enrichment/playbook-sync.service.ts), so the two return the same pages.
"""

from __future__ import annotations

import base64
import html
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from config import settings

logger = logging.getLogger("confluence")

# A connection check that hangs for CONFLUENCE_TIMEOUT on a host that silently
# drops packets is not answering the question it was asked.
CHECK_TIMEOUT_SECONDS = 10
V2_MAX_LIMIT = 250
# /descendants answers this many levels a call; what sits at the last one is
# asked again for what is under it.
TREE_DEPTH = 10


class ConfluenceError(RuntimeError):
    """Anything that stops Confluence from being read. `kind` says where it stopped:
    reach, auth or read — what /check-connection reports as failed_at."""

    def __init__(self, message: str, kind: str = "read") -> None:
        super().__init__(message)
        self.kind = kind


def _auth_header() -> dict[str, str]:
    # Cloud uses email + API token as basic auth. A Server/DC personal access
    # token is sent as a bearer instead, which is why the email is optional.
    if settings.CONFLUENCE_EMAIL:
        raw = f"{settings.CONFLUENCE_EMAIL}:{settings.CONFLUENCE_API_TOKEN}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    return {"Authorization": f"Bearer {settings.CONFLUENCE_API_TOKEN}"}


def _client(timeout: float | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout or settings.CONFLUENCE_TIMEOUT,
        verify=settings.CONFLUENCE_VERIFY_SSL,
        headers={**_auth_header(), "Accept": "application/json"},
        proxy=settings.CONFLUENCE_PROXY.strip() or None,
        # No proxy at all when none is set, not one picked up from the environment.
        trust_env=False,
        # A redirect is a login page in front of the API, and following it would
        # send the credentials wherever it points.
        follow_redirects=False,
    )


async def _get(client: httpx.AsyncClient, url: str, params: dict | None = None) -> dict:
    """One GET: what each refusal means, and a 200 that is not JSON is not an answer."""
    path = urlsplit(url).path
    via = ", or the proxy refused" if settings.CONFLUENCE_PROXY.strip() else ""
    try:
        resp = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        raise ConfluenceError(
            f"cannot reach Confluence at {settings.base_url}: {type(exc).__name__}: {exc}", "reach"
        ) from exc

    if resp.status_code == 401:
        raise ConfluenceError("Confluence rejected the credentials (401)", "auth")
    if resp.status_code == 403:
        raise ConfluenceError(
            f"Confluence refused the read (403) — the account cannot see space {settings.space_key}{via}"
        )
    if resp.status_code == 407:
        raise ConfluenceError(
            "the proxy wants credentials of its own (407): CONFLUENCE_PROXY=http://user:pass@host:port",
            "reach",
        )
    if resp.status_code == 404:
        raise ConfluenceError(
            f"not found (404) at {path} — no such space {settings.space_key} or page, one the "
            "account cannot see, or CONFLUENCE_BASE_URL is missing a path such as /wiki"
        )
    if 300 <= resp.status_code < 400:
        raise ConfluenceError(
            f"Confluence redirected ({resp.status_code}) GET {path} — is CONFLUENCE_BASE_URL "
            "behind a login page?",
            "reach",
        )
    if resp.status_code >= 400:
        raise ConfluenceError(f"Confluence returned {resp.status_code}: {resp.text[:200]}")
    # An SSO gateway in front of Confluence answers 200 with its login page.
    try:
        data = resp.json()
    except ValueError as exc:
        raise ConfluenceError(
            "Confluence returned a non-JSON body (200) — is CONFLUENCE_BASE_URL behind a login page?",
            "reach",
        ) from exc
    if not isinstance(data, dict):
        raise ConfluenceError("Confluence answered with JSON that is not an object", "reach")
    return data


def _results(data: dict) -> list:
    if not isinstance(data.get("results"), list):
        raise ConfluenceError(
            "Confluence answered without a results list — is CONFLUENCE_BASE_URL behind a login page?",
            "reach",
        )
    return data["results"]


def _next(data: dict) -> str | None:
    """The next batch's URL. v2's next is a path from the site's root, cursor and all."""
    link = (data.get("_links") or {}).get("next")
    return urljoin(settings.base_url + "/", link) if link else None


def _page(raw: dict, base: str, body: bool) -> dict:
    """One page as the backend and soc-ai know it. `body` is the storage-format
    XHTML, unparsed: this connector does not decide what a page means."""
    page = {
        "id": str(raw.get("id") or ""),
        "title": raw.get("title") or "",
        "version": (raw.get("version") or {}).get("number"),
        "url": base + ((raw.get("_links") or {}).get("webui") or ""),
    }
    if body:
        page["body"] = ((raw.get("body") or {}).get("storage") or {}).get("value") or ""
    return page


# ── The space ──────────────────────────────────────────────────────────────────

async def _space_v2(client: httpx.AsyncClient) -> dict:
    """The space's record from its key: v2 addresses a space by id."""
    key = settings.space_key
    spaces = _results(await _get(client, f"{settings.base_url}/api/v2/spaces", {"keys": key}))
    space = next((s for s in spaces if isinstance(s, dict) and s.get("key") == key), None)
    if not space or not space.get("id"):
        raise ConfluenceError(f"space {key} not found — or the account cannot see it")
    return space


async def _read_v1(client: httpx.AsyncClient, body: bool) -> list[dict]:
    """Server/DC (and Cloud while it lasts): GET <api path>/content, offset paging."""
    limit = settings.CONFLUENCE_PAGE_LIMIT
    raw: list = []
    start = 0
    while True:
        data = await _get(client, f"{settings.base_url}{settings.CONFLUENCE_API_PATH}/content", {
            "spaceKey": settings.space_key, "type": "page", "status": "current",
            "expand": "body.storage,version" if body else "version", "limit": limit, "start": start,
        })
        batch = _results(data)
        raw.extend(batch)
        # The end is where Confluence stops offering a next page, not the first
        # batch shorter than asked for: it may cap the page size below
        # CONFLUENCE_PAGE_LIMIT (it does when bodies are expanded), and stopping
        # there would return the first batch of the space and quietly drop the
        # rest. Without _links at all, by the page size it says it used.
        links = data.get("_links")
        more = bool(links.get("next")) if isinstance(links, dict) else len(batch) >= (data.get("limit") or limit)
        if not more or not batch:
            break
        start += len(batch)
    return [_page(p, settings.base_url, body) for p in raw if isinstance(p, dict)]


async def _paged_v2(client: httpx.AsyncClient, url: str, params: dict) -> tuple[list, str]:
    """Every batch of a v2 listing, following the cursor: (results, the site's base)."""
    raw: list = []
    base = settings.base_url
    next_url: str | None = url
    next_params: dict | None = params
    while next_url:
        data = await _get(client, next_url, next_params)
        raw.extend(_results(data))
        base = (data.get("_links") or {}).get("base") or base
        next_url, next_params = _next(data), None
    return raw, base


async def _read_v2(client: httpx.AsyncClient, body: bool) -> list[dict]:
    site = settings.site
    if site["root_type"] and site["root_id"]:
        return await _read_tree_v2(client, site["root_type"], site["root_id"], body)
    space = await _space_v2(client)
    params: dict[str, Any] = {"status": "current", "limit": min(settings.CONFLUENCE_PAGE_LIMIT, V2_MAX_LIMIT)}
    if body:
        params["body-format"] = "storage"
    raw, base = await _paged_v2(client, f"{settings.base_url}/api/v2/spaces/{space['id']}/pages", params)
    return [_page(p, base, body) for p in raw if isinstance(p, dict)]


async def _tree_ids_v2(client: httpx.AsyncClient, root_type: str, root_id: str) -> list[str]:
    """The page CONFLUENCE_BASE_URL points at, and every page under it or under
    the folder it points at, at any depth."""
    ids: dict[str, None] = {root_id: None} if root_type == "page" else {}
    queue = [(root_type, root_id)]
    while queue:
        kind, node = queue.pop(0)
        where = "folders" if kind == "folder" else "pages"
        found, _ = await _paged_v2(
            client, f"{settings.base_url}/api/v2/{where}/{node}/descendants",
            {"depth": TREE_DEPTH, "limit": V2_MAX_LIMIT},
        )
        for d in found:
            if not isinstance(d, dict):
                continue
            if d.get("type") == "page":
                ids[str(d.get("id"))] = None
            if (d.get("depth") or 0) >= TREE_DEPTH and d.get("type") in ("page", "folder"):
                queue.append((d["type"], str(d.get("id"))))
    return list(ids)


async def _read_tree_v2(client: httpx.AsyncClient, root_type: str, root_id: str, body: bool) -> list[dict]:
    ids = await _tree_ids_v2(client, root_type, root_id)
    pages: list[dict] = []
    for i in range(0, len(ids), V2_MAX_LIMIT):
        params: dict[str, Any] = {"id": ",".join(ids[i:i + V2_MAX_LIMIT]), "status": "current", "limit": V2_MAX_LIMIT}
        if body:
            params["body-format"] = "storage"
        raw, base = await _paged_v2(client, f"{settings.base_url}/api/v2/pages", params)
        pages.extend(_page(p, base, body) for p in raw if isinstance(p, dict))
    return pages


async def read_pages(body: bool = True) -> list[dict]:
    """
    Every current page that is read — the space, or the part of it
    CONFLUENCE_BASE_URL names — as {id, title, version, url[, body]}.

    Raises rather than returning an empty list for a space that could not be
    read, which a caller would take for an empty space.
    """
    async with _client() as client:
        pages = await (_read_v2(client, body) if settings.api_version == "v2" else _read_v1(client, body))
    logger.info("read %d page(s) from space %s (%s)", len(pages), settings.space_key, settings.api_version)
    return pages


# ── One page ───────────────────────────────────────────────────────────────────

_PAGE_ID = re.compile(r"^\d{1,20}$")
_BLOCK_END = re.compile(r"</(?:p|div|li|tr|h[1-6]|table|ul|ol)>|<br\s*/?>", re.IGNORECASE)
_CELL_END = re.compile(r"</t[hd]>", re.IGNORECASE)
_TAG = re.compile(r"<[^>]+>")


def text_of(storage: str) -> str:
    """Storage-format XHTML as plain text: a line per block, table cells apart."""
    text = _CELL_END.sub(" | ", storage or "")
    text = _BLOCK_END.sub("\n", text)
    text = html.unescape(_TAG.sub("", text))
    lines = (re.sub(r"[ \t\xa0]+", " ", line).strip(" |") for line in text.split("\n"))
    return "\n".join(line for line in lines if line)


async def read_page(page_id: str) -> dict:
    """
    One page of the space, with its body. A page outside the configured space is
    refused even when the account can see it: this connector is the playbook
    space's, not the wiki's.
    """
    page_id = str(page_id or "").strip()
    if not _PAGE_ID.match(page_id):
        raise ConfluenceError(f"invalid page id: {page_id!r} — a page id is a number")
    key = settings.space_key
    outside = ConfluenceError(f"page {page_id} is not in space {key}")

    async with _client() as client:
        if settings.api_version == "v2":
            raw = await _get(client, f"{settings.base_url}/api/v2/pages/{page_id}", {"body-format": "storage"})
            space = await _space_v2(client)
            if str(raw.get("spaceId") or "") != str(space["id"]):
                raise outside
            base = (raw.get("_links") or {}).get("base") or settings.base_url
        else:
            raw = await _get(
                client, f"{settings.base_url}{settings.CONFLUENCE_API_PATH}/content/{page_id}",
                {"expand": "body.storage,version,space"},
            )
            if ((raw.get("space") or {}).get("key") or "") != key:
                raise outside
            base = settings.base_url
    return _page(raw, base, body=True)


# ── Can it be used ─────────────────────────────────────────────────────────────

async def check() -> dict:
    """
    Can this connector read Confluence right now? Never raises.

    One authenticated read of the space's own record, and the answer says where
    it stopped:

        reach   no answer, or an answer that is not Confluence's REST API —
                including the login page an SSO gateway sends with a 200
        auth    the credentials were refused (401)
        read    authenticated, but the space is not visible to this account

    No page is fetched and nothing is written.
    """
    started = time.monotonic()
    site = settings.site
    result: dict[str, Any] = {
        "connected": False,
        "base_url": settings.base_url,
        "space_key": settings.space_key,
        "api": settings.api_version,
        "reads": f"{site['root_type']} {site['root_id']} and what is under it" if site["root_id"] else "the whole space",
    }
    if settings.CONFLUENCE_PROXY.strip():
        # The host only: a proxy URL may carry credentials.
        result["proxy"] = urlsplit(settings.CONFLUENCE_PROXY.strip()).hostname

    try:
        async with _client(min(settings.CONFLUENCE_TIMEOUT, CHECK_TIMEOUT_SECONDS)) as client:
            if settings.api_version == "v2":
                await _space_v2(client)
            else:
                space = await _get(
                    client, f"{settings.base_url}{settings.CONFLUENCE_API_PATH}/space/{settings.space_key}"
                )
                if not space.get("key"):
                    raise ConfluenceError(
                        "Confluence's REST API did not answer with the space — is CONFLUENCE_BASE_URL "
                        "behind a login page, or missing a path such as /wiki?",
                        "reach",
                    )
        result["connected"] = True
    except ConfluenceError as exc:
        result["failed_at"] = exc.kind
        result["error"] = str(exc)
    result["latency_ms"] = int((time.monotonic() - started) * 1000)
    return result


async def reachable() -> bool:
    """A real call, not a guess. /health must not claim a connection it has not made."""
    url = (
        f"{settings.base_url}/api/v2/spaces" if settings.api_version == "v2"
        else f"{settings.base_url}{settings.CONFLUENCE_API_PATH}/space"
    )
    try:
        async with _client(CHECK_TIMEOUT_SECONDS) as client:
            resp = await client.get(url, params={"limit": 1})
        return resp.status_code < 400
    except httpx.HTTPError:
        return False
