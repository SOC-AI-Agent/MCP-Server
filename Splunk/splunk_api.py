"""Minimal async client for the Splunk search REST API."""

import asyncio
import logging
import time
from typing import Any

import httpx

import spl
from config import settings

logger = logging.getLogger("splunk")


# A connection check that hangs for SPLUNK_TIMEOUT on a host that silently
# drops packets is not answering the question it was asked.
CHECK_TIMEOUT_SECONDS = 10
# A search job has to be created and run, so it gets longer than a GET.
CHECK_SEARCH_TIMEOUT_SECONDS = 30


class SplunkError(RuntimeError):
    """Anything that stops a search from returning rows."""


class SplunkClient:
    """
    One oneshot search per call.

    Oneshot blocks until the search finishes and hands back the rows, which is
    what a tool call wants — no job polling, no job to clean up. It also means
    the search must stay small: every tool caps `count` before getting here.
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.SPLUNK_BASE_URL.rstrip("/"),
            headers={"Authorization": f"Bearer {settings.SPLUNK_TOKEN}"},
            verify=settings.SPLUNK_VERIFY_SSL,
            timeout=settings.SPLUNK_TIMEOUT,
        )

    async def search(
        self,
        spl: str,
        earliest: str,
        latest: str,
        count: int,
    ) -> list[dict]:
        logger.info("splunk search spl=%s earliest=%s latest=%s", spl, earliest, latest)
        try:
            resp = await self._client.post(
                "/services/search/jobs",
                data={
                    "search": spl,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "count": count,
                    # Disable lookups/alerts that a search could otherwise fire.
                    "adhoc_search_level": "fast",
                },
            )
        except httpx.HTTPError as exc:
            raise SplunkError(f"cannot reach Splunk at {settings.SPLUNK_BASE_URL}: {exc}") from exc

        if resp.status_code == 401:
            raise SplunkError("Splunk rejected SPLUNK_TOKEN (401)")
        if resp.status_code == 403:
            raise SplunkError(
                "Splunk denied the search (403) — the token's role is missing a "
                "capability or access to the index"
            )
        if resp.status_code >= 400:
            raise SplunkError(f"Splunk returned {resp.status_code}: {resp.text[:300]}")

        try:
            return resp.json().get("results", [])
        except ValueError as exc:
            raise SplunkError(f"Splunk returned a non-JSON body: {resp.text[:300]}") from exc

    async def reachable(self) -> bool:
        try:
            resp = await self._client.get("/services/server/info", params={"output_mode": "json"})
            return resp.status_code < 400
        except httpx.HTTPError:
            return False

    async def check(self) -> dict:
        """
        Can this connector use Splunk right now? Never raises.

        Three steps, in order, so a failure says where it stopped:

            reach   the management port answers the way Splunk's does
            auth    SPLUNK_TOKEN is accepted
            search  a search can be run with it

        The search is a fixed `| makeresults`: it needs the same capability a
        real one does, reads no index and returns one synthetic row. It skips
        spl.py on purpose — that guards what a model may ask for, and no model
        is involved here.
        """
        started = time.monotonic()

        def outcome(failed_at: str | None = None, error: str | None = None,
                    version: str | None = None) -> dict:
            result: dict[str, Any] = {
                "connected": failed_at is None,
                "base_url": settings.SPLUNK_BASE_URL,
                "latency_ms": int((time.monotonic() - started) * 1000),
            }
            if version:
                result["splunk_version"] = version
            if failed_at:
                result["failed_at"] = failed_at
                result["error"] = error
            return result

        try:
            resp = await self._client.get(
                "/services/server/info",
                params={"output_mode": "json"},
                timeout=min(settings.SPLUNK_TIMEOUT, CHECK_TIMEOUT_SECONDS),
            )
        except httpx.HTTPError as exc:
            return outcome("reach", f"cannot reach Splunk at {settings.SPLUNK_BASE_URL}: "
                                    f"{type(exc).__name__}: {exc}")

        if resp.status_code in (401, 403):
            return outcome("auth", f"Splunk rejected SPLUNK_TOKEN ({resp.status_code})")

        # Anything else that is not Splunk's own JSON is usually the wrong
        # port: the web UI (8000) answers, but not like this.
        version: str | None = None
        if 200 <= resp.status_code < 300:
            try:
                version = str(resp.json()["entry"][0]["content"]["version"])
            except (ValueError, KeyError, IndexError, TypeError):
                version = None
        if version is None:
            return outcome("reach", f"Splunk's management API did not answer properly: "
                                    f"{resp.status_code} for GET /services/server/info — "
                                    "SPLUNK_BASE_URL should be the management port (8089), "
                                    "not the web UI")

        try:
            await asyncio.wait_for(
                self.search("| makeresults count=1", "-1m", "now", 1),
                timeout=CHECK_SEARCH_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            return outcome("search", f"no answer to a search within "
                                     f"{CHECK_SEARCH_TIMEOUT_SECONDS}s", version)
        except SplunkError as exc:
            return outcome("search", str(exc), version)

        result = outcome(version=version)
        result.update(await self._index_visibility())
        return result

    async def _index_visibility(self) -> dict:
        """
        Which of the allowed indexes showed events in the last 30 days.

        Advisory — it never changes `connected`. A search over an index the token
        cannot read returns nothing rather than an error, so a quiet index and an
        unreadable one look the same from here. The ones that show events are
        certainly readable; for the rest the answer is only "look at /catalog".
        Built from the allowlist through spl.py, like every other search.
        """
        if settings.index_restriction_disabled:
            return {}
        allowed = settings.allowed_indexes
        try:
            rows = await asyncio.wait_for(
                self.search(
                    f"| tstats count where {spl.index_clause(None)} by index",
                    "-30d", "now", 1000,
                ),
                timeout=CHECK_SEARCH_TIMEOUT_SECONDS,
            )
        except (SplunkError, TimeoutError) as exc:
            return {"indexes": {"checked": False, "reason": str(exc) or "no answer in time"}}

        seen = {row.get("index") for row in rows}
        quiet = [name for name in allowed if name not in seen]
        result: dict[str, Any] = {
            "indexes": {
                "with_events": [name for name in allowed if name in seen],
                "no_events_in_30d": quiet,
            }
        }
        if quiet:
            result["warning"] = (
                f"no events seen in the last 30 days in {', '.join(quiet)}: the token may not "
                "be able to read them, or they are quiet. A search over an unreadable index "
                "returns nothing, not an error — GET /catalog shows what the token can see."
            )
        return result

    async def aclose(self) -> None:
        await self._client.aclose()


splunk = SplunkClient()
