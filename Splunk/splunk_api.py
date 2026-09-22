"""Minimal async client for the Splunk search REST API."""

import logging

import httpx

from config import settings

logger = logging.getLogger("splunk")


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

    async def aclose(self) -> None:
        await self._client.aclose()


splunk = SplunkClient()
