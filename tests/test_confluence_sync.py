"""Confluence answering, but not with what a wiki API sends.

The case that ended the process: an SSO gateway in front of Confluence replies
200 with its login page. json() raised, nothing caught it, and the connector
died at boot instead of starting with the "stale" flag the design promises.
"""

import asyncio

import httpx
import pytest

from conftest import AUTH

LOGIN_PAGE = httpx.Response(200, html="<html><body>Please sign in</body></html>")


@pytest.fixture
def confluence(platform, connector):
    """The Confluence connector, with every outgoing call answered by `platform`."""
    server = connector("Confluence")
    import confluence_api

    return server, confluence_api, platform.answer


@pytest.mark.parametrize(
    "reply,said",
    [
        (LOGIN_PAGE, "non-JSON"),
        (httpx.Response(200, json=["not", "an", "object"]), "results list"),
        (httpx.Response(200, json={"unexpected": True}), "results list"),
    ],
    ids=["login-page", "json-list", "no-results-key"],
)
def test_an_odd_answer_is_a_confluence_error(confluence, reply, said):
    _, api, answer_with = confluence
    answer_with(reply)
    with pytest.raises(api.ConfluenceError, match=said):
        asyncio.run(api.fetch_pages())


def test_a_failed_sync_is_recorded_not_raised(confluence):
    server, _, answer_with = confluence
    answer_with(LOGIN_PAGE)
    result = asyncio.run(server.sync())
    assert "non-JSON" in result["error"]


def test_the_connector_boots_when_the_first_sync_fails(confluence):
    server, _, answer_with = confluence
    answer_with(LOGIN_PAGE)
    from starlette.testclient import TestClient

    # Entering the client runs the lifespan, which is where the first sync is.
    with TestClient(server.app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["stale"] is True

        # And it says so with the answer, rather than reporting a clean miss.
        match = client.post("/match", json={"alert_name": "anything"}, headers=AUTH)
        assert match.json()["corpus"]["stale"] is True
