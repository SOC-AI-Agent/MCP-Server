"""GET /pages: the space as Confluence stores it, for the backend to pass on."""

import httpx
import pytest

from conftest import AUTH

PAGE = {
    "id": "101",
    "title": "Excessive Failed Logins",
    "version": {"number": 7},
    "_links": {"webui": "/spaces/SOC/pages/101"},
    "body": {"storage": {"value": "<table><tr><th>Alert Name</th><td><p>Excessive Failed Logins</p></td></tr></table>"}},
}


@pytest.fixture
def pages_client(platform, client):
    def make(reply):
        platform.answer(reply)
        return client("Confluence")
    return make


def test_pages_come_back_unparsed(pages_client):
    with pages_client(httpx.Response(200, json={"results": [PAGE]})) as app:
        resp = app.get("/pages", headers=AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["space_key"] == "SOC"
    assert body["count"] == 1
    page = body["pages"][0]
    assert page == {
        "id": "101", "title": "Excessive Failed Logins", "version": 7,
        "url": page["url"], "body": PAGE["body"]["storage"]["value"],
    }
    assert page["url"].endswith("/spaces/SOC/pages/101")


def test_a_page_missing_its_parts_is_passed_on_empty_not_a_crash(pages_client):
    with pages_client(httpx.Response(200, json={"results": [{"id": 5}]})) as app:
        page = app.get("/pages", headers=AUTH).json()["pages"][0]
    assert page == {"id": "5", "title": "", "version": None, "url": page["url"], "body": ""}


@pytest.mark.parametrize("reply,said", [
    (httpx.Response(401), "401"),
    (httpx.Response(200, html="<html>Please sign in</html>"), "non-JSON"),
    (httpx.Response(500, text="boom"), "500"),
], ids=["refused", "login-page", "server-error"])
def test_an_unreadable_space_is_a_502_never_an_empty_list(pages_client, reply, said):
    with pages_client(reply) as app:
        resp = app.get("/pages", headers=AUTH)
    assert resp.status_code == 502
    assert said in resp.json()["error"]
    assert "pages" not in resp.json()


def test_pages_needs_the_token(pages_client):
    with pages_client(httpx.Response(200, json={"results": []})) as app:
        assert app.get("/pages").status_code == 401
