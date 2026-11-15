"""soc-mcp-confluence: the playbook space, read from Confluence and handed over unparsed.

Confluence is a stand-in (conftest `platform`) that answers whatever a case says, so
nothing here leaves the process. Both REST APIs are covered: v1 (Server/DC) and v2
(Cloud), which the connector picks between by CONFLUENCE_API or the host name.
"""

import base64
import json
import sys

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import AUTH, SECRETS

MCP = "/mcp"
HEADERS = {**AUTH, "Accept": "application/json, text/event-stream"}
CLOUD = "https://acme.atlassian.net/wiki"

BODY = "<table><tr><th>Alert Name</th><td><p>Excessive Failed Logins</p></td></tr></table><p>Check&nbsp;the source &amp; user.</p>"
PAGE = {
    "id": "101",
    "title": "Excessive Failed Logins",
    "version": {"number": 7},
    "_links": {"webui": "/spaces/SOC/pages/101"},
    "body": {"storage": {"value": BODY}},
    "space": {"key": "SOC"},
    "spaceId": "9",
}
EXPECTED = {"id": "101", "title": "Excessive Failed Logins", "version": 7, "body": BODY}


def page(n: int) -> dict:
    return {**PAGE, "id": str(n), "_links": {"webui": f"/spaces/SOC/pages/{n}"}}


@pytest.fixture
def confluence(platform, connector):
    """`confluence(table, **env)` -> (client, call): the app with Confluence
    answering `table` (path -> reply), and call(tool, **args) -> (is_error, payload)."""
    clients = []

    def start(table, **env):
        platform.by_path(table)
        app = connector("Confluence", **env).app
        client = TestClient(app, base_url="http://soc-mcp-confluence:8600", raise_server_exceptions=False)
        client.__enter__()
        clients.append(client)

        def call(name, **args):
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
            resp = client.post(MCP, json=body, headers=HEADERS)
            assert resp.status_code == 200, resp.text
            answer = resp.json()["result"]
            text = "".join(c.get("text", "") for c in answer["content"])
            try:
                return answer.get("isError", False), json.loads(text)
            except ValueError:
                return answer.get("isError", False), text

        return client, call

    yield start
    for client in clients:
        client.__exit__(None, None, None)


V1 = {"/rest/api/content": httpx.Response(200, json={"results": [PAGE], "_links": {}})}


# ── The tools ──────────────────────────────────────────────────────────────────

def test_it_publishes_three_read_only_tools(confluence):
    client, _ = confluence(V1)
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    tools = {t["name"]: t for t in client.post(MCP, json=body, headers=HEADERS).json()["result"]["tools"]}
    assert set(tools) == {"confluence_read_pages", "confluence_list_pages", "confluence_get_page"}
    for t in tools.values():
        assert t["annotations"]["readOnlyHint"] is True and t["annotations"]["destructiveHint"] is False
    assert tools["confluence_get_page"]["inputSchema"]["required"] == ["page_id"]


def test_pages_come_back_unparsed(confluence, platform):
    _, call = confluence(V1)
    failed, got = call("confluence_read_pages")
    assert not failed
    assert got["space_key"] == "SOC" and got["count"] == 1
    (one,) = got["pages"]
    assert one == {**EXPECTED, "url": one["url"]} and one["url"].endswith("/spaces/SOC/pages/101")
    sent = platform.requests[-1]
    assert sent.url.params["spaceKey"] == "SOC" and sent.url.params["status"] == "current"
    assert sent.url.params["expand"] == "body.storage,version"


def test_the_listing_leaves_the_bodies_in_confluence(confluence, platform):
    _, call = confluence(V1)
    _, got = call("confluence_list_pages")
    assert got["pages"] == [{"id": "101", "title": "Excessive Failed Logins", "version": 7,
                             "url": got["pages"][0]["url"]}]
    assert platform.requests[-1].url.params["expand"] == "version"


def test_a_page_missing_its_parts_is_passed_on_empty_not_a_crash(confluence):
    _, call = confluence({"/rest/api/content": httpx.Response(200, json={"results": [{"id": 5}, "junk"]})})
    _, got = call("confluence_read_pages")
    assert got["pages"] == [{"id": "5", "title": "", "version": None, "url": got["pages"][0]["url"], "body": ""}]


def test_the_space_is_read_to_the_end_not_to_the_first_short_batch(confluence, platform):
    # Confluence caps the batch below what was asked for when bodies are expanded;
    # the end is where it stops offering a next page.
    def batches(request):
        start = int(request.url.params["start"])
        if start >= 5:
            return httpx.Response(200, json={"results": [], "_links": {}})
        return httpx.Response(200, json={
            "results": [page(start + 1), page(start + 2)][: 5 - start], "limit": 2,
            "_links": {"next": "/rest/api/content?start=x"} if start + 2 < 5 else {},
        })

    _, call = confluence({"/rest/api/content": batches}, CONFLUENCE_PAGE_LIMIT="200")
    _, got = call("confluence_read_pages")
    assert [p["id"] for p in got["pages"]] == ["1", "2", "3", "4", "5"]
    assert [r.url.params["start"] for r in platform.requests] == ["0", "2", "4"]


@pytest.mark.parametrize("reply,said", [
    (httpx.Response(401), "401"),
    (httpx.Response(403), "403"),
    (httpx.Response(404), "404"),
    (httpx.Response(407), "proxy"),
    (httpx.Response(302, headers={"location": "https://sso.example/login"}), "login page"),
    (httpx.Response(200, html="<html>Please sign in</html>"), "non-JSON"),
    (httpx.Response(200, json={"message": "hello"}), "results list"),
    (httpx.Response(500, text="boom"), "500"),
    (httpx.ConnectError("refused"), "cannot reach"),
], ids=["refused", "forbidden", "missing", "proxy-auth", "redirect", "login-page", "not-a-listing",
        "server-error", "unreachable"])
def test_an_unreadable_space_is_an_error_never_an_empty_list(confluence, reply, said):
    client, call = confluence({"/rest/api/content": reply})
    failed, got = call("confluence_read_pages")
    assert failed and said in str(got)
    resp = client.get("/pages", headers=AUTH)
    assert resp.status_code == 502 and said in resp.json()["error"] and "pages" not in resp.json()


def test_the_plain_route_returns_what_the_tool_does(confluence):
    client, call = confluence(V1)
    assert client.get("/pages", headers=AUTH).json() == call("confluence_read_pages")[1]


# ── One page ───────────────────────────────────────────────────────────────────

def test_one_page_as_storage_or_as_text(confluence, platform):
    _, call = confluence({"/rest/api/content/101": httpx.Response(200, json=PAGE)})
    failed, got = call("confluence_get_page", page_id="101")
    assert not failed and got["body"] == BODY and got["format"] == "storage"
    assert platform.requests[-1].url.params["expand"] == "body.storage,version,space"

    _, got = call("confluence_get_page", page_id="101", format="text")
    assert got["body"] == "Alert Name | Excessive Failed Logins\nCheck the source & user."
    assert got["title"] == "Excessive Failed Logins" and got["version"] == 7


def test_a_page_outside_the_playbook_space_is_refused(confluence):
    other = {**PAGE, "space": {"key": "HR"}}
    _, call = confluence({"/rest/api/content/101": httpx.Response(200, json=other)})
    failed, got = call("confluence_get_page", page_id="101")
    assert failed and "not in space SOC" in str(got) and BODY not in str(got)


@pytest.mark.parametrize("page_id", ["", "abc", "101/../../space", "1 OR 1=1"])
def test_a_page_id_that_is_not_a_number_never_reaches_confluence(confluence, platform, page_id):
    _, call = confluence({})
    failed, got = call("confluence_get_page", page_id=page_id)
    assert failed and "page id" in str(got)
    assert platform.requests == []


def test_an_unknown_format_is_refused(confluence, platform):
    _, call = confluence({})
    failed, _ = call("confluence_get_page", page_id="101", format="html")
    assert failed and platform.requests == []


# ── Cloud: API v2 ──────────────────────────────────────────────────────────────

SPACES = httpx.Response(200, json={"results": [{"id": "9", "key": "SOC"}]})


def test_cloud_is_read_with_v2_by_the_space_id_following_the_cursor(confluence, platform):
    def pages(request):
        if "cursor" in request.url.params:
            return httpx.Response(200, json={"results": [page(2)], "_links": {"base": CLOUD}})
        return httpx.Response(200, json={
            "results": [page(1)],
            "_links": {"next": "/wiki/api/v2/spaces/9/pages?cursor=abc", "base": CLOUD},
        })

    _, call = confluence({"/wiki/api/v2/spaces": SPACES, "/wiki/api/v2/spaces/9/pages": pages},
                         CONFLUENCE_BASE_URL=f"{CLOUD}/spaces/SOC/overview", CONFLUENCE_SPACE_KEY="")
    failed, got = call("confluence_read_pages")
    assert not failed and [p["id"] for p in got["pages"]] == ["1", "2"]
    assert got["space_key"] == "SOC"
    assert got["pages"][0]["url"] == f"{CLOUD}/spaces/SOC/pages/1"
    first = platform.requests[1]
    assert first.url.params["body-format"] == "storage" and first.url.params["limit"] == "200"
    assert platform.requests[0].url.params["keys"] == "SOC"


def test_a_page_address_reads_that_page_and_everything_under_it(confluence, platform):
    descendants = httpx.Response(200, json={"results": [
        {"id": "11", "type": "page", "depth": 1},
        {"id": "12", "type": "folder", "depth": 1},
        {"id": "13", "type": "page", "depth": 2},
    ], "_links": {}})

    def by_id(request):
        ids = request.url.params["id"].split(",")
        return httpx.Response(200, json={"results": [page(int(i)) for i in ids], "_links": {"base": CLOUD}})

    _, call = confluence(
        {"/wiki/api/v2/pages/10/descendants": descendants, "/wiki/api/v2/pages": by_id},
        CONFLUENCE_BASE_URL=f"{CLOUD}/spaces/SOC/pages/10/Use+Cases", CONFLUENCE_SPACE_KEY="",
    )
    _, got = call("confluence_read_pages")
    assert [p["id"] for p in got["pages"]] == ["10", "11", "13"]
    assert all("/api/v2/spaces" not in r.url.path for r in platform.requests)


def test_a_cloud_page_is_checked_against_the_space_by_its_id(confluence):
    table = {"/wiki/api/v2/spaces": SPACES, "/wiki/api/v2/pages/101": httpx.Response(200, json=PAGE)}
    _, call = confluence(table, CONFLUENCE_BASE_URL=CLOUD)
    failed, got = call("confluence_get_page", page_id="101")
    assert not failed and got["body"] == BODY

    table["/wiki/api/v2/pages/101"] = httpx.Response(200, json={**PAGE, "spaceId": "77"})
    _, call = confluence(table, CONFLUENCE_BASE_URL=CLOUD)
    failed, got = call("confluence_get_page", page_id="101")
    assert failed and "not in space SOC" in str(got)


# ── Settings ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,key,expected", [
    (f"{CLOUD}/spaces/SOC/overview", "", (CLOUD, "SOC", "", "")),
    (f"{CLOUD}/spaces/SOC/pages/123/Title", "OTHER", (CLOUD, "SOC", "page", "123")),
    (f"{CLOUD}/spaces/SOC/pages/edit-v2/123", "", (CLOUD, "SOC", "page", "123")),
    (f"{CLOUD}/spaces/SOC/folder/456", "", (CLOUD, "SOC", "folder", "456")),
    ("https://confluence.corp/display/SOC/Some+Page", "", ("https://confluence.corp", "SOC", "", "")),
    ("https://confluence.corp/spaces/viewspace.action?key=SOC", "", ("https://confluence.corp", "SOC", "", "")),
    ("https://confluence.corp/pages/viewpage.action?pageId=5", "SOC", ("https://confluence.corp", "SOC", "", "")),
    (f"{CLOUD}/", "SOC", (CLOUD, "SOC", "", "")),
])
def test_the_base_url_is_read_as_the_backend_reads_it(connector, url, key, expected):
    connector("Confluence", CONFLUENCE_BASE_URL=url, CONFLUENCE_SPACE_KEY=key)
    site = sys.modules["config"].settings.site
    assert (site["base_url"], site["space_key"], site["root_type"], site["root_id"]) == expected


@pytest.mark.parametrize("env,version", [
    ({"CONFLUENCE_BASE_URL": CLOUD}, "v2"),
    ({"CONFLUENCE_BASE_URL": "https://confluence.corp"}, "v1"),
    ({"CONFLUENCE_BASE_URL": CLOUD, "CONFLUENCE_API": "v1"}, "v1"),
    ({"CONFLUENCE_BASE_URL": "https://confluence.corp", "CONFLUENCE_API": "V2"}, "v2"),
])
def test_the_api_is_picked_by_the_host_unless_it_is_set(connector, env, version):
    connector("Confluence", **env)
    assert sys.modules["config"].settings.api_version == version


def test_an_unknown_api_refuses_to_start(connector):
    with pytest.raises(RuntimeError):
        connector("Confluence", CONFLUENCE_API="v3")


def test_cloud_gets_basic_auth_and_server_a_bearer(confluence, platform):
    _, call = confluence(V1, CONFLUENCE_EMAIL="bot@example.com")
    call("confluence_list_pages")
    expected = base64.b64encode(f"bot@example.com:{SECRETS['Confluence']}".encode()).decode()
    assert platform.requests[-1].headers["authorization"] == f"Basic {expected}"

    _, call = confluence(V1)
    call("confluence_list_pages")
    assert platform.requests[-1].headers["authorization"] == f"Bearer {SECRETS['Confluence']}"


# ── The gate, and the connection check ─────────────────────────────────────────

@pytest.mark.parametrize("path", ["/pages", "/check-connection"])
def test_the_routes_need_the_token(confluence, platform, path):
    client, _ = confluence(V1)
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert platform.requests == []


def test_the_mcp_endpoint_needs_the_token_and_a_host_it_serves(confluence):
    client, _ = confluence(V1)
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    assert client.post(MCP, json=body, headers={"Accept": HEADERS["Accept"]}).status_code == 401
    assert client.post(MCP, json=body, headers={**HEADERS, "Host": "evil.example"}).status_code == 421


SPACE = "/rest/api/space/SOC"


@pytest.mark.parametrize("reply,failed_at", [
    (httpx.ConnectError("refused"), "reach"),
    (httpx.Response(200, html="<html>Please sign in</html>"), "reach"),
    (httpx.Response(302, headers={"location": "https://sso.example"}), "reach"),
    (httpx.Response(200, json={"no": "key"}), "reach"),
    (httpx.Response(401), "auth"),
    (httpx.Response(403), "read"),
    (httpx.Response(404), "read"),
], ids=["unreachable", "login-page", "redirect", "not-the-api", "refused", "forbidden", "no-such-space"])
def test_the_check_says_where_it_stopped(confluence, reply, failed_at):
    client, _ = confluence({SPACE: reply})
    resp = client.get("/check-connection", headers=AUTH)
    assert resp.status_code == 502
    body = resp.json()
    assert body["connected"] is False and body["failed_at"] == failed_at and body["error"]
    assert SECRETS["Confluence"] not in resp.text


def test_the_check_passes_on_the_space_alone_and_reads_no_page(confluence, platform):
    client, _ = confluence({SPACE: httpx.Response(200, json={"key": "SOC"})})
    resp = client.get("/check-connection", headers=AUTH)
    body = resp.json()
    assert resp.status_code == 200 and body["connected"] is True
    assert body["space_key"] == "SOC" and body["api"] == "v1" and body["reads"] == "the whole space"
    assert "proxy" not in body
    assert [r.url.path for r in platform.requests] == [SPACE]


def test_a_proxy_is_used_and_named_without_its_credentials(confluence, platform):
    # Nothing listens there, so the call fails at the proxy — and never reaches
    # the stand-in directly, which is the point of setting one.
    client, _ = confluence({SPACE: httpx.Response(200, json={"key": "SOC"})},
                           CONFLUENCE_PROXY="http://user:hunter2@127.0.0.1:9")
    resp = client.get("/check-connection", headers=AUTH)
    body = resp.json()
    assert body["connected"] is False and body["failed_at"] == "reach"
    assert body["proxy"] == "127.0.0.1" and "hunter2" not in resp.text
    assert platform.requests == []


def test_the_cloud_check_looks_the_space_up_by_its_key(confluence):
    client, _ = confluence({"/wiki/api/v2/spaces": httpx.Response(200, json={"results": []})},
                           CONFLUENCE_BASE_URL=f"{CLOUD}/spaces/SOC/folder/456", CONFLUENCE_SPACE_KEY="")
    body = client.get("/check-connection", headers=AUTH).json()
    assert body["failed_at"] == "read" and "SOC" in body["error"] and body["api"] == "v2"
    assert body["reads"] == "folder 456 and what is under it"
