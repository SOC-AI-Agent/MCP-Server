"""GET /check-connection on each connector: which step failed, and nothing else.

The platform is a stand-in that answers whatever a case says. What is under test
is the connector's reading of those answers.
"""

import httpx
import pytest

from conftest import AUTH, SECRETS


def body(status, data):
    return httpx.Response(status, json=data)


# ── Splunk: reach -> auth -> search ─────────────────────────────────────────
INFO, SEARCH = "/services/server/info", "/services/search/jobs"
SPLUNK_OK = {INFO: body(200, {"entry": [{"content": {"version": "9.2.1"}}]})}


def searches(tstats_rows):
    """The search endpoint, answering the connectivity search and the per-index one."""

    def answer(request):
        if b"tstats" in request.content:
            return body(200, {"results": tstats_rows})
        return body(200, {"results": [{"_time": "now"}]})

    return answer


SPLUNK_SEARCHED = {**SPLUNK_OK, SEARCH: searches([{"index": "main", "count": "5"}])}

SPLUNK = [
    ("connected", SPLUNK_SEARCHED, None),
    ("token-401", {INFO: httpx.Response(401)}, "auth"),
    ("token-403", {INFO: httpx.Response(403)}, "auth"),
    ("web-ui-redirect", {INFO: httpx.Response(303)}, "reach"),
    ("not-splunk", {INFO: httpx.Response(200, text="<html>hello</html>")}, "reach"),
    ("search-denied", {**SPLUNK_OK, SEARCH: httpx.Response(403)}, "search"),
    ("search-error", {**SPLUNK_OK, SEARCH: httpx.Response(500, text="boom")}, "search"),
    # A quiet or unreadable index is advice, not a failure.
    ("indexes-quiet", {**SPLUNK_OK, SEARCH: searches([])}, None),
    ("unreachable", {INFO: httpx.ConnectError("refused")}, "reach"),
]

# ── ThreatQ: reach -> auth -> read -> search ────────────────────────────────
INDICATORS, TOKEN_PATH, THREATQ_SEARCH = "/api/indicators", "/api/token", "/api/indicators/search"
MINTED = body(200, {"access_token": "minted", "expires_in": 3600})
READABLE = {INDICATORS: body(200, {"data": []})}
SEARCHABLE = {**READABLE, THREATQ_SEARCH: body(200, {"data": []})}

THREATQ = [
    ("connected", SEARCHABLE, None),
    ("token-401", {INDICATORS: httpx.Response(401)}, "auth"),
    ("read-403", {INDICATORS: httpx.Response(403)}, "read"),
    ("read-redirect", {INDICATORS: httpx.Response(302)}, "read"),
    ("read-500", {INDICATORS: httpx.Response(500)}, "read"),
    ("search-refused-403", {**READABLE, THREATQ_SEARCH: httpx.Response(403)}, "search"),
    ("search-token-401", {**READABLE, THREATQ_SEARCH: httpx.Response(401)}, "auth"),
    ("search-500", {**READABLE, THREATQ_SEARCH: httpx.Response(500)}, "search"),
    # ThreatQ documents 404 as "Object not found", which is how a miss can arrive.
    ("search-miss-404-json", {**READABLE, THREATQ_SEARCH: body(404, {"error": "Object not found"})}, None),
    ("search-path-404-html", {**READABLE, THREATQ_SEARCH: httpx.Response(404, text="<html>nope</html>")}, "search"),
    ("unreachable", {"/": httpx.ConnectError("refused")}, "reach"),
]
OAUTH = {
    "THREATQ_AUTH_MODE": "oauth",
    "THREATQ_CLIENT_ID": "client",
    "THREATQ_EMAIL": "svc@example.invalid",
    "THREATQ_PASSWORD": "threatq-password-value",
}
THREATQ_OAUTH = [
    ("oauth-connected", {TOKEN_PATH: MINTED, **SEARCHABLE}, None),
    ("oauth-credentials-refused", {TOKEN_PATH: httpx.Response(401)}, "auth"),
]

# ── Confluence: one authenticated read of the space ─────────────────────────
SPACE = "/rest/api/space/SOC"

CONFLUENCE = [
    ("connected", {SPACE: body(200, {"key": "SOC"})}, None),
    ("credentials-401", {SPACE: httpx.Response(401)}, "auth"),
    ("space-forbidden-403", {SPACE: httpx.Response(403)}, "read"),
    ("space-not-found-404", {SPACE: httpx.Response(404)}, "read"),
    ("login-redirect", {SPACE: httpx.Response(302)}, "reach"),
    ("login-page-with-200", {SPACE: httpx.Response(200, text="<html>sign in</html>")}, "reach"),
    ("json-without-a-space", {SPACE: body(200, {"unexpected": True})}, "reach"),
    ("unreachable", {SPACE: httpx.ConnectError("refused")}, "reach"),
]


def cases(name, table, **env):
    return [pytest.param(name, env, replies, expected, id=f"{name}-{label}")
            for label, replies, expected in table]


ALL = (
    cases("Splunk", SPLUNK)
    + cases("Threatq", THREATQ)
    + cases("Threatq", THREATQ_OAUTH, **OAUTH)
    + cases("Confluence", CONFLUENCE)
)


@pytest.mark.parametrize("name,env,replies,expected", ALL)
def test_it_says_where_it_stopped(platform, client, name, env, replies, expected):
    platform.by_path(replies)
    resp = client(name, **env).get("/check-connection", headers=AUTH)
    answer = resp.json()

    assert answer.get("failed_at") == expected, answer
    assert answer["connected"] is (expected is None)
    assert resp.status_code == (200 if expected is None else 502)
    assert isinstance(answer["latency_ms"], int)
    if expected:
        assert answer["error"]


@pytest.mark.parametrize("name,env,replies,expected", ALL)
def test_it_never_repeats_a_credential(platform, client, name, env, replies, expected):
    platform.by_path(replies)
    text = client(name, **env).get("/check-connection", headers=AUTH).text
    for secret in [*SECRETS.values(), OAUTH["THREATQ_PASSWORD"], "minted"]:
        assert secret not in text


@pytest.mark.parametrize("name", ["Splunk", "Threatq", "Confluence"])
def test_it_needs_the_connectors_own_token(platform, client, name):
    # Each call goes out to the platform, so an open route would let anyone who
    # can reach the port make the service account do that.
    assert client(name).get("/check-connection").status_code == 401
    assert platform.requests == []


def test_confluence_without_credentials_says_so(platform, client, connector, monkeypatch):
    app = client("Confluence")
    import config

    monkeypatch.setattr(config.settings, "CONFLUENCE_API_TOKEN", "")
    answer = app.get("/check-connection", headers=AUTH).json()
    assert answer["failed_at"] == "config"
    assert platform.requests == []


# ── Read-only: the check must not change anything on the platform ───────────

@pytest.mark.parametrize(
    "name,env,replies,allowed_posts",
    [
        ("Splunk", {}, SPLUNK_SEARCHED, {SEARCH}),
        ("Threatq", {}, SEARCHABLE, {THREATQ_SEARCH}),
        ("Threatq", OAUTH, {TOKEN_PATH: MINTED, **SEARCHABLE}, {TOKEN_PATH, THREATQ_SEARCH}),
        ("Confluence", {}, {SPACE: body(200, {"key": "SOC"})}, set()),
    ],
    ids=["Splunk", "Threatq-bearer", "Threatq-oauth", "Confluence"],
)
def test_it_writes_nothing(platform, client, name, env, replies, allowed_posts):
    platform.by_path(replies)
    assert client(name, **env).get("/check-connection", headers=AUTH).status_code == 200

    for request in platform.requests:
        if request.method != "GET":
            assert request.method == "POST" and request.url.path in allowed_posts, request
    if name == "Splunk":
        # A synthetic row, and a count per index: no event is read.
        for search in [r for r in platform.requests if r.url.path == SEARCH]:
            assert b"makeresults" in search.content or b"tstats" in search.content
    if name == "Threatq":
        (found,) = [r for r in platform.requests if r.url.path == THREATQ_SEARCH]
        assert b"soc-mcp-connection-check" in found.content  # a value nothing has


def test_the_oauth_token_request_follows_the_documented_shape(platform, client):
    # ThreatQ's REST reference: POST /api/token?grant_type=password&client_id=…
    # with the credentials in the body.
    platform.by_path({TOKEN_PATH: MINTED, **SEARCHABLE})
    assert client("Threatq", **OAUTH).get("/check-connection", headers=AUTH).status_code == 200

    (mint,) = [r for r in platform.requests if r.url.path == TOKEN_PATH]
    assert mint.method == "POST"
    assert mint.url.params["grant_type"] == "password"
    assert mint.url.params["client_id"] == "client"
    assert b"email=" in mint.content and b"password=" in mint.content


# ── Splunk: which allowed indexes show events (advice, never a failure) ─────

def splunk_answer(platform, client, tstats_rows, **env):
    platform.by_path({**SPLUNK_OK, SEARCH: searches(tstats_rows)})
    return client("Splunk", **env).get("/check-connection", headers=AUTH).json()


def test_indexes_that_show_events_are_reported_without_a_warning(platform, client):
    answer = splunk_answer(platform, client, [{"index": "main", "count": "5"}])
    assert answer["connected"] is True
    assert answer["indexes"] == {"with_events": ["main"], "no_events_in_30d": []}
    assert "warning" not in answer


def test_an_index_with_no_events_is_a_warning_not_a_failure(platform, client):
    answer = splunk_answer(platform, client, [], SPLUNK_ALLOWED_INDEXES="main,notable")
    assert answer["connected"] is True
    assert answer["indexes"]["no_events_in_30d"] == ["main", "notable"]
    assert "main" in answer["warning"] and "notable" in answer["warning"]


def test_an_index_search_that_errors_leaves_the_connection_intact(platform, client):
    def answer(request):
        if b"tstats" in request.content:
            return httpx.Response(403)
        return body(200, {"results": [{"_time": "now"}]})

    platform.by_path({**SPLUNK_OK, SEARCH: answer})
    result = client("Splunk").get("/check-connection", headers=AUTH).json()
    assert result["connected"] is True
    assert result["indexes"]["checked"] is False


def test_an_unrestricted_allowlist_is_not_asked_about(platform, client):
    answer = splunk_answer(platform, client, [], SPLUNK_ALLOWED_INDEXES="*")
    assert answer["connected"] is True
    assert "indexes" not in answer
    assert not any(b"tstats" in r.content for r in platform.requests)


def test_a_refused_search_names_the_permission_to_ask_for(platform, client):
    platform.by_path({**READABLE, THREATQ_SEARCH: httpx.Response(403)})
    answer = client("Threatq").get("/check-connection", headers=AUTH).json()
    assert "indicators_search" in answer["error"]
