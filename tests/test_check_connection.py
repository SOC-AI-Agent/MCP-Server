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

def cases(name, table, **env):
    return [pytest.param(name, env, replies, expected, id=f"{name}-{label}")
            for label, replies, expected in table]


ALL = cases("Splunk", SPLUNK)


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
    for secret in SECRETS.values():
        assert secret not in text


@pytest.mark.parametrize("name", ["Splunk"])
def test_it_needs_the_connectors_own_token(platform, client, name):
    # Each call goes out to the platform, so an open route would let anyone who
    # can reach the port make the service account do that.
    assert client(name).get("/check-connection").status_code == 401
    assert platform.requests == []


# ── Read-only: the check must not change anything on the platform ───────────

@pytest.mark.parametrize(
    "name,env,replies,allowed_posts",
    [
        ("Splunk", {}, SPLUNK_SEARCHED, {SEARCH}),
    ],
    ids=["Splunk"],
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
