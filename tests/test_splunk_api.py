"""The Splunk connector as a plain HTTP API: it runs the SPL the backend sends.

No MCP transport and no model. The backend writes the search; this service checks
it again — a read-only search over an allowed index, nothing else — and runs it.
These check what it runs, what it refuses, and what it answers when Splunk is the
one that is wrong.
"""

import re
from urllib.parse import parse_qs

import httpx
import pytest

from conftest import AUTH, ROOT

SEARCH = "/services/search/jobs"


def rows(*events):
    return httpx.Response(200, json={"results": list(events)})


# The backend's searches name the alert index too, so the allowlist has to.
ALLOWED = {"SPLUNK_ALLOWED_INDEXES": "main,notable"}


def query(platform, client, spl, reply=None, env=None, **extra):
    platform.by_path({SEARCH: reply if reply is not None else rows()})
    return client("Splunk", **(env or ALLOWED)).post("/query", json={"spl": spl, **extra}, headers=AUTH)


def sent_to_splunk(platform):
    (request,) = [r for r in platform.requests if r.url.path == SEARCH]
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


# What the backend writes (Backend: modules/enrichment/spl.ts) — every shape it uses.
BACKEND_SPL = [
    'search index="main" (srcip="10.1.100.11" OR dstip="10.1.100.11") sourcetype="fortigate" | head 20',
    'search (index="main" OR index="notable") (user="jdoe") | head 20',
    'search index="main" filters="a" | bin _time span=1h | stats count, dc(dstip) as dstip_distinct_count by _time, action | sort -count | head 50',
    'search index="notable" search_name="Some Rule" | bin _time span=1d | stats count by _time | sort _time',
    '| tstats count where (index="main" OR index="notable") by index',
    "| makeresults count=1",
    # A value that tries to close its quote and run a command stays a value.
    'search index="main" action="blocked\\" | delete | head 1" | stats count | head 50',
]


@pytest.mark.parametrize("spl", BACKEND_SPL)
def test_the_searches_the_backend_writes_are_run_as_written(platform, client, spl):
    resp = query(platform, client, spl, rows({"srcip": "10.1.100.11", "host": "fw-1"}))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Rows come back as Splunk gave them — `host` included. Trimming is the caller's.
    assert body["results"] == [{"srcip": "10.1.100.11", "host": "fw-1"}]
    assert body["count"] == 1
    assert sent_to_splunk(platform)["search"] == spl


def test_the_window_and_the_ceiling_are_applied(platform, client):
    resp = query(
        platform, client, 'search index="main" | head 9999',
        earliest="-7d@d", latest="now", count=9999,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["limit"] == 200  # SPLUNK_MAX_COUNT
    sent = sent_to_splunk(platform)
    assert (sent["earliest_time"], sent["latest_time"], sent["count"]) == ("-7d@d", "now", "200")


# ── refused: not a read-only search over an allowed index ──────────────────

REFUSED = [
    ('search index="main" | delete', "command 'delete'"),
    ('search index="main" | DELETE', "command 'delete'"),
    ('search index="main" | outputlookup evil', "command 'outputlookup'"),
    ('search index="main" | head 5 | sendemail to=x@example.invalid', "command 'sendemail'"),
    ("| rest /services/authentication/users", "command 'rest'"),
    ('search index="main" | eval x=1', "command 'eval'"),
    ('search index="main" | inputlookup users', "command 'inputlookup'"),
    ('delete index="main"', "must start with `search`"),
    ('search index="main" [search index="main" | head 1]', "subsearches and macros"),
    ('search index="main" `some_macro`', "subsearches and macros"),
    ('search index="secret" | head 5', "not allowed; permitted: main, notable"),
    ('search index="main" OR index="secret" | head 5', "not allowed; permitted: main, notable"),
    ('| tstats count where index="secret" by index', "not allowed; permitted: main, notable"),
    ("search index=* | head 5", 'index must be written index="name"'),
    ("search index=main | head 5", 'index must be written index="name"'),
    ('search index IN ("main") | head 5', 'index must be written index="name"'),
    ('search index!="secret" | head 5', 'index must be written index="name"'),
    ('search index="ma*" | head 5', "invalid index name"),
    ("search foo=bar | head 5", "must name an index"),
    ('search index="main"\n| delete', "newlines"),
    ('search index="main" action="x | head 5', "unbalanced quote"),
    ('search index="main" | | head 1', "empty command"),
    ("x" * 5000, "too long"),
    ("", "spl is required"),
]


@pytest.mark.parametrize("spl,said", REFUSED, ids=[r[0][:40] or "empty" for r in REFUSED])
def test_anything_that_is_not_a_read_only_search_over_an_allowed_index_is_refused(
    platform, client, spl, said
):
    resp = query(platform, client, spl)
    assert resp.status_code == 400, resp.text
    assert said in resp.json()["error"]
    assert platform.requests == []  # refused before anything reached Splunk


@pytest.mark.parametrize(
    "extra,said",
    [({"earliest": "yesterday"}, "invalid earliest"), ({"latest": "soon"}, "invalid latest"), ({"count": "abc"}, ""), ({"count": 0}, "")],
)
def test_a_bad_window_or_count_is_a_400(platform, client, extra, said):
    if extra.get("count") == 0:
        # 0 means "the default", as for any missing count — not a request for none.
        assert query(platform, client, 'search index="main"', **extra).status_code == 200
        return
    resp = query(platform, client, 'search index="main"', **extra)
    assert resp.status_code == 400, resp.text
    assert said in resp.json()["error"]
    assert platform.requests == []


def test_a_search_needs_no_index_only_when_it_reads_nothing(platform, client):
    assert query(platform, client, "| makeresults count=1").status_code == 200


def test_opting_out_of_the_allowlist_still_leaves_the_commands_restricted(platform, client):
    everything = {"SPLUNK_ALLOWED_INDEXES": "*"}
    assert query(platform, client, "search index=* | head 5", env=everything).status_code == 200
    refused = query(platform, client, "search index=* | delete", env=everything)
    assert refused.status_code == 400 and "command 'delete'" in refused.json()["error"]


# ── Splunk is wrong: a 502, with its own reason ────────────────────────────

@pytest.mark.parametrize(
    "reply,said",
    [
        (httpx.ConnectError("refused"), "cannot reach Splunk"),
        (httpx.Response(401), "rejected SPLUNK_TOKEN"),
        (httpx.Response(403), "denied the search"),
        (httpx.Response(500, text="boom"), "500"),
    ],
    ids=["down", "token-refused", "denied", "server-error"],
)
def test_a_splunk_failure_is_a_502_not_a_400(platform, client, reply, said):
    # The caller did nothing wrong, and reporting a Splunk outage as a 400 sends
    # someone looking at their own request.
    resp = query(platform, client, 'search index="main" | head 1', reply)
    assert resp.status_code == 502, resp.text
    assert said in resp.json()["error"]


# ── there is no MCP layer, and no parameter routes ─────────────────────────

def test_the_mcp_transport_and_the_old_routes_are_gone(client):
    splunk = client("Splunk")
    for path in ("/mcp", "/search", "/summarise", "/frequency"):
        assert splunk.post(path, json={}).status_code == 401  # the gate still answers first
        assert splunk.post(path, json={}, headers=AUTH).status_code == 404, path


def test_the_service_no_longer_depends_on_the_mcp_sdk():
    imports = [
        path.name
        for path in (ROOT / "Splunk").glob("*.py")
        if re.search(r"^\s*(from|import) mcp\b", path.read_text(), re.M)
    ]
    assert imports == []
    assert "mcp" not in (ROOT / "Splunk" / "requirements.txt").read_text().replace("MCP", "")
