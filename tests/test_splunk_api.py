"""The Splunk connector as a plain HTTP API.

It is what the backend calls to run a search it has already planned — no MCP
transport and no model. These check what it runs, and what it answers when the
caller or Splunk is the one that is wrong.
"""

import re

import httpx
import pytest

from conftest import AUTH, ROOT

SEARCH = "/services/search/jobs"


def rows(*events):
    return httpx.Response(200, json={"results": list(events)})


# The alert index has to be one the allowlist names, or /frequency is refused.
ALERTS = {"SPLUNK_ALLOWED_INDEXES": "main,notable"}


def post(platform, client, path, payload, reply, **env):
    platform.by_path({SEARCH: reply})
    return client("Splunk", **env).post(path, json=payload, headers=AUTH)


# ── what it runs ───────────────────────────────────────────────────────────

def test_a_planned_search_runs_and_says_which_field_matched(platform, client):
    resp = post(
        platform, client, "/search",
        {"indicator": "10.0.0.1", "indicator_type": "ip", "fields": ["srcip", "dstip"], "index": "main"},
        rows({"_time": "t", "srcip": "10.0.0.1", "action": "blocked"}),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["events"][0]["matched_on"] == ["srcip"]
    assert body["fields_searched"] == ["srcip", "dstip"]
    # What was sent to Splunk is what the answer says it was.
    (sent,) = [r for r in platform.requests if r.url.path == SEARCH]
    assert b"srcip" in sent.content and b"10.0.0.1" in sent.content
    assert body["spl"]


def test_a_summary_groups_instead_of_listing(platform, client):
    resp = post(
        platform, client, "/summarise",
        {"index": "main", "group_by": ["dstip"], "metrics": [{"fn": "count"}]},
        rows({"dstip": "1.2.3.4", "count": "7"}),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["rows"] == [{"dstip": "1.2.3.4", "count": "7"}]
    assert "stats" in resp.json()["spl"]


def test_an_alert_frequency_totals_the_days(platform, client):
    resp = post(
        platform, client, "/frequency", {"alert_name": "Some Rule", "days": 7},
        rows({"_time": "2026-09-20", "count": "3"}, {"_time": "2026-09-21", "count": "4"}),
        **ALERTS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["total"], body["days_seen"]) == (7, 2)


# ── the caller is wrong: a 400 that says how ───────────────────────────────

@pytest.mark.parametrize(
    "path,payload,said",
    [
        ("/search", {"indicator": "10.0.0.1", "indicator_type": "ip", "fields": ["srcip"], "index": "secret"}, "not allowed"),
        ("/search", {"indicator": "a\nb", "indicator_type": "ip", "fields": ["srcip"]}, "newlines"),
        ("/search", {"indicator": "x", "indicator_type": "ip", "fields": ["not a field"]}, "invalid field"),
        ("/summarise", {"index": "main", "metrics": [{"fn": "drop"}]}, ""),
        ("/frequency", {"alert_name": "x", "days": 91}, "between 1 and 90"),
    ],
    ids=["index-not-allowed", "newline", "bad-field", "unknown-function", "days-too-many"],
)
def test_a_parameter_it_will_not_search_on_is_a_400(platform, client, path, payload, said):
    resp = post(platform, client, path, payload, rows(), **ALERTS)
    assert resp.status_code == 400, resp.text
    assert said in resp.json()["error"]
    assert platform.requests == []  # refused before anything reached Splunk


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
    resp = post(
        platform, client, "/search",
        {"indicator": "10.0.0.1", "indicator_type": "ip", "fields": ["srcip"]}, reply,
    )
    assert resp.status_code == 502, resp.text
    assert said in resp.json()["error"]


# ── there is no MCP layer ──────────────────────────────────────────────────

def test_the_mcp_transport_is_gone(client):
    splunk = client("Splunk")
    assert splunk.post("/mcp", json={}).status_code == 401  # the gate still answers first
    assert splunk.post("/mcp", json={}, headers=AUTH).status_code == 404


def test_the_service_no_longer_depends_on_the_mcp_sdk():
    imports = [
        path.name
        for path in (ROOT / "Splunk").glob("*.py")
        if re.search(r"^\s*(from|import) mcp\b", path.read_text(), re.M)
    ]
    assert imports == []
    assert "mcp" not in (ROOT / "Splunk" / "requirements.txt").read_text().replace("MCP", "")
