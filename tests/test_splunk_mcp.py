"""The MCP endpoint, spoken to the way the backend speaks to it.

/services/mcp with the two tools Splunk's own MCP Server publishes under the same
names: saia_generate_spl (Text-to-SPL) and splunk_run_query. The backend sends a
requirement as text, gets SPL back, and runs it. Mock mode answers from a fixed
set of events; nothing here contacts a platform.
"""

import json

import pytest
from starlette.testclient import TestClient

from conftest import AUTH, ROOT

MCP = "/services/mcp"
HEADERS = {**AUTH, "Accept": "application/json, text/event-stream"}


@pytest.fixture
def mcp(connector):
    """`mcp(**env)` -> call(method, params) against a running app (lifespan on:
    the MCP session manager starts there)."""
    clients = []

    def start(**env):
        app = connector("Splunk", **{"SPLUNK_MODE": "mock", **env}).app
        # An allowed Host: the endpoint refuses others (DNS-rebinding defence).
        client = TestClient(app, base_url="http://soc-mcp-splunk:8200", raise_server_exceptions=False)
        client.__enter__()
        clients.append(client)

        def call(method, params=None, headers=HEADERS):
            body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
            return client.post(MCP, json=body, headers=headers)

        return call

    yield start
    for client in clients:
        client.__exit__(None, None, None)


def result(resp):
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]


def tool(call, name, **args):
    """A tool's answer: (is_error, payload parsed from its text)."""
    answer = result(call("tools/call", {"name": name, "arguments": args}))
    text = "".join(c.get("text", "") for c in answer["content"])
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return answer.get("isError", False), payload


def test_it_publishes_the_two_tools_splunk_does(mcp):
    tools = {t["name"]: t for t in result(mcp()("tools/list"))["tools"]}
    assert {"saia_generate_spl", "splunk_run_query"} <= set(tools)
    # The backend reads the prompt argument from here rather than assuming a name.
    assert tools["saia_generate_spl"]["inputSchema"]["required"] == ["prompt"]
    assert "query" in tools["splunk_run_query"]["inputSchema"]["required"]
    for t in tools.values():
        assert t["annotations"]["readOnlyHint"] is True


def test_a_requirement_becomes_spl_and_the_spl_runs(mcp):
    call = mcp()
    failed, generated = tool(
        call, "saia_generate_spl",
        prompt="Find VPN login failures from 45.83.122.9.\nSearch index=main sourcetype=fortigate\n"
               "Time range: earliest=-24h latest=now",
    )
    assert not failed and generated["mock"] is True
    spl = generated["spl"]
    assert spl.startswith('search index="main" sourcetype="fortigate" "45.83.122.9"')
    assert 'earliest="-24h" latest="now"' in spl

    failed, ran = tool(call, "splunk_run_query", query=spl)
    assert not failed and ran["mock"] is True
    assert ran["count"] > 0
    assert all(row["srcip"] == "45.83.122.9" for row in ran["results"])


def test_a_count_question_is_answered_with_stats(mcp):
    call = mcp()
    _, generated = tool(call, "saia_generate_spl",
                        prompt="Which destinations did 10.1.100.11 talk to and how many times")
    assert "| stats count by" in generated["spl"]
    _, ran = tool(call, "splunk_run_query", query=generated["spl"])
    assert ran["results"] and all("count" in row for row in ran["results"])


def test_punctuation_after_a_value_is_not_part_of_it(mcp):
    _, generated = tool(mcp(), "saia_generate_spl", prompt="Show events for user=j.smith. latest=now.")
    assert '"j.smith"' in generated["spl"]
    assert 'latest="now"' in generated["spl"]


@pytest.mark.parametrize(
    "spl,said",
    [
        ('search index="main" | delete', "delete"),
        ('search index="main" [search index="main" | outputlookup x.csv]', "outputlookup"),
        ('search index="main" `evil_macro`', "macro"),
        ('search index="other" foo', "other"),
    ],
    ids=["delete", "write-in-subsearch", "macro", "index-outside-allowlist"],
)
def test_anything_that_is_not_a_read_only_search_is_refused(mcp, spl, said):
    failed, payload = tool(mcp(SPLUNK_ALLOWED_INDEXES="main"), "splunk_run_query", query=spl)
    assert failed
    assert said in str(payload)


# Splunk's own list of risky commands (SPL safeguards for risky commands).
SPLUNK_RISKY = ["collect", "delete", "dump", "map", "mcollect", "meventcollect", "outputcsv",
                "outputlookup", "run", "runshellscript", "script", "sendalert", "sendemail",
                "tscollect"]


@pytest.mark.parametrize("command", SPLUNK_RISKY)
def test_every_command_splunk_calls_risky_is_refused(mcp, command):
    failed, payload = tool(mcp(), "splunk_run_query", query=f'search index="main" | {command} x')
    assert failed
    assert command in str(payload)


def test_the_backend_refuses_the_same_commands(connector):
    # Two copies of one list: Backend/src/modules/enrichment/spl-guard.ts checks the
    # generated SPL before it is sent, this checks it again. A command added to one
    # and not the other is a gap in the check that should have caught it.
    import re
    import sys

    connector("Splunk")
    spl = sys.modules["spl"]

    guard = (ROOT.parent / "Backend" / "src" / "modules" / "enrichment" / "spl-guard.ts")
    if not guard.exists():
        pytest.skip("Backend is not checked out beside this repo")
    block = re.search(r"FORBIDDEN_COMMANDS = new Set\(\[(.*?)\]\)", guard.read_text(), re.S).group(1)
    assert set(re.findall(r"'([a-z_]+)'", block)) == set(spl.FORBIDDEN_COMMANDS)


def test_live_mode_has_no_text_to_spl_of_its_own(mcp):
    # In production Text-to-SPL is Splunk AI Assistant behind Splunk's own MCP
    # server; this one says so instead of pretending.
    failed, payload = tool(
        mcp(SPLUNK_MODE="live", SPLUNK_TOKEN="t", SPLUNK_ALLOWED_INDEXES="main"),
        "saia_generate_spl", prompt="anything",
    )
    assert failed
    assert "Splunk" in str(payload)


def test_the_endpoint_needs_the_token(mcp):
    call = mcp()
    assert call("tools/list", headers={"Accept": HEADERS["Accept"]}).status_code == 401
    wrong = {**HEADERS, "Authorization": "Bearer wrong"}
    assert call("tools/list", headers=wrong).status_code == 401


def test_a_host_it_does_not_serve_is_refused(mcp):
    call = mcp()
    assert call("tools/list", headers={**HEADERS, "Host": "evil.example"}).status_code == 421


def test_mock_needs_no_splunk_credentials(connector):
    # Mock talks to no Splunk; only the bearer token is required.
    connector("Splunk", SPLUNK_MODE="mock", SPLUNK_TOKEN="", SPLUNK_ALLOWED_INDEXES="")
    with pytest.raises(RuntimeError):
        connector("Splunk", SPLUNK_MODE="mock", MCP_AUTH_TOKEN="")


def test_an_unknown_mode_refuses_to_start(connector):
    with pytest.raises(RuntimeError):
        connector("Splunk", SPLUNK_MODE="mok")
