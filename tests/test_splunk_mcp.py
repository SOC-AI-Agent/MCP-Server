"""The MCP endpoint, spoken to the way the backend speaks to it.

/services/mcp. The backend sends a requirement as stage 1 stored it to
splunk_lookup and gets the SPL that ran and its rows back; splunk_text_to_spl is
the first half alone. Under them are the two tools Splunk's own MCP Server
publishes under the same names: saia_generate_spl (Text-to-SPL) and
splunk_run_query. Mock mode answers from a fixed set of events; nothing here
contacts a platform.
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


LIVE = {"SPLUNK_MODE": "live", "SPLUNK_TOKEN": "t", "SPLUNK_ALLOWED_INDEXES": "main"}


def test_live_mode_without_the_assistant_writes_spl_from_a_template(mcp):
    # A plain Splunk has no AI Assistant. The template assumes nothing about the
    # data: the index and the field names are the ones the request names.
    failed, generated = tool(
        mcp(**LIVE), "saia_generate_spl",
        prompt="Which destinations did 10.1.100.11 talk to.\nSearch index=main\n"
               "Field names in this data: 10.1.100.11 is in srcip or dstip. Use these field names.\n"
               "Time range: earliest=-24h latest=now",
    )
    assert not failed
    assert generated["mock"] is False and generated["generator"] == "template"
    # In the fields it was placed in: as a bare term, "what did it reach" (srcip)
    # and "what reached it" (dstip) would be one search.
    assert generated["spl"] == (
        'search index="main" (srcip="10.1.100.11" OR dstip="10.1.100.11") earliest="-24h" latest="now" '
        "| stats count by srcip, dstip | sort - count | head 20"
    )


# The structured lines lookup.build_prompt writes, and the SPL each becomes.
@pytest.mark.parametrize("lines, spl", [
    # A value that is no IP, hash or user is still searched, and a backslash is doubled.
    (["Who ran it.", "Field names in this data: CORP\\bob is in User. Use these field names."],
     'search index="main" User="CORP\\\\bob" earliest="-24h" latest="now" | head 50 | fields *'),
    # Two details narrow: both have to be there. Neither is searched again as a bare term.
    (["Logons.", "Details from the alert:", "- user: bob", "- source: 10.1.100.11",
      "Field names in this data: bob is in Account_Name; 10.1.100.11 is in src or dest. Use these field names."],
     'search index="main" Account_Name="bob" (src="10.1.100.11" OR dest="10.1.100.11") '
     'earliest="-24h" latest="now" | head 50 | fields *'),
    # A playbook's own filters.
    (["Installed services.", 'Only events where EventCode="7045" and LogName="System".'],
     'search index="main" EventCode="7045" LogName="System" earliest="-24h" latest="now" | head 50 | fields *'),
    # A grouped count, in the plan's names for the functions.
    (["How much.", "Summarise: count, distinct_count(dstip) by action sorted by -count.",
      "Field names in this data: 10.1.100.11 is in srcip. Use these field names."],
     'search index="main" srcip="10.1.100.11" earliest="-24h" latest="now" '
     "| stats count, dc(dstip) by action | sort - count | head 20"),
    # Per hour: every span is a row, and none is cut off.
    (["A steady beat.", "Summarise: count per 1h."],
     'search index="main" earliest="-24h" latest="now" | bin _time span=1h | stats count by _time'),
    # A summary this cannot write is not guessed at: the events, as before.
    (["Odd.", "Summarise: percentile(bytes)."],
     'search index="main" earliest="-24h" latest="now" | head 50 | fields *'),
    # No field named for a value: a bare term, as it always was.
    (["Anything about 10.1.100.11."],
     'search index="main" "10.1.100.11" earliest="-24h" latest="now" | head 50 | fields *'),
])
def test_the_template_reads_the_lines_the_prompt_is_built_from(mcp, lines, spl):
    prompt = "\n".join([lines[0], "Search index=main", *lines[1:], "Time range: earliest=-24h latest=now"])
    failed, generated = tool(mcp(**LIVE), "saia_generate_spl", prompt=prompt)
    assert not failed
    assert generated["spl"] == spl


def test_the_live_template_names_no_index_the_request_did_not(mcp):
    _, generated = tool(mcp(**LIVE), "saia_generate_spl", prompt="Show events for 10.1.100.11")
    assert "index=" not in generated["spl"]
    # Fast mode extracts only the fields a search names.
    assert generated["spl"].endswith("| head 50 | fields *")


# ── The backend's tools ────────────────────────────────────────────────────────

QUESTION = {
    "requirement": "What else did 45.83.122.9 touch around the alert.",
    "index": "main",
    "sourcetype": "fortigate",
    "context": {"source": "45.83.122.9", "device": "FGT-01", "nested": {"dropped": True}},
    "fieldHints": [{"value": "45.83.122.9", "fields": ["srcip", "dstip"]}],
    "earliest": "2026-10-01T00:00:00Z",
    "latest": "2026-10-02T00:00:00Z",
    # The stored plan carries more than the lookup uses.
    "indicatorType": "ip",
}


def test_it_publishes_the_tools_the_backend_calls(mcp):
    tools = {t["name"]: t for t in result(mcp()("tools/list"))["tools"]}
    for name in ("splunk_lookup", "splunk_text_to_spl", "splunk_prompt"):
        assert tools[name]["inputSchema"]["required"] == ["question"]
        assert tools[name]["annotations"]["readOnlyHint"] is True


def test_a_lookup_is_the_prompt_the_spl_and_the_rows(mcp):
    failed, got = tool(mcp(), "splunk_lookup", question={**QUESTION, "earliest": None, "latest": None})
    assert not failed and "error" not in got
    assert got["prompt"].split("\n") == [
        "What else did 45.83.122.9 touch around the alert.",
        "Details from the alert:",
        "- source: 45.83.122.9",
        "- device: FGT-01",
        "Search index=main sourcetype=fortigate",
        "Field names in this data: 45.83.122.9 is in srcip or dstip. Use these field names.",
        "Time range: earliest=-24h latest=now",
    ]
    assert got["spl"].startswith('search index="main" sourcetype="fortigate" "45.83.122.9"')
    assert got["count"] == len(got["rows"]) > 0 and got["capped"] is False
    assert all(row["srcip"] == "45.83.122.9" for row in got["rows"])
    assert got["mock"] is True
    assert got["answer"].startswith(f"Splunk ran: {got['spl']}\n{got['count']} row(s).")
    assert "MOCK DATA" in got["answer"]


def test_the_alert_window_goes_to_splunk_as_epoch_seconds(mcp):
    _, got = tool(mcp(), "splunk_text_to_spl", question=QUESTION)
    assert got["prompt"].endswith("Time range: earliest=1790812800 latest=1790899200")
    assert 'earliest="1790812800" latest="1790899200"' in got["spl"]
    assert got["searched"] is False and "rows" not in got


def test_text_to_spl_alone_says_when_the_spl_would_not_run(mcp):
    failed, got = tool(mcp(SPLUNK_ALLOWED_INDEXES="main"), "splunk_text_to_spl",
                       question={"requirement": "Show logins", "index": "other"})
    assert not failed
    assert got["generated"].startswith('search index="other"')
    assert "other" in got["refused"] and "spl" not in got


def test_a_lookup_that_cannot_run_is_an_answer_with_the_reason(mcp):
    # Not a tool error: the backend keeps the failed requirement, and what was
    # asked, beside the ones that worked.
    failed, got = tool(mcp(SPLUNK_ALLOWED_INDEXES="main"), "splunk_lookup",
                       question={"requirement": "Show logins", "index": "other"})
    assert not failed
    assert "refused" in got["error"] and "other" in got["error"]
    assert got["prompt"].startswith("Show logins.") and "rows" not in got


def test_a_lookup_that_splunk_fails_keeps_the_spl_it_tried(mcp, platform):
    import httpx

    platform.answer(httpx.Response(403))
    failed, got = tool(mcp(**LIVE), "splunk_lookup", question={"requirement": "Show logins", "index": "main"})
    assert not failed
    assert "403" in got["error"] and got["spl"].startswith('search index="main"')
    assert got["mock"] is False


def test_a_live_lookup_runs_on_splunk_and_trims_the_rows(mcp, platform):
    import httpx

    raw = "x" * 2000
    platform.answer(httpx.Response(200, json={"results": [
        {"_time": "t", "srcip": "10.1.100.11", "_raw": raw, "punct": "..", "host": "fwd", "date_hour": "2"},
    ]}))
    failed, got = tool(mcp(**LIVE), "splunk_lookup",
                       question={"requirement": "Show events for 10.1.100.11", "index": "main"})
    assert not failed and "error" not in got
    sent = platform.requests[-1]
    assert sent.url.path == "/services/search/jobs"
    assert "10.1.100.11" in sent.content.decode()
    (row,) = got["rows"]
    assert set(row) == {"_time", "srcip", "_raw"}
    assert row["_raw"].endswith("chars truncated]") and len(row["_raw"]) < 900
    assert "srcip=10.1.100.11" in got["answer"] and raw[:50] not in got["answer"]


def test_a_question_without_a_requirement_is_refused(mcp):
    failed, _ = tool(mcp(), "splunk_lookup", question={"index": "main"})
    assert failed
    failed, _ = tool(mcp(), "splunk_lookup", question={"requirement": "  "})
    assert failed


def test_how_often_an_alert_fired_is_asked_of_the_alert_index(mcp):
    _, got = tool(mcp(SPLUNK_ALERT_INDEX="alerts", SPLUNK_ALERT_NAME_FIELD="rule"), "splunk_text_to_spl",
                  question={"requirement": "How often has this alert fired", "index": "main",
                            "frequencyOf": "Excessive DNS Failures"})
    assert "Fired alerts are in index=alerts; the alert name is in the field rule." in got["prompt"]
    assert "Search index=main" not in got["prompt"]


def test_frequency_of_errors_cleanly_when_alert_index_unavailable(mcp):
    _, got = tool(mcp(**LIVE, SPLUNK_ALERT_INDEX="notable"), "splunk_text_to_spl",
                  question={"requirement": "How often has this alert fired", "index": "main",
                            "frequencyOf": "Excessive DNS Failures"})
    assert "SPLUNK_ALLOWED_INDEXES" in got["error"]
    assert "refused" not in got

    _, unset = tool(mcp(**LIVE, SPLUNK_ALERT_INDEX=""), "splunk_text_to_spl",
                    question={"requirement": "How often has this alert fired", "index": "main",
                              "frequencyOf": "Excessive DNS Failures"})
    assert "SPLUNK_ALERT_INDEX is unset" in unset["error"]


def test_a_playbook_search_carries_its_filters_and_its_count(mcp):
    _, got = tool(mcp(), "splunk_text_to_spl", question={
        "requirement": "Blocked traffic by destination",
        "alertIndex": "main", "alertSourcetype": "fortigate",
        "filters": {"action": "blocked"},
        "summarise": {"group_by": ["dstip", "dstport"], "metrics": [{"fn": "count"}, {"fn": "dc", "field": "srcip"}],
                      "span": "1h", "sort": "-count"},
        "indicator": "185.220.101.4", "fields": ["dstip"],
    })
    lines = got["prompt"].split("\n")
    assert "The alert came from index=main sourcetype=fortigate" in lines
    assert 'Only events where action="blocked".' in lines
    assert "Summarise: count, dc(srcip) by dstip, dstport per 1h sorted by -count." in lines
    assert "Field names in this data: 185.220.101.4 is in dstip. Use these field names." in lines


# ── SPL written by the caller's own agent ──────────────────────────────────────
# The backend shows its soc-spl agent what splunk_prompt returns and hands the
# reply back as `spl`. Nothing here calls a model.

REPLY = """Here is the search you asked for:

```spl
search index=main sourcetype=fortigate
    srcip="45.83.122.9"
| stats count by user, action
```
It counts the logins."""


def test_the_prompt_for_an_agent_is_the_request_and_the_answer_format(mcp):
    failed, got = tool(mcp(**LIVE), "splunk_prompt", question=QUESTION)
    assert not failed
    assert got["prompt"].startswith("What else did 45.83.122.9 touch around the alert.")
    assert (got["earliest"], got["latest"]) == ("1790812800", "1790899200")
    shown = got["writer_prompt"]
    assert shown.startswith("--- SPLUNK SEARCH REQUEST ---\n" + got["prompt"] + "\n--- END OF REQUEST ---")
    assert "--- ANSWER FORMAT ---" in shown and "```spl" in shown
    # The agent is told where it may look, and that it may only read.
    assert "Indexes you may search: main." in shown and "outputlookup" in shown


def test_the_prompt_tool_runs_nothing(mcp, platform):
    tool(mcp(**LIVE), "splunk_prompt", question=QUESTION)
    assert platform.requests == []


def test_an_agents_reply_is_read_checked_and_run(mcp, platform):
    import httpx

    platform.answer(httpx.Response(200, json={"results": [{"user": "j.smith", "action": "ssl-login-fail", "count": "6"}]}))
    failed, got = tool(mcp(**LIVE), "splunk_lookup", question=QUESTION, spl=REPLY)
    assert not failed and "error" not in got
    assert got["written_by"] == "caller"
    # Found in the prose, put on one line, and given the alert's window.
    assert got["generated"] == 'search index=main sourcetype=fortigate srcip="45.83.122.9" | stats count by user, action'
    assert got["spl"] == ('search earliest=1790812800 latest=1790899200 index=main sourcetype=fortigate '
                          'srcip="45.83.122.9" | stats count by user, action')
    assert got["spl"] in platform.requests[-1].content.decode().replace("+", " ") or "stats" in platform.requests[-1].content.decode()
    assert got["rows"] == [{"user": "j.smith", "action": "ssl-login-fail", "count": "6"}]
    assert "user=j.smith" in got["answer"]


def test_who_wrote_the_spl_is_said_either_way(mcp):
    call = mcp()
    assert tool(call, "splunk_lookup", question=QUESTION)[1]["written_by"] == "template"
    assert tool(call, "splunk_text_to_spl", question=QUESTION, spl=REPLY)[1]["written_by"] == "caller"


@pytest.mark.parametrize("reply,said", [
    ("```spl\nsearch index=main | delete\n```", "delete"),
    ("```spl\nsearch index=main [search index=main | outputlookup x.csv]\n```", "outputlookup"),
    ("index=other user=admin | head 5", "other"),
    ("```spl\nsearch index=main `get_all`\n```", "macro"),
    ("```\nsearch index=* | head 5\n```", "*"),
], ids=["delete", "write-in-subsearch", "index-outside-allowlist", "macro", "every-index"])
def test_what_an_agent_writes_is_checked_like_any_other_spl(mcp, platform, reply, said):
    # An alert's text is something an attacker can write, and it reaches the agent.
    failed, got = tool(mcp(**LIVE), "splunk_lookup", question={"requirement": "Show logins"}, spl=reply)
    assert not failed
    assert "refused" in got["error"] and said in got["error"]
    assert "rows" not in got and platform.requests == []


@pytest.mark.parametrize("reply", ["", "I cannot help with that.", "The answer is 42 events."])
def test_a_reply_with_no_spl_in_it_is_an_answer_with_the_reason(mcp, platform, reply):
    failed, got = tool(mcp(**LIVE), "splunk_lookup", question={"requirement": "Show logins"}, spl=reply)
    assert not failed
    assert "no SPL" in got["error"] and got["prompt"].startswith("Show logins.")
    assert platform.requests == []


def test_a_passed_spl_never_goes_to_the_assistant(mcp, assistant):
    call = mcp(**SAIA)
    prompts = assistant("search index=main")
    _, got = tool(call, "splunk_text_to_spl", question={"requirement": "Show logins"}, spl="index=main | stats count")
    assert prompts == [] and got["written_by"] == "caller"


# ── Every field of the events ──────────────────────────────────────────────────

@pytest.mark.parametrize("written,ran", [
    # Events, no columns named: all fields, of the rows that are kept.
    ('index=main "10.1.100.11"', 'index=main "10.1.100.11" | head 200 | fields *'),
    ('index=main srcip=10.1.100.11 | where dstport=445 | head 5', 'index=main srcip=10.1.100.11 | where dstport=445 | head 5 | fields *'),
    ('index=main | eval note="a | stats b" | sort - _time', 'index=main | eval note="a | stats b" | sort - _time | head 200 | fields *'),
    # The search names its own columns, or is not an event search: as written.
    ('index=main | stats count by srcip', None),
    ('index=main | table _time, srcip | head 5', None),
    ('index=main | head 5 | fields srcip', None),
    ('index=main [search index=main | head 1 | fields srcip]', None),
    ('| tstats count where index=main by sourcetype', None),
])
def test_an_event_search_is_asked_for_every_field(mcp, written, ran):
    _, got = tool(mcp(**LIVE), "splunk_text_to_spl", question={"requirement": "x"}, spl=written)
    window = "search earliest=-24h latest=now "
    expected = ran if ran is not None else written
    assert got["spl"] == (expected if expected.startswith("|") else window + expected)


def test_mock_keeps_every_field_when_asked_for_all(mcp):
    _, got = tool(mcp(), "splunk_lookup", question={"requirement": "x"}, spl='index=main "45.83.122.9" | head 3')
    assert got["spl"].endswith("| head 3 | fields *")
    assert got["count"] == 3 and all(row["srcip"] == "45.83.122.9" for row in got["rows"])


# ── Text-to-SPL by Splunk AI Assistant (SPLUNK_SAIA_MCP_URL) ───────────────────

@pytest.fixture
def assistant(monkeypatch):
    """Splunk's own MCP server, in-process: `assistant(reply)` makes its Text-to-SPL
    tool answer `reply` and returns the list of prompts it was sent."""

    def stand_in(reply, tool_name="saia_generate_spl"):
        import saia
        from mcp.server.mcpserver import MCPServer

        splunk_mcp = MCPServer("splunk-own")
        prompts: list[str] = []

        @splunk_mcp.tool(name=tool_name)
        async def generate(user_query: str) -> str:
            prompts.append(user_query)
            return reply

        monkeypatch.setattr(saia, "_target", lambda: splunk_mcp)
        return prompts

    return stand_in


SAIA = {**LIVE, "SPLUNK_SAIA_MCP_URL": "https://splunk.example:8089"}


def test_with_the_assistant_configured_text_to_spl_is_forwarded_to_it(mcp, assistant):
    call = mcp(**SAIA)
    # Whatever Splunk names the argument, and however it wraps the SPL.
    prompts = assistant("Here you go:\n```spl\nindex=main srcip=10.1.100.11 | stats count by dstip\n```")
    failed, got = tool(call, "splunk_text_to_spl", question={"requirement": "Who did 10.1.100.11 talk to"})
    assert not failed and "error" not in got
    assert prompts == [got["prompt"]]
    assert got["generated"] == "index=main srcip=10.1.100.11 | stats count by dstip"
    # The window it left out is added, and the check still runs.
    assert got["spl"] == "search earliest=-24h latest=now index=main srcip=10.1.100.11 | stats count by dstip"


def test_what_the_assistant_writes_is_still_checked(mcp, assistant):
    call = mcp(**SAIA)
    assistant("search index=main | delete")
    _, got = tool(call, "splunk_lookup", question={"requirement": "Remove the events"})
    assert "delete" in got["error"] and "rows" not in got


def test_a_splunk_without_the_assistant_says_so(mcp, assistant):
    call = mcp(**SAIA)
    assistant("unused", tool_name="splunk_run_query")
    _, got = tool(call, "splunk_lookup", question={"requirement": "Show logins"})
    assert "Splunk AI Assistant" in got["error"]


def test_the_assistant_endpoint_takes_a_bare_base_url(connector):
    import sys

    connector("Splunk", **SAIA)
    assert sys.modules["saia"].endpoint() == "https://splunk.example:8089/services/mcp"
    connector("Splunk", **{**SAIA, "SPLUNK_SAIA_MCP_URL": "https://splunk.example:8089/custom/mcp"})
    assert sys.modules["saia"].endpoint() == "https://splunk.example:8089/custom/mcp"


def test_mock_never_forwards_to_the_assistant(mcp, assistant):
    call = mcp(SPLUNK_SAIA_MCP_URL="https://splunk.example:8089")
    prompts = assistant("search index=main")
    _, got = tool(call, "splunk_lookup", question={"requirement": "Show events for 45.83.122.9"})
    assert prompts == [] and got["mock"] is True


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
