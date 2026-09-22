# Confluence playbook connector

Which runbook covers this alert, and what does it say.

The backend asks at the start of triage, before any model runs. Matching an
alert name to a playbook has one right answer, so it does not cost an
inference — the same reason the ThreatQ connector has a `/lookup` route.

```
POST /match   {"alert_name": "Malware detected in downloaded file"}
POST /sync                       re-read the space now
GET  /health
```

Tools for an agent that wants to look further: `find_playbook`,
`list_playbooks`. Neither can write.

## Matching

Two tiers, both free:

| Tier | Handles |
| --- | --- |
| exact | a known alert name, after case and spacing are folded |
| fuzzy | a detection that was renamed — `Malware detected in download file` → `…downloaded file`, 0.971 |

Aliases count as names, so `Virus detected` and `T1110` route to their
playbooks. Dots and hyphens survive normalisation, which is what keeps
`T1059.001` one token.

A miss is reported as a miss. A playbook that nearly matches is worse than
none: the analyst reads criteria written for a different detection and has no
way to tell. `how` comes back with every answer for the same reason — a fuzzy
match is a guess that cleared a threshold.

The notebook's third tier (dense + lexical retrieval for genuinely novel
wording) is not here. It needs an embedding model resident in memory and
answers a question this service is not being asked yet: matching a *question*
to a playbook rather than an alert. `match` returns `how`, so it slots in
without changing callers.

## `splunk_query` holds parameters, not SPL

```json
{"index": "main", "sourcetype": "fortigate",
 "filters": {"action": "blocked"},
 "group_by": ["srcip"], "metrics": [{"fn": "count"}]}
```

Storing the analyst's search verbatim and running it would hand anyone with
edit access to the Confluence space the ability to run arbitrary SPL as the
service account — and SPL is not read-only: `| delete`, `| collect`,
`| outputlookup` and `| script` all write or destroy. So the field holds
parameters and the Splunk connector builds the search, through the same
validation everything else goes through.

A cell that is not JSON is dropped with a warning rather than passed on as a
string for something downstream to guess at.

## Running without Confluence

Leave `CONFLUENCE_BASE_URL` empty and it reads `PLAYBOOK_FILE`
(`tests/playbooks.sample.json`), so the stack comes up on a workstation with no
Atlassian account and the matching can be exercised.

## Settings

| | |
| --- | --- |
| `CONFLUENCE_MCP_AUTH_TOKEN` | required; callers send it as a bearer |
| `CONFLUENCE_BASE_URL` | `https://your-org.atlassian.net/wiki` |
| `CONFLUENCE_SPACE_KEY` | e.g. `SOC` |
| `CONFLUENCE_EMAIL` + `CONFLUENCE_API_TOKEN` | Cloud: basic auth. Leave the email empty for a Server/DC personal access token, which is sent as a bearer |
| `CONFLUENCE_API_PATH` | `/rest/api`. Cloud needs `/wiki` in the base URL; Server and DC do not |
| `FUZZY_CUTOFF` | `0.85` |
| `SYNC_INTERVAL_MINUTES` | `30` |

## When a sync fails

The previous corpus is kept and `stale: true` comes back with every match.
Serving yesterday's playbooks beats serving none: an empty corpus answers every
alert with "no playbook covers this", which is indistinguishable from a real
gap in the wiki.

## Page Properties

Playbooks are authored with the Page Properties macro, which stores each field
as a table row. `FIELD_LABELS` in `playbooks.py` maps the labels; a label that
is not there is ignored rather than guessed at, so a page that grows a new row
does not silently change what the matcher sees.

Two playbooks claiming the same name is reported as a conflict, not resolved —
whichever page loaded second is not an answer. A primary name does outrank an
alias.
