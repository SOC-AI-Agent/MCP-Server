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

You cannot. There is no sample-playbook fallback: without `CONFLUENCE_BASE_URL`
and `CONFLUENCE_API_TOKEN` the connector refuses to start, and `/match` would
answer `503 how: "unconfigured"` if it did. Confluence runs outside this Docker
network, on the company network, and is reached at `CONFLUENCE_BASE_URL`.

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

## Check it is connected

```bash
docker compose exec -T soc-mcp-confluence python check_connection.py
```

```json
{"connected":true,"base_url":"https://wiki.example.com","space_key":"SOC","latency_ms":180}
```

One authenticated read of the space's own record — no page is fetched and
nothing is written — and the answer says where it stopped:

| `failed_at` | Meant | Usually |
| --- | --- | --- |
| `config` | nothing to connect with | `CONFLUENCE_BASE_URL` or `CONFLUENCE_API_TOKEN` unset |
| `reach` | no answer, or not Confluence's REST API | wrong URL, DNS, a firewall, an internal CA the container does not trust (see `SSL_CERT_FILE` in `../.env.example`), or a login page — an SSO gateway answers with one, sometimes as a `200` |
| `auth` | credentials refused (401) | wrong `CONFLUENCE_API_TOKEN` or `CONFLUENCE_EMAIL` |
| `read` | authenticated, but the space is not visible (403/404) | wrong `CONFLUENCE_SPACE_KEY`, no view permission on it, or a `CONFLUENCE_BASE_URL` missing a path such as `/wiki` |

The script calls `GET /check-connection` with the connector's own token, read
from the container's environment. The route answers `200` when connected and
`502` when not, and sits behind the bearer token unlike `/health`. The deploy
job runs the script after the containers are up and fails the pipeline if it
exits 1. `/health` only says the process is up and whether the last read worked.

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
