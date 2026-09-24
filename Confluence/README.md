# Confluence playbook connector

Reads the playbook space. It holds the Confluence credentials, so it is the one
thing that talks to Confluence, and it does not decide what a page means.

```
GET  /pages              every current page: {id, title, version, url, body}
GET  /check-connection   can Confluence be read right now
GET  /health
```

`body` is the page's storage-format XHTML, unparsed. The backend's worker reads
`/pages` every `PLAYBOOK_SYNC_MINUTES` and sends the pages to the AI service
(`PUT /playbooks/index`), which extracts the Page Properties fields, embeds them
and does the matching — by name, then spelling, then meaning. See
`AI-Service/README.md`. A space that cannot be read is a `502`, never an empty
list: the caller would take an empty list for an emptied wiki.

## What is still here, off the triage path

```
POST /match   {"alert_name": "Malware detected in downloaded file"}
POST /sync                       re-read the space now
```

Plus the tools `find_playbook` and `list_playbooks`. These are the matcher as
it was before matching moved to the AI service: exact and fuzzy name matching
over a corpus this connector re-reads every `SYNC_INTERVAL_MINUTES`. The backend
no longer calls them and no agent is given them. They are left in place until
someone decides to remove them; until then this connector still reads the space
on its own schedule as well as when `/pages` is asked.

One thing the AI service does differently: it reduces each cell to its text.
This connector keeps a cell's XHTML, so a name the editor wrapped in `<p>` is
matched here as `p excessive failed logins p` — fuzzily at best.

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
parameters and the backend builds the search (`Backend/src/modules/enrichment/spl.ts`),
through the same validation everything else goes through.

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
