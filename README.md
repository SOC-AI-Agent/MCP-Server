# soc-mcp-server

Tool servers for the AI agent, one per platform they front.

| Connector | Port | Fronts |
| --- | --- | --- |
| `Splunk/` | 8200 | Searching logs. Builds every search from structured parameters — the model never writes SPL. |
| `Threatq/` | 8300 | Indicator reputation. |
| `Confluence/` | 8600 | Which playbook covers an alert, and what it says. |

```bash
cp .env.example .env     # platform credentials and one bearer token each
docker compose up -d --build
```

Each carries its own token on purpose: one stolen token should not open all
three.

## The data catalogue lives here

`Splunk/catalog/` holds two files a person edits:

- `splunk-catalog.json` — which index and sourcetype hold what, and which field
  carries which meaning. It is what turns "10.1.100.44 is a source IP" into
  "search `srcip`", and searching a CIM name against raw vendor logs that do
  not use it returns zero events and reads as "nothing happened".
- `lookup-plans.json` — what to ask Splunk when an alert carries a given kind
  of indicator.

`soc-backend` mounts this directory read-only. It is the one file dependency
between repos; the backend's compose points at `../soc-mcp-server/Splunk/catalog`
by default and takes `MCP_CATALOG_PATH` to override it.

## Tooling

`scripts/` is everything that produces or checks the data catalogue:

| | |
| --- | --- |
| `export_splunk_catalog.sh` | Pulls indexes, sourcetypes and fields out of Splunk. |
| `verify_catalog_export.py` | Says whether an export is complete enough to use — exit 0 or 1, so CI can branch on it. |
| `make_catalog_template.py` | Turns that export into a catalogue skeleton, marking every guess. |
| `plan_query_agents.py` | Groups sourcetypes into query agents. |

The `export_catalog` job in `.gitlab-ci.yml` runs the first two. It is manual:
it searches a production search head, and the catalogue changes when the
estate does, not on a timer. It exports only when `Splunk/table/` does not
already hold a complete one, and leaves the result as a job artifact rather
than committing it — the export carries field names and, with the right
flags, example values from real events, and git history is not a place to
put those by accident.

`docs/splunk-catalog.md` is the long version — what to export, what the files
mean, and what to check before trusting one in production.

`notebooks/` is where the Confluence connector came from: `playbook_rag.ipynb`
built and measured the retrieval layer, and `router.py` here is that work as a
service.

`api-tests/` is a Bruno collection for the three connectors.

## Test doubles, and keeping them out of production

This repo runs against stand-ins on a workstation and against the real
platforms everywhere else. The difference is not visible in an answer, which is
why it is enforced rather than documented:

| Setting | Workstation | Production |
| --- | --- | --- |
| `SPLUNK_BASE_URL` | a local Splunk container | the real search head |
| `THREATQ_BASE_URL` | `threatq.local`, or a stand-in | the real appliance |
| `SPLUNK_VERIFY_SSL` / `THREATQ_VERIFY_SSL` | `false` for a self-signed lab cert | `true` |

The deploy job checks all of them before bringing anything up. A pipeline
pointed at a stand-in fails there rather than serving confident answers about
data nobody has.

### Confluence has no fallback

It used to read sample playbooks when `CONFLUENCE_BASE_URL` was unset, so the
stack would come up without an Atlassian account. Those came back through
`/match` in the shape of a real runbook — version number and all — and an
analyst reading "FALSE POSITIVE when: EICAR test file" had nothing telling them
nobody wrote that for this estate.

That is gone. Unconfigured now means the connector refuses to start, and
`/match` answers `503 how: "unconfigured"` rather than a miss. The two are
different facts: a miss means the wiki was searched and covers nothing, and
this means the wiki was never reached.

---

## Where this came from

Split out of the SOC-AI monorepo. The other pieces:

| Repo | What it is |
| --- | --- |
| `Backend` | API, queue worker, Postgres, Redis. The only writer to the database. |
| `AI-Service` | The backend's stateless door to the agent platform. |
| `LLM-Server` | Agents as data — model, prompt, tools — and the loop that runs them. |
| `MCP-Server` | Tool servers for Splunk, ThreatQ and Confluence. |
| `Frontend` | The analyst dashboard. |

They meet on one Docker network called `soc-network`, created by whichever
stack comes up first, and address each other by container name. Bring up
`MCP-Server` and `LLM-Server` first: those are the ones the rest call.

Each repo carries only the settings its own services read. In the monorepo one
`.env` was shared by every container, which meant the Splunk connector's
environment also held the database password and the ThreatQ credentials — a
compromise of any one service read the secrets of all of them.
