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

`.github/workflows/splunk-catalog.yml` runs the first two: it exports into
`Splunk/table/` only when there is not already a complete export there.

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
| `THREATQ_BASE_URL` | `threatq.local`, or the fake from the old stack | the real appliance |
| `ALLOW_SAMPLE_PLAYBOOKS` | `true` | `false` |
| `SPLUNK_VERIFY_SSL` / `THREATQ_VERIFY_SSL` | `false` for a self-signed lab cert | `true` |

`ALLOW_SAMPLE_PLAYBOOKS` is the one that bites. With Confluence unconfigured
the connector used to fall back to `Confluence/tests/playbooks.sample.json` —
two playbooks written to exercise the matcher. They come back through `/match`
in the same shape as a real one, with a version number, and an analyst reading
"FALSE POSITIVE when: EICAR test file" has nothing telling them nobody wrote
that for this estate.

So the connector now refuses to start when Confluence is unconfigured unless
the flag is explicitly set, `/match` and `/health` carry `samples: true` when
it is, and every match comes back with a warning saying so.

The deploy job checks all four before bringing anything up. A production
pipeline pointed at a stand-in fails there rather than serving confident
answers about data nobody has.

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
