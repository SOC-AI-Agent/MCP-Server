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
