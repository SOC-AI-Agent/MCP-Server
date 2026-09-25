# soc-mcp-server

One connector per external platform. The backend calls each over plain HTTP; ThreatQ
and Confluence also publish MCP tools an agent can call.

| Connector | Port | Fronts | How it is called |
| --- | --- | --- | --- |
| `Splunk/` | 8200 | Running searches. The backend builds the SPL from a plan; this refuses anything that is not a read-only search over an allowed index. | `POST /query`, nothing else a caller uses. **No MCP, no model** — the backend plans each search from the catalogue and writes the SPL; this checks it (read-only, allowed indexes) and runs it. |
| `Threatq/` | 8300 | Indicator reputation. | `POST /lookup` for the backend; the `lookup_indicator` tool for an agent (none uses it yet). |
| `Confluence/` | 8600 | The playbook space. Holds the Confluence credentials and reads the pages; matching them to alerts is the AI service's job now (`AI-Service/playbooks/`). | `GET /pages` for the backend's worker, which passes the pages to the AI service to index. `POST /match` and the read-only tools remain, but nothing on the triage path calls them. |

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

`soc-backend` mounts this directory read-only; the Splunk connector does not read it. It is the one file dependency
between repos; the backend's compose points at `../MCP-Server/Splunk/catalog`
by default and takes `MCP_CATALOG_PATH` to override it.

## Tooling

`scripts/` is everything that produces or checks the data catalogue:

| | |
| --- | --- |
| `export_splunk_catalog.py` | Pulls indexes, sourcetypes and fields out of Splunk. |
| `verify_catalog_export.py` | Says whether an export is complete enough to use — exit 0 or 1, so CI can branch on it. |
| `make_catalog_template.py` | Turns that export into a catalogue skeleton, marking every guess. |
| `plan_query_agents.py` | Groups sourcetypes into query agents. **Obsolete** — no agent searches Splunk any more. |

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

`tests/` is a pytest suite that needs no platform and no running stack: it loads
each connector in-process, with the platform replaced by a stand-in that answers
whatever a case says. It checks what the routes do with a bad token or a body
that is not a JSON object, what `/check-connection` reports for each way a
platform can fail, and that Confluence answering with a login page does not kill
the connector.

```bash
pip install -r tests/requirements.txt
python -m pytest
```

The `code_test` job runs it on every branch.

## Platforms outside Docker

Splunk, ThreatQ and Confluence are not part of this stack. They run on the
company network and the connectors reach them at `SPLUNK_BASE_URL`,
`THREATQ_BASE_URL` and `CONFLUENCE_BASE_URL`. What that asks of the machine that
hosts these containers:

- **A route and an open port** from this host to each platform (Splunk's
  management port `8089`, `443` for the others). Traffic leaves the containers
  through the host, so the platforms see **the host's address** — that is the one
  to allow if they restrict sources.
- **DNS** that resolves the company names from inside a container. Containers
  use the host's resolvers through Docker; if a name does not resolve, use the
  address or set `dns:` on the service.
- **Trust in their certificates.** An internal CA is not in the container's CA
  list. Put its PEM in `certs/` and set `SSL_CERT_FILE=/certs/<file>.pem` in
  `.env`; `*_VERIFY_SSL` stays `true`, and the deploy job refuses to run with it
  off. `SSL_CERT_FILE` replaces the built-in list, so the file must hold every CA
  the three platforms chain to. A certificate has to name the host you call: an
  address in `*_BASE_URL` needs the address in the certificate's SAN.

The deploy job checks all of this from inside each container, after it starts:
`failed_at: reach` in its output is one of the three above. See "Check it is
connected" in each connector's README.

## Test doubles, and keeping them out of production

This repo runs against stand-ins on a workstation and against the real
platforms everywhere else. The difference is not visible in an answer, which is
why it is enforced rather than documented:

| Setting | Workstation | Production |
| --- | --- | --- |
| `SPLUNK_BASE_URL` | a local Splunk container | the real search head |
| `THREATQ_BASE_URL` | the real appliance — no stand-in ships | the real appliance |
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

## Running the whole stack

This repo runs on its own with the compose file above, which is enough to work
on it. Running the SOC end to end takes four repos, checked out side by side,
and one script that writes the `.env` files — plus
[Agent-Server](../Agent-Server/readme.md), run separately with its own compose
(it is not one of the four; see `AI-Service/README.md`, "Agent-Server"):

```bash
git clone https://gitlab.com/agentic-soc/backend.git      Backend
git clone https://gitlab.com/agentic-soc/frontend.git     Frontend
git clone https://gitlab.com/agentic-soc/ai-service.git   AI-Service
git clone https://gitlab.com/agentic-soc/mcp-server.git   MCP-Server
git clone https://gitlab.com/agentic-soc/Agent-Server.git Agent-Server

cd Backend
./deploy/dev-setup.sh                            # writes .env in Backend, AI-Service, MCP-Server
docker compose -f deploy/dev.yml --project-directory . up -d --build   # http://localhost:3001

cd ../Agent-Server
cp .env.example .env && docker compose up -d --build   # http://localhost:7100
```

The script lives in Backend because three of the secrets it generates have to
be identical in more than one repo — the tokens the connectors check — and
they are the ones that break quietly: a mismatch is a 401 with nothing saying
why. Generating them in one place is the whole point. It does not touch
Agent-Server, which manages its own `.env`.

---

## Where this came from

Split out of the SOC-AI monorepo. The other pieces:

| Repo | What it is |
| --- | --- |
| `Backend` | API, queue worker, Postgres, Redis. The only writer to the database. |
| `AI-Service` | The backend's stateless door to the agent platform. |
| `MCP-Server` | Tool servers for Splunk, ThreatQ and Confluence. |
| `Frontend` | The analyst dashboard. |

Plus [`Agent-Server`](../Agent-Server/readme.md) (DALL-M): agents as data —
model, prompt, tools — and the loop that runs them. A separate system, its own
network, reached by `AI-Service` over a URL rather than by container name.

They meet on one Docker network called `soc-network`, created by whichever
stack comes up first, and address each other by container name. Bring up
`MCP-Server` first: it is the one the rest call. Agent-Server is not on
`soc-network` and brings itself up on its own.

Each repo carries only the settings its own services read. In the monorepo one
`.env` was shared by every container, which meant the Splunk connector's
environment also held the database password and the ThreatQ credentials — a
compromise of any one service read the secrets of all of them.
