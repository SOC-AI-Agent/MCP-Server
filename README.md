# soc-mcp-server

`soc-mcp-splunk`: Splunk for the backend, over MCP. The backend sends each stage-2
requirement, as stage 1 stored it, to one tool — `splunk_lookup` — and this service
does everything Splunk-shaped: builds the prompt, has Text-to-SPL write the search,
checks it is read-only, runs it, and returns the SPL and the rows. That logic used
to be in the backend (`splunk-mcp.service.ts`, `spl-guard.ts`); it lives here now,
and the backend holds no Splunk credentials.

| | Port | What |
| --- | --- | --- |
| `Splunk/` | 8200 | The connector. MCP at `/services/mcp`, plus `/query`, `/catalog`, `/check-connection` for operators. [Splunk/README.md](Splunk/README.md) |
| `Confluence/` | 8600 | `soc-mcp-confluence`: the playbook space over MCP, read-only. MCP at `/mcp`, plus `/pages`, `/check-connection`. Started with `--profile confluence`. [Confluence/README.md](Confluence/README.md) |
| `external/splunk/` | 8000, 8089 (this machine only) | A Splunk Enterprise container for the connector to search in live mode, with sample events. [external/splunk/README.md](external/splunk/README.md) |

Which Splunk answers is `SPLUNK_MODE` and `SPLUNK_BASE_URL` in `.env`:

| | Searches run on | Text-to-SPL |
| --- | --- | --- |
| `mock` | a fixed set of events in `Splunk/mock.py` | a template |
| `live` + the container | `https://soc-splunk:8089` | a template (a plain Splunk has no AI Assistant) |
| `live` + the company's Splunk | `https://<search-head>:8089` | Splunk AI Assistant, with `SPLUNK_SAIA_MCP_URL` set; else the template |

**ThreatQ is not here.** It was an HTTP proxy that held the credentials; the backend
now calls it directly (`Backend/.env`: `THREATQ_*`). Its code is in this repo's
history. **Confluence is back as an MCP connector**, ready to use, but nothing calls
it yet: the backend still reads Confluence itself (`playbook-sync.service.ts`) until
it is pointed here.

```bash
# mock
cp .env.example .env     # SPLUNK_MODE=mock; MCP_AUTH_TOKEN = the value in Backend/.env
docker compose up -d --build

# live, against the Splunk container
cd external/splunk && cp .env.example .env      # set SPLUNK_PASSWORD
docker compose up -d                            # first start takes a few minutes
python3 setup.py --write-env                    # token, index, sample events -> ../../.env
cd ../.. && docker compose up -d --build
docker compose exec -T soc-mcp-splunk python check_connection.py

# Confluence (fill CONFLUENCE_* in .env first — it refuses to start without them)
docker compose --profile confluence up -d --build
docker compose exec -T soc-mcp-confluence python check_connection.py
```

## Deployment

The pipeline builds and tests this service and deploys nothing yet. That was right
while production's backend talked to Splunk's own MCP Server app directly; now that
the backend calls `splunk_lookup` here, **production needs this connector running
on `soc-network` beside the backend**, in live mode, with the company Splunk's URL,
token and CA in its `.env`. That deploy job is still to be written.

The **data catalogue** (`splunk-catalog.json`, `lookup-plans.json`), the scripts
that export it from Splunk and the `export_catalog` CI job moved to the Backend
repo, which is what reads them: `Backend/catalog/`, `Backend/scripts/`,
`Backend/docs/splunk-catalog.md`. The catalogue is built into the backend's image,
so no deployment depends on this repo being checked out beside it.

## Tooling

`notebooks/` is where playbook matching came from: `playbook_rag.ipynb` built and
measured the retrieval layer that now lives in `AI-Service/playbooks/`.

`tests/` is a pytest suite that needs no platform and no running stack: it loads
each connector in-process, with Splunk or Confluence replaced by a stand-in that
answers whatever a case says. It checks the MCP tools as the backend calls them (the prompt, Text-to-SPL by
template and by a stand-in for Splunk AI Assistant, the read-only guard, the
trimmed rows, the token and Host checks), what the routes do with a bad
token or body, and what `/check-connection` reports for each way Splunk can fail.

```bash
pip install -r tests/requirements.txt
python -m pytest
```

The `code_test` job runs it on every branch.

## Splunk outside Docker (live mode)

In live mode the connector reaches Splunk at `SPLUNK_BASE_URL`. For the container in
`external/splunk` that is `https://soc-splunk:8089` on `soc-network`, with a
self-signed certificate (`SPLUNK_VERIFY_SSL=false`; `setup.py` sets both).

For the company's Splunk it asks of the host: a route and an open port to the
management port `8089` (Splunk sees **the host's address**), DNS that resolves the
name from inside a container, and trust in its certificate — put an internal CA's
PEM in `certs/` and set `SSL_CERT_FILE=/certs/<file>.pem` (it replaces the built-in
list). Keep `SPLUNK_VERIFY_SSL=true`. For Text-to-SPL by Splunk AI Assistant set
`SPLUNK_SAIA_MCP_URL` to Splunk's MCP Server app and `SPLUNK_SAIA_MCP_TOKEN` to its
token; the apps, role, token, network and CA that needs are in
[Backend/docs/splunk-mcp.md](../Backend/docs/splunk-mcp.md).

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

The script lives in Backend because some of the secrets it generates have to
be identical in more than one repo — `MCP_AUTH_TOKEN` here and in Backend,
`AI_SERVICE_AUTH_TOKEN` in Backend and AI-Service — and they are the ones that
break quietly: a mismatch is a 401 with nothing saying why. Generating them in one place is the whole point. It does not touch
Agent-Server, which manages its own `.env`.

---

## Where this came from

Split out of the SOC-AI monorepo. The other pieces:

| Repo | What it is |
| --- | --- |
| `Backend` | API, queue worker, Postgres, Redis. The only writer to the database. |
| `AI-Service` | The backend's stateless door to the agent platform. |
| `MCP-Server` | The Splunk connector, and a Splunk container to run it against. |
| `Frontend` | The analyst dashboard. |

Plus [`Agent-Server`](../Agent-Server/readme.md) (DALL-M): agents as data —
model, prompt, tools — and the loop that runs them. A separate system, its own
network, reached by `AI-Service` over a URL rather than by container name.

They meet on one Docker network called `soc-network`, created by whichever
stack comes up first, and address each other by container name. Agent-Server is not on
`soc-network` and brings itself up on its own.

Each repo carries only the settings its own services read. In the monorepo one
`.env` was shared by every container, which meant the Splunk connector's
environment also held the database password and the ThreatQ credentials — a
compromise of any one service read the secrets of all of them.
