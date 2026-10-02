# soc-mcp-server

`soc-mcp-splunk`: Splunk over MCP, for development. The backend sends each stage-2
requirement to Splunk as text over MCP — `saia_generate_spl` (Text-to-SPL) writes
the search, `splunk_run_query` runs it — and this service answers both in
`SPLUNK_MODE=mock` from a fixed set of events. In production the backend points at
**Splunk's own MCP Server app** instead: see
[Splunk/README.md — Production: connecting to Splunk](Splunk/README.md#production-connecting-to-splunk).

| Service | Port | What |
| --- | --- | --- |
| `Splunk/` | 8200 | MCP at `/services/mcp` (tools named as Splunk names them), plus `/query`, `/catalog`, `/check-connection` for operators. |

**ThreatQ and Confluence are no longer here.** They were HTTP proxies that held the
credentials; the backend now calls both directly (`Backend/.env`: `THREATQ_*`,
`CONFLUENCE_*`). Their code is in this repo's history.

```bash
cp .env.example .env     # SPLUNK_MODE=mock; MCP_AUTH_TOKEN = the value in Backend/.env
docker compose up -d --build
```

## Not deployed

This repo is for development only. In production the backend talks to Splunk's
own MCP Server app, so the pipeline builds and tests this service and deploys
nothing.

The **data catalogue** (`splunk-catalog.json`, `lookup-plans.json`), the scripts
that export it from Splunk and the `export_catalog` CI job moved to the Backend
repo, which is what reads them: `Backend/catalog/`, `Backend/scripts/`,
`Backend/docs/splunk-catalog.md`. The catalogue is built into the backend's image,
so no deployment depends on this repo being checked out beside it.

## Tooling

`notebooks/` is where playbook matching came from: `playbook_rag.ipynb` built and
measured the retrieval layer that now lives in `AI-Service/playbooks/`.

`tests/` is a pytest suite that needs no platform and no running stack: it loads
the connector in-process, with Splunk replaced by a stand-in that answers whatever
a case says. It checks the MCP tools as the backend calls them (mock Text-to-SPL,
the read-only guard, the token and Host checks), what the routes do with a bad
token or body, and what `/check-connection` reports for each way Splunk can fail.

```bash
pip install -r tests/requirements.txt
python -m pytest
```

The `code_test` job runs it on every branch.

## Splunk outside Docker (live mode)

In live mode the connector reaches Splunk at `SPLUNK_BASE_URL`, on the company
network. That asks of the host: a route and an open port to the management port
`8089` (Splunk sees **the host's address**), DNS that resolves the name from inside
a container, and trust in its certificate — put an internal CA's PEM in `certs/` and
set `SSL_CERT_FILE=/certs/<file>.pem` (it replaces the built-in list).
Keep `SPLUNK_VERIFY_SSL=true` unless it is a self-signed lab Splunk.

The production backend does not go through this service at all — it talks to
Splunk's MCP Server app directly, and what that needs (apps, role, token, network,
CA) is in [Splunk/README.md](Splunk/README.md#production-connecting-to-splunk).

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
| `MCP-Server` | The Splunk MCP server (mock for development). |
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
