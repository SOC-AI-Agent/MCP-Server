# soc-mcp-splunk

Splunk over MCP for stage 2 of the SOC flow. Each requirement stage 1 wrote down
goes to Splunk **as text**; Splunk's Text-to-SPL writes the search, the backend
checks it, and Splunk runs it. No model on our side writes SPL any more.

```
stage 1 requirement (text + details from the alert; index, sourcetype and field names from the catalogue; the alert's window)
   │
soc-core-worker ──MCP── saia_generate_spl ──► SPL            (Text-to-SPL: Splunk AI Assistant for SPL)
   │  spl-guard: read-only, allowed indexes, the alert's window
   └──────────MCP── splunk_run_query ──► rows ──► answer on the job (with the SPL that ran) ──► soc-conclude
```

What `saia_generate_spl` is sent for one requirement
(`Backend/src/modules/enrichment/splunk-mcp.service.ts`, `promptFor`):

```
What else did 45.83.122.9 touch in the 24 hours around the alert.
Details from the alert:
- source: 45.83.122.9
- device: FGT-01
- type: event
- user_agent: FortiClient/7.2
Search index=main sourcetype=fortigate
Field names in this data: 45.83.122.9 is in srcip or dstip; FGT-01 is in devname. Use these field names.
Time range: earliest=1790834543 latest=1790924543
```

The question and the details are written by the `soc-requirements` agent, which
reads the alert, ThreatQ and the playbook; a detail is kept only if its value
appears in what the agent was shown. The index, sourcetype and field names come
from the data catalogue (`Backend/catalog/`), the window from the alert's time.

**Who is who.** The backend (`soc-core-worker`) is the **MCP client**: it makes both
calls. Splunk's MCP Server app is the **MCP server**: the tools live there, and
Text-to-SPL runs inside Splunk (Splunk AI Assistant for SPL), not on our side.
`saia_generate_spl` only *writes* the SPL and hands it back; it does not run it. Running
it is the second call, so the SPL passes through the backend in between — which is
where `spl-guard` reads it before asking Splunk to run it. Nothing sits between the
backend and Splunk in production.

The two tool names, their arguments and the `/services/mcp` path are the ones
**Splunk's own MCP Server app** publishes. This service is a stand-in shaped like
it, so the backend does not change between development and production — only
`SPLUNK_MCP_URL` and `SPLUNK_MCP_TOKEN` do.

| | Development | Production |
| --- | --- | --- |
| MCP server | this service, `SPLUNK_MODE=mock` | Splunk MCP Server app on the search head |
| `SPLUNK_MCP_URL` (Backend/.env) | `http://soc-mcp-splunk:8200/services/mcp` | `https://<search-head>:8089/services/mcp` |
| `SPLUNK_MCP_TOKEN` (Backend/.env) | blank — `MCP_AUTH_TOKEN` is used | the encrypted token from the MCP Server app |
| Text-to-SPL | a template filled with the IPs, hashes and `user=` values in the text | Splunk AI Assistant for SPL |
| Data | 22 fixed FortiGate-style events, timed relative to now | your indexes |

Every mock answer carries `mock: true`, and the backend writes **MOCK DATA** into
the answer an analyst reads. This service is not deployed to production at all.

---

## Production: connecting to Splunk

What the backend needs from Splunk, in the order it is usually set up. Everything
here is on the Splunk side or in `Backend/.env`; this repo is not in the
production path.

### 1. Apps on the search head

| Needs | Why |
| --- | --- |
| Splunk Enterprise or Splunk Cloud Platform, a version the app supports | The MCP Server app 2.0.0 (3 Sep 2026) lists platform versions 9.3 to 10.6 [1]. |
| **Splunk MCP Server** app ([Splunkbase 7931][1]) on the search head or search head cluster | Serves `/services/mcp` and `splunk_run_query`. It may need a restart [2]. |
| **Splunk AI Assistant for SPL** ([Splunkbase 7245][3]) | Without it the server has **no `saia_generate_spl`**, and every lookup fails with "Splunk's MCP server has no saia_generate_spl" [2][4]. |
| Token authentication enabled | The backend authenticates with a token, never a username and password [2]. |
| Splunk Cloud only: REST API access allowed | The MCP endpoint is on the management port [2]. Add the backend host's egress address to the `search-api` IP allow list (port 8089; closed by default, unlike the other features) [7]. |

**Splunk AI Assistant for SPL on Splunk Enterprise is cloud-connected** [5]:

- the search head needs outbound HTTPS (443) to `*.scs.splunk.com`, through a proxy if that is how the network works;
- onboarding is in the app: accept the terms, get a tenant code, then wait for an activation code by email — Splunk quotes **2–3 business days**;
- each prompt is processed in Splunk Cloud Platform ("only the necessary info required to answer each prompt"). **Our prompts carry alert details** — the requirement text names IPs, users and hosts from the alert. Get this approved by whoever owns data-handling decisions **before** turning stage 2 on.

### 2. Service account, role and token

Create a **service account** for the backend, not a person's account, with its own role:

- **Search-only.** Only the indexes the SOC flow may read (`srchIndexesAllowed`) [8], no write or admin capabilities. In particular **not** `delete_by_keyword` (`delete`), `run_collect` (`collect`), `run_mcollect` (`mcollect`, `meventcollect`), `run_dump` (`dump`), `run_sendalert` (`sendalert`), `output_file` (`outputcsv`, `outputlookup`) or `run_custom_command` [8][11]. Give it modest search quotas.
- **`mcp_tool_execute`** — lets the role use MCP tools [2].
- **Only two tools.** From MCP Server 1.3 the app's *Tools* tab maps roles to tools [2]. Give this role `saia_generate_spl` and `splunk_run_query` and nothing else: it needs no user lists, KV store or saved searches.

Then the token:

- Generate it in the **Splunk MCP Server app**. It is an **encrypted token** that only works for MCP, and it is **shown once** [6].
- To create a token for yourself you need `edit_tokens_own` + `mcp_tool_admin`; for another user (the service account), `edit_tokens_all` + `mcp_tool_admin` [6]. Those are for the admin who creates it — the service account itself needs only `mcp_tool_execute`.
- Set an expiry and put the date in the team calendar. An expired token fails every lookup with a 401 from `connect`, and the job page shows it.
- If it leaks: the app's settings page can **invalidate every MCP token** at once [6].

The token goes into Backend's CI variables as `SPLUNK_MCP_TOKEN` (masked, protected). Never commit it, and never put it in `MCP-Server/.env`.

### 3. Network and TLS

- **Route:** `soc-core-worker` → search head **TCP 8089**. The worker is the only container that calls Splunk; Splunk sees the Docker host's address.
- **DNS:** the name in `SPLUNK_MCP_URL` must resolve from inside the container.
- **Certificate:** unless the Splunk admin replaced them, 8089 serves the default certificates Splunk provides [9], which Node does not trust. Ask for the CA that signed the certificate on 8089, put it (PEM) in `Backend/certs/` and set `NODE_EXTRA_CA_CERTS=/certs/<file>.pem` in `Backend/.env` — it **extends** Node's built-in CA list rather than replacing it, and is read only when the process starts [10]. The name in `SPLUNK_MCP_URL` must be in the certificate's SAN.
- Do **not** use `NODE_TLS_REJECT_UNAUTHORIZED=0`. Splunk's docs mention it for testing a client [6]; on the backend it would turn verification off for ThreatQ and Confluence too.
- Splunk's own `mcp.conf` has `ssl_verify` (default `true`, recommended for production) [6]. Leave it on.

### 4. Backend settings

In `Backend/.env` (the deploy builds it from `.env.example` + CI variables):

| Variable | Production value | Notes |
| --- | --- | --- |
| `SPLUNK_MCP_URL` | `https://<search-head>:8089/services/mcp` | A bare `https://<search-head>:8089` gets `/services/mcp` added. |
| `SPLUNK_MCP_TOKEN` | the encrypted token | CI variable. When blank, `MCP_AUTH_TOKEN` (the mock's) is sent instead. |
| `SPLUNK_ALLOWED_INDEXES` | the same indexes as the role | Checked **before** a generated search is sent. A search that names no index is scoped to this list. Empty refuses every search; `*` opts out. |
| `SPLUNK_SEARCH_TIMEOUT` | `120` | Seconds per MCP call. Text-to-SPL can take tens of seconds; Splunk stops a search at 1 minute anyway [4]. |
| `SPLUNK_MAX_COUNT` | `200` | Rows kept per requirement. Splunk returns at most 1000 events [4]. |
| `SPLUNK_LOOKUP_MODE` | `manual` | `manual`: an analyst presses the button. `auto`: every alert. `off`: no stage 2. |
| `SPLUNK_MCP_GENERATE_ARG` | blank | The argument `saia_generate_spl` takes the text in. Splunk does not document its name, so the backend reads it from the tool's schema; set it only if that fails. |
| `SPLUNK_MCP_GENERATE_TOOL` / `SPLUNK_MCP_QUERY_TOOL` | blank (defaults) | Only if Splunk renames the tools. |
| `NODE_EXTRA_CA_CERTS` | `/certs/<ca>.pem` | See 3. |

`MCP_AUTH_TOKEN` is not used in production.

**The data catalogue** (which index, sourcetype and fields each requirement should
look at) is refreshed by the manual `export_catalog` job in Backend's CI. It calls
Splunk's REST API rather than MCP, so it needs two more CI variables in the Backend
project: `SPLUNK_URL` (`https://<search-head>:8089`) and `SPLUNK_TOKEN` — an
*ordinary* Splunk token for the same service account, because the encrypted MCP
token works only for MCP [6]. See `Backend/docs/splunk-catalog.md`.

### 5. Check it

From the container that will make the calls, with its real settings:

```bash
docker exec soc-core-worker node dist/scripts/splunk-mcp-check.js
```

```
endpoint       https://splunk.corp.example:8089/services/mcp
token          set (… chars)
tools          saia_generate_spl, splunk_run_query
allowlist      fortigate, notable
extra CA       /certs/company-ca.pem
connected      yes — both tools found; Text-to-SPL takes the request in "<arg>"
```

Then one real requirement, through exactly the path a lookup takes (generate → check → run). Read-only:

```bash
docker exec soc-core-worker node dist/scripts/splunk-mcp-check.js "Failed VPN logins in the last hour"
```

| It says | Usually |
| --- | --- |
| `cannot connect … fetch failed` / `ECONNREFUSED` / `ETIMEDOUT` | route, firewall, DNS, or the Splunk Cloud allow list |
| `self-signed certificate` / `unable to verify the first certificate` | `NODE_EXTRA_CA_CERTS` missing or the wrong CA |
| `cannot connect … 401` | wrong or expired token, or a token not created in the MCP Server app |
| `has no saia_generate_spl` | Splunk AI Assistant for SPL not installed or not activated, or the role is not mapped to the tool |
| `returned no SPL` | Text-to-SPL answered in a shape the backend does not read — see 6 |
| `the generated SPL reads index '…'` | the generated search left `SPLUNK_ALLOWED_INDEXES`; it was refused before it ran |

### 6. Watch the first runs

- **What Text-to-SPL returns is not documented.** The backend takes the SPL from a `spl`, `query` or `search` field, a fenced code block, or the first line that starts with `search`, `index=` or `|`. If the real answer is shaped differently, lookups fail with "returned no SPL", and `splOf()` in `Backend/src/modules/enrichment/splunk-mcp.service.ts` is the one place to adjust.
- **Field names are chosen by Splunk now.** A generated search can use a CIM name that your raw logs do not have, and come back empty — which reads as "nothing happened". Every answer stores the SPL that ran and the prompt that produced it; the evidence page shows both. Check them on the first alerts.
- **Splunk's guardrails apply on top of ours** [4]: unsafe or destructive commands are not run, a search stops at 1 minute, and at most 1000 events come back.
- `splunk_run_query` takes no time range, so the backend writes the alert's window into the SPL as epoch `earliest=`/`latest=` when Text-to-SPL leaves it out.

### Sources

[1]: https://splunkbase.splunk.com/app/7931
[2]: https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.3/set-up-the-splunk-mcp-server
[3]: https://splunkbase.splunk.com/app/7245
[4]: https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/2.0/mcp-server-tools
[5]: https://www.splunk.com/en_us/blog/artificial-intelligence/introducing-splunk-ai-assistant-for-spl-through-a-cloud-connected-solution-on-prem-ai-without-the-gpu-hassle.html
[6]: https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.1/connecting-to-the-mcp-server-and-settings
[7]: https://help.splunk.com/en/splunk-cloud-platform/administer/admin-config-service-manual/10.5.2605/administer-splunk-cloud-platform-using-the-admin-config-service-acs-api/configure-ip-allowlists-for-splunk-cloud-platform
[8]: https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authorize.conf
[9]: https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.1/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificates-for-inter-splunk-communication
[10]: https://nodejs.org/api/cli.html#node_extra_ca_certsfile
[11]: https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.2/best-practices-for-splunk-platform-security/spl-safeguards-for-risky-commands

1. [Splunk MCP Server — Splunkbase](https://splunkbase.splunk.com/app/7931)
2. [Set up the Splunk MCP Server (1.3)](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.3/set-up-the-splunk-mcp-server)
3. [Splunk AI Assistant for SPL — Splunkbase](https://splunkbase.splunk.com/app/7245)
4. [MCP Server tools (2.0)](https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/2.0/mcp-server-tools)
5. [Splunk AI Assistant for SPL through a cloud-connected solution (Splunk blog)](https://www.splunk.com/en_us/blog/artificial-intelligence/introducing-splunk-ai-assistant-for-spl-through-a-cloud-connected-solution-on-prem-ai-without-the-gpu-hassle.html)
6. [Connecting to the MCP Server and settings (1.1)](https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.1/connecting-to-the-mcp-server-and-settings)
7. [Configure IP allowlists for Splunk Cloud Platform (ACS)](https://help.splunk.com/en/splunk-cloud-platform/administer/admin-config-service-manual/10.5.2605/administer-splunk-cloud-platform-using-the-admin-config-service-acs-api/configure-ip-allowlists-for-splunk-cloud-platform)
8. [authorize.conf — roles and capabilities (10.4)](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authorize.conf)
9. [Configure TLS certificates for inter-Splunk communication (9.1)](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.1/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificates-for-inter-splunk-communication)
10. [Node.js — `NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#node_extra_ca_certsfile)
11. [SPL safeguards for risky commands (9.2)](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.2/best-practices-for-splunk-platform-security/spl-safeguards-for-risky-commands)

Read in October 2026. The app moves quickly, so check these pages against the version you install.

---

## Development: the mock

```bash
cp ../.env.example ../.env     # SPLUNK_MODE=mock; set MCP_AUTH_TOKEN = Backend/.env's
docker compose up -d --build soc-mcp-splunk
```

In `Backend/.env`: `SPLUNK_MCP_URL=http://soc-mcp-splunk:8200/services/mcp`, the same
`MCP_AUTH_TOKEN`, `SPLUNK_ALLOWED_INDEXES=main`, and `SPLUNK_LOOKUP_MODE=manual` or `auto`.
`docker exec soc-core-worker node dist/scripts/splunk-mcp-check.js "Which destinations did 10.1.100.11 talk to"` runs one through.

The events (`index=main sourcetype=fortigate`, all inside the last two hours):

- `45.83.122.9` failing SSL-VPN logins as `j.smith` and `admin`, then a tunnel up;
- `10.1.100.11` (user `j.smith`) then talking to `23.59.154.35`, `44.215.36.185` on 443/8443, Tor on `185.220.101.4:9001` (blocked), and SMB to `10.1.100.20-22`;
- background DNS and HTTPS from `10.1.100.44` and `10.1.100.52`.

`saia_generate_spl` fills a template: `search index=… [sourcetype=…] ("value" OR …) earliest=… latest=…`,
then `| stats count by srcip, dstip, dstport, action` when the text asks how many / top /
destinations, otherwise `| table _time, srcip, dstip, dstport, user, action, msg`.
`index=`, `sourcetype=`, `earliest=` and `latest=` in the text are taken as hints.
`splunk_run_query` understands `index=`, `sourcetype=`, quoted values, `| table`/`fields`,
`| stats count by`, `| sort` and `| head`. It is a stand-in, not Splunk.

## Modes

| `SPLUNK_MODE` | `saia_generate_spl` | `splunk_run_query` | Needs |
| --- | --- | --- | --- |
| `mock` | the template above | the fixed events | `MCP_AUTH_TOKEN` |
| `live` (the default) | refuses: in production Text-to-SPL is Splunk's own | runs against `SPLUNK_BASE_URL` | `MCP_AUTH_TOKEN`, `SPLUNK_TOKEN`, `SPLUNK_ALLOWED_INDEXES` |

Live mode is for `/catalog`, `/check-connection` and `/query` against a real Splunk;
stage 2 itself needs Text-to-SPL, which only Splunk's own MCP server has. The
default is `live` so that a forgotten setting can never serve made-up events.

## What a search may do

Both tools and `/query` refuse before anything reaches Splunk:

- **`splunk_run_query`** (`spl.check_readonly`): a denylist, because generated SPL uses the
  whole read-only language. It is Splunk's own list of risky commands — `collect`, `delete`,
  `dump`, `map`, `mcollect`, `meventcollect`, `outputcsv`, `outputlookup`, `run`,
  `runshellscript`, `script`, `sendalert`, `sendemail`, `tscollect` [11] — plus `summaryindex`,
  `outputtext`, `rest`, `crawl`, `dbxquery` and `dbxoutput`, **in subsearches too**. No
  macros (what they expand to cannot be checked), balanced quotes, at most 4000 characters,
  and every `index=` inside `SPLUNK_ALLOWED_INDEXES` unless it is `*`.
  Splunk's own safeguard for these commands is a warning dialog in Splunk Web, and not even
  for ad hoc searches [11]; a search sent over the API gets no such check, which is why
  this one exists.
- **`POST /query`** (`spl.check_query`): the stricter allowlist from before — `search`,
  `tstats`, `makeresults`, `bin`, `stats`, `sort`, `head`, quoted `index="name"` only, no
  subsearches.

The backend runs the same denylist on the generated SPL **before** sending it
(`Backend/src/modules/enrichment/spl-guard.ts`; `tests/test_splunk_mcp.py` fails if the two
lists differ), and Splunk's own guardrails run after [4].
None of these is the real control: **the token's role must be unable to write or read
other indexes regardless.**

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /services/mcp` | backend | MCP (streamable HTTP, stateless, JSON responses). Tools `saia_generate_spl`, `splunk_run_query`. |
| `POST /query` | an operator | Run one SPL search and return Splunk's rows (live mode). |
| `GET /catalog` | an operator | Indexes, sourcetypes and fields this token can see. |
| `GET /check-connection` | CI, an operator | Whether Splunk can be used, and where it stops if not. |
| `GET /health` | container healthcheck | No token needed. |

Every route but `/health` needs `Authorization: Bearer $MCP_AUTH_TOKEN`. The MCP
endpoint also checks the `Host` header against `MCP_ALLOWED_HOSTS` (DNS-rebinding
defence) and answers 421 to anything else.

```bash
POST /query  {"spl": "search index=\"main\" srcip=\"10.1.100.11\" | head 20",
              "earliest": "-24h", "latest": "now", "count": 20}
-> {"results": [...], "count": 20, "earliest": "-24h", "latest": "now", "limit": 20}
```

## Files

| File | Role |
| --- | --- |
| `server.py` | The MCP server, its two tools, and the plain routes. |
| `mock.py` | The mock estate, the Text-to-SPL template and the tiny search engine behind mock mode. |
| `spl.py` | `check_readonly` (MCP) and `check_query` (`/query`); the quoting the catalogue route uses. |
| `splunk_api.py` | HTTP client for the Splunk REST API, and the connection check. |
| `check_connection.py` | Calls `/check-connection` from inside the container; exit 0 or 1, so CI can branch on it. |
| `auth.py` | Bearer-token middleware in front of every route but `/health`. |
| `config.py` | Env to typed settings, plus the startup preconditions. |

The backend side of the same flow:

| File | Role |
| --- | --- |
| `Backend/src/modules/enrichment/splunk-mcp.service.ts` | The MCP client: connects, finds the two tools, builds the prompt, then generate → check → run. |
| `Backend/src/modules/enrichment/spl-guard.ts` | The check between the two calls, and the alert's window when the SPL has none. |
| `Backend/src/modules/queue/lookup.processor.ts` | Stage 2: one MCP session per lookup, one stored answer per requirement. |
| `Backend/src/scripts/splunk-mcp-check.ts` | The check in "5. Check it". |
| `Backend/src/config/configuration.ts` (`splunk`) | The settings in "4. Backend settings". |

The data catalogue and the lookup plans live in the Backend repo (`Backend/catalog/`,
built into its image), with the scripts and the `export_catalog` CI job that refresh
them from Splunk — see `Backend/docs/splunk-catalog.md`. Stage 1 uses them to say
where a requirement should look (index, sourcetype), which reaches Text-to-SPL as a
hint.

## Configuration

Set in `../.env` (`../.env.local.example` is a skeleton).

| Variable | Default | Notes |
| --- | --- | --- |
| `SPLUNK_MODE` | `live` | `mock` or `live`; anything else refuses to start. `.env.example` sets `mock`. |
| `MCP_AUTH_TOKEN` | — **required** | Bearer token the backend presents. Same value in `Backend/.env`. |
| `MCP_ALLOWED_HOSTS` | `soc-mcp-splunk:8200,localhost:8200,127.0.0.1:8200` | Host headers the MCP endpoint accepts. |
| `SPLUNK_TOKEN` | — **required in live** | Splunk auth token for a search-only role. |
| `SPLUNK_ALLOWED_INDEXES` | — **required in live** | Comma-separated allowlist, or `*` to opt out on purpose. Same list as `Backend/.env`. |
| `SPLUNK_BASE_URL` | — | Management port (8089), not the web UI on 8000. |
| `SPLUNK_VERIFY_SSL` | `true` | `false` only for a self-signed lab cert. |
| `SPLUNK_TIMEOUT` | `60` | Seconds per search. |
| `SPLUNK_MAX_COUNT` | `200` | Hard ceiling on rows, whatever the caller asks for. |
| `MCP_PORT` | `8200` | Internal only — the service publishes no port. |

Generate the token with `openssl rand -hex 32`.

## Commands

```bash
docker compose up -d --build soc-mcp-splunk
docker compose logs -f soc-mcp-splunk
```

### Check it is connected (live mode)

```bash
docker compose exec -T soc-mcp-splunk python check_connection.py
```

```json
{"connected":true,"base_url":"https://splunk.example.com:8089","latency_ms":140,"splunk_version":"9.2.1"}
```

| `failed_at` | Meant | Usually |
| --- | --- | --- |
| `reach` | nothing answered, or what answered is not Splunk's management API | wrong `SPLUNK_BASE_URL` (8089, not 8000), DNS, a firewall, a certificate the container does not trust |
| `auth` | `SPLUNK_TOKEN` was refused (401/403) | wrong or expired token |
| `search` | authenticated, but a search could not be run | the role lacks the `search` capability, or Splunk is overloaded |

The search is a fixed `| makeresults`; when `SPLUNK_ALLOWED_INDEXES` is a list the answer
also says which of those indexes showed events in the last 30 days (advice, never a
failure — an unreadable index and a quiet one look the same from here).
