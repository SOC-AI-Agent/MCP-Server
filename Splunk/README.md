# soc-mcp-splunk

A development stand-in for **Splunk's own MCP Server app**: the same two tools
(`saia_generate_spl` for Text-to-SPL, `splunk_run_query`) at the same path
(`/services/mcp`), so the backend does not change between development and a real
Splunk — only `SPLUNK_MCP_URL` and `SPLUNK_MCP_TOKEN` in `Backend/.env` do. In
`SPLUNK_MODE=mock` it answers both from a fixed set of events.

The backend (`soc-core-worker`) is the MCP client. How it connects to a real
Splunk — the flow, what Text-to-SPL is sent, the apps to install, the service
account and token, network and certificate, its settings and the check — is in
**[Backend/docs/splunk-mcp.md](../../Backend/docs/splunk-mcp.md)**.

Every mock answer carries `mock: true`, and the backend writes **MOCK DATA** into
the answer an analyst reads. This service is not deployed to production at all.

---

## Development: the mock

```bash
cp ../.env.example ../.env     # SPLUNK_MODE=mock; set MCP_AUTH_TOKEN = Backend/.env's
docker compose up -d --build soc-mcp-splunk
```

In `Backend/.env`: `SPLUNK_MCP_URL=http://soc-mcp-splunk:8200/services/mcp`, the same
`MCP_AUTH_TOKEN`, and `SPLUNK_LOOKUP_MODE=manual` or `auto`.
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
  whole read-only language. It is [Splunk's own list of risky commands][risky] — `collect`, `delete`,
  `dump`, `map`, `mcollect`, `meventcollect`, `outputcsv`, `outputlookup`, `run`,
  `runshellscript`, `script`, `sendalert`, `sendemail`, `tscollect` — plus `summaryindex`,
  `outputtext`, `rest`, `crawl`, `dbxquery` and `dbxoutput`, **in subsearches too**. No
  macros (what they expand to cannot be checked), balanced quotes, at most 4000 characters,
  and every `index=` inside `SPLUNK_ALLOWED_INDEXES` unless it is `*`.
  Splunk's own safeguard for these commands is a warning dialog in Splunk Web, and not even
  for ad hoc searches; a search sent over the API gets no such check, which is why
  this one exists.
- **`POST /query`** (`spl.check_query`): the stricter allowlist from before — `search`,
  `tstats`, `makeresults`, `bin`, `stats`, `sort`, `head`, quoted `index="name"` only, no
  subsearches.

The backend runs the same denylist on the generated SPL **before** sending it
(`Backend/src/modules/enrichment/spl-guard.ts`; `tests/test_splunk_mcp.py` fails if the two
lists differ), and [Splunk's own guardrails][guardrails] run after.
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

The backend side of the same flow (the MCP client, `spl-guard.ts`, the check script and
its settings) is listed in [Backend/docs/splunk-mcp.md](../../Backend/docs/splunk-mcp.md).

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
| `SPLUNK_ALLOWED_INDEXES` | — **required in live** | Comma-separated allowlist, or `*` to opt out on purpose. The connector's own; the backend has no allowlist. |
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

[risky]: https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.2/best-practices-for-splunk-platform-security/spl-safeguards-for-risky-commands
[guardrails]: https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/2.0/mcp-server-tools
