# soc-mcp-splunk

Splunk for the backend, over MCP. The backend (`soc-core-worker`) is the MCP client
and calls two tools here:

| Tool | Does |
| --- | --- |
| `splunk_lookup(question)` | One requirement, start to finish: the prompt, Text-to-SPL, the read-only check, the search, the rows trimmed for a small model, and the answer as text. |
| `splunk_text_to_spl(question)` | The first half: the SPL that would run, or why it would not. Nothing is searched. |

`question` is what stage 1 stored for the requirement: `requirement`, and optionally
`index`, `sourcetype`, `alertIndex`, `alertSourcetype`, `context`, `fieldHints`,
`indicator`, `fields`, `filters`, `summarise`, `frequencyOf`, `earliest`, `latest`.
A requirement that cannot be answered is not a tool error: the result has `error`
and the `prompt` that was built, so the backend keeps it beside the ones that worked.

```
question ─► lookup.build_prompt ─► Text-to-SPL ─► lookup.with_time_window ─► spl.check_readonly
                                   (template, or                                    │
                                    Splunk AI Assistant)        mock.run_query  or  Splunk REST
                                                                                    │
            prompt, spl, rows, count, capped, limit, mock, answer ◄─ lookup.trim_row / render
```

This used to be the backend's own code (`splunk-mcp.service.ts`, `spl-guard.ts`),
calling this service twice per requirement. Under the two tools are the ones
Splunk's own MCP Server app publishes, by the same names at the same path
(`/services/mcp`): `saia_generate_spl` and `splunk_run_query`.

Every mock answer carries `mock: true` and says **MOCK DATA** in the text an analyst
reads.

---

## Development: the mock

```bash
cp ../.env.example ../.env     # SPLUNK_MODE=mock; set MCP_AUTH_TOKEN = Backend/.env's
docker compose up -d --build soc-mcp-splunk
```

In `Backend/.env`: `SPLUNK_MCP_URL=http://soc-mcp-splunk:8200/services/mcp`, the same
`MCP_AUTH_TOKEN`, and `SPLUNK_LOOKUP_MODE=manual` or `auto`.
`docker exec soc-core-worker node dist/scripts/splunk-mcp-check.js "Which destinations did 10.1.100.11 talk to"` runs one through.

The same events can be put in a real Splunk: the container in
[`../external/splunk`](../external/splunk/README.md), searched in live mode.

The events (`index=main sourcetype=fortigate`, all inside the last two hours):

- `45.83.122.9` failing SSL-VPN logins as `j.smith` and `admin`, then a tunnel up;
- `10.1.100.11` (user `j.smith`) then talking to `23.59.154.35`, `44.215.36.185` on 443/8443, Tor on `185.220.101.4:9001` (blocked), and SMB to `10.1.100.20-22`;
- background DNS and HTTPS from `10.1.100.44` and `10.1.100.52`.

Text-to-SPL in mock mode fills a template (`text_to_spl.py`): `search index=… [sourcetype=…] ("value" OR …) earliest=… latest=…`,
then `| stats count by srcip, dstip, dstport, action` when the text asks how many / top /
destinations, otherwise `| table _time, srcip, dstip, dstport, user, action, msg`.
`index=`, `sourcetype=`, `earliest=` and `latest=` in the text are taken as hints.
`splunk_run_query` understands `index=`, `sourcetype=`, quoted values, `| table`/`fields`,
`| stats count by`, `| sort` and `| head`. It is a stand-in, not Splunk.

## Modes

| `SPLUNK_MODE` | Text-to-SPL | Searches run on | Needs |
| --- | --- | --- | --- |
| `mock` | the template above | the fixed events | `MCP_AUTH_TOKEN` |
| `live` (the default) | the template, without the mock's columns | `SPLUNK_BASE_URL` | `MCP_AUTH_TOKEN`, `SPLUNK_TOKEN`, `SPLUNK_ALLOWED_INDEXES` |
| `live` + `SPLUNK_SAIA_MCP_URL` | Splunk AI Assistant for SPL, through Splunk's own MCP server (`saia.py`) | `SPLUNK_BASE_URL` | the above, and a Splunk with the MCP Server and AI Assistant apps |

The default is `live` so that a forgotten setting can never serve made-up events.

The live template assumes nothing about the data: the index, sourcetype and window
are the ones the request names, the values found in it are search terms, and a
count groups by the field names the request gives (`… is in srcip or dstip`). It
ends `| head 50 | fields *` because searches run in fast mode, which extracts only
the fields a search names. It is enough for a Splunk without the assistant, and it
is not the assistant: with `SPLUNK_SAIA_MCP_URL` set the prompt — which carries
values from the alert — goes to Splunk AI Assistant, which processes it in Splunk
Cloud. What the assistant writes is checked and run here like any other SPL.

## What a search may do

Every tool and `/query` refuse before anything reaches Splunk:

- **`splunk_lookup`, `splunk_text_to_spl`, `splunk_run_query`** (`spl.check_readonly`): a denylist, because generated SPL uses the
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

This is the only check on our side now — the backend no longer has one of its own —
and [Splunk's own guardrails][guardrails] run after when the search goes through
Splunk's MCP server.
None of these is the real control: **the token's role must be unable to write or read
other indexes regardless.**

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /services/mcp` | backend | MCP (streamable HTTP, stateless, JSON responses). Tools `splunk_lookup`, `splunk_text_to_spl`; and `saia_generate_spl`, `splunk_run_query`. |
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
| `server.py` | The MCP server, its tools, and the plain routes. |
| `lookup.py` | One requirement: the question's shape, the prompt, the SPL in what Text-to-SPL answered, the time window, trimming and rendering the rows. |
| `text_to_spl.py` | Text-to-SPL as a template, for mock mode and for a Splunk without the assistant. |
| `saia.py` | Text-to-SPL forwarded to Splunk AI Assistant through Splunk's own MCP server (`SPLUNK_SAIA_MCP_URL`). |
| `mock.py` | The mock estate and the tiny search engine behind mock mode. |
| `spl.py` | `check_readonly` (MCP) and `check_query` (`/query`); the quoting the catalogue route uses. |
| `splunk_api.py` | HTTP client for the Splunk REST API, and the connection check. |
| `check_connection.py` | Calls `/check-connection` from inside the container; exit 0 or 1, so CI can branch on it. |
| `auth.py` | Bearer-token middleware in front of every route but `/health`. |
| `config.py` | Env to typed settings, plus the startup preconditions. |

The backend side of the same flow (the MCP client, the check script and its
settings) is listed in [Backend/docs/splunk-mcp.md](../../Backend/docs/splunk-mcp.md).

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
| `SPLUNK_BASE_URL` | — | Management port (8089), not the web UI on 8000. `https://soc-splunk:8089` for the container. |
| `SPLUNK_VERIFY_SSL` | `true` | `false` only for a self-signed lab cert. |
| `SPLUNK_TIMEOUT` | `60` | Seconds per search. |
| `SPLUNK_MAX_COUNT` | `200` | Hard ceiling on rows, whatever the caller asks for. |
| `SPLUNK_ALERT_INDEX`, `SPLUNK_ALERT_NAME_FIELD` | `notable`, `search_name` | Where fired alerts are and the field with their name, for "how often has this alert fired". Splunk ES defaults. |
| `SPLUNK_SAIA_MCP_URL` | — | Splunk's own MCP server, `https://<splunk>:8089/services/mcp`. Set: Text-to-SPL is Splunk AI Assistant. Blank: the template. Ignored in mock. |
| `SPLUNK_SAIA_MCP_TOKEN` | — | The token for it (audience `mcp`). Blank: `SPLUNK_TOKEN`. |
| `SPLUNK_SAIA_TOOL`, `SPLUNK_SAIA_ARG` | `saia_generate_spl`, read from the schema | Only if Splunk renames them. |
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
