# soc-mcp-splunk

A small HTTP API the backend runs its Splunk searches through. Standalone container, no
database, no job state, not reachable from outside `soc-network`. Splunk itself runs
outside this Docker network, on the company network, and is reached at `SPLUNK_BASE_URL`.

**The backend writes the SPL; this checks it and runs it.** The search is planned there —
which indicator, which fields carry it in this estate, which index and sourcetype, from the
data catalogue — and built by `Backend/src/modules/enrichment/spl.ts` (quoting, field and
index checks, the day and row limits). This service does not build a search from parameters
and does not trust the one it is sent: `spl.check_query` refuses anything that is not a
read-only search over an allowed index, whoever wrote it.

There is **no MCP layer and no model** in this service. The name is from when it published
these searches as MCP tools for an agent to call.

```
soc-core-worker --POST /query {spl, earliest, latest, count}--> soc-mcp-splunk --Splunk REST--> Splunk
                     Bearer MCP_AUTH_TOKEN                      (check_query, then run)
```

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /query` | backend | Run one SPL search and return Splunk's rows as they came. |
| `GET /catalog` | an operator | Indexes, sourcetypes and fields this token can see. See below. |
| `GET /check-connection` | CI, an operator | Whether Splunk can be used, and where it stops if not. See below. |
| `GET /health` | container healthcheck | No token needed. |

```bash
POST /query  {"spl": "search index=\"main\" srcip=\"10.1.100.11\" | head 20",
              "earliest": "-24h", "latest": "now", "count": 20}
-> {"results": [...], "count": 20, "earliest": "-24h", "latest": "now", "limit": 20}
```

`earliest` and `latest` default to `-24h` and `now`; `count` defaults to 20 and is capped at
`SPLUNK_MAX_COUNT`. Rows are not trimmed or interpreted: that is the caller's job.

Errors say whose they are: **400** is the request (the `error` names what was refused),
**502** is Splunk (its own reason: unreachable, token refused, search denied), **401** is a
missing or wrong bearer token.

## What `/query` will run

Only a read-only search over an allowed index. Everything else is a 400 and never reaches Splunk.

- **Commands:** `search`, `tstats`, `makeresults`, `bin`, `stats`, `sort`, `head` — an allowlist,
  because the list of SPL commands that write or reach out (`delete`, `collect`, `outputlookup`,
  `sendemail`, `script`, `rest`, ...) is long and grows, and the list a read-only search needs is short.
  The query starts with `search` or a `|` command.
- **No subsearches (`[ ]`) and no macros (`` ` ``),** which can hide a second search.
- **Indexes:** every `index=` must be written `index="name"`, quoted and exact, and be in
  `SPLUNK_ALLOWED_INDEXES`. A search that reads data must name one. `index=*`, `index=main`,
  `index IN (...)` and `index!=` are refused, because those are the forms that slip a name past
  the list. (`SPLUNK_ALLOWED_INDEXES=*` turns the index check off; the command check stays.)
- Quoted values are set aside before any of this is looked at, so `action="blocked\" | delete"` —
  a value that tried to close its quote, safely inside its quotes as the backend writes it — is a
  value, and a real `| delete` outside quotes is not missed.
- No newlines or null bytes, at most 4000 characters, balanced quotes, a valid time window.

This is the **second** place these rules are enforced. The first is `spl.ts` in the backend, which
builds the query. Two checks on one rule set: a bug in one, or a caller that is not the backend,
should not be enough to run `| delete`. Neither is the only control — **the Splunk token must
belong to a role that cannot write regardless**: search-only, the target indexes and no others,
with `delete_by_keyword` and `run_script` removed. Use a token, never a username and password.

## Files

| File | Role |
| --- | --- |
| `server.py` | The routes and the Starlette app. |
| `spl.py` | `check_query`, the second check on every search; and the quoting the catalogue route uses. |
| `splunk_api.py` | HTTP client for the Splunk REST API, and the connection check. |
| `check_connection.py` | Calls `/check-connection` from inside the container; exit 0 or 1, so CI can branch on it. |
| `auth.py` | Bearer-token middleware in front of every route but `/health`. |
| `config.py` | Env to typed settings, plus the startup preconditions. |

`catalog/` holds the data catalogue and lookup plans. **The backend reads them, not
this service** — `soc-core-api` mounts the directory read-only. They stay here
because the scripts that produce them do (`../scripts`, `../docs/splunk-catalog.md`).

## `/catalog` — what this token can actually see

```bash
curl -s "http://soc-mcp-splunk:8200/catalog" -H "Authorization: Bearer $MCP_AUTH_TOKEN"
```

Indexes, sourcetypes and field names, with `?values=true` for example values,
`?index=`, `?sample=` and `?max_sourcetypes=`. An operator pulls it once and a person
writes the data catalogue from it; the backend then plans from that file.

Example values are omitted unless asked for — they are real data — the allowlist is
respected, and every call is logged with whether values were requested.

See [`../docs/splunk-catalog.md`](../docs/splunk-catalog.md).

## Configuration

Set in `.env` (`../.env.local.example` is a skeleton). The three with no default make
the container refuse to start if unset, rather than quietly serving an open proxy
into Splunk.

| Variable | Default | Notes |
| --- | --- | --- |
| `MCP_AUTH_TOKEN` | — **required** | Bearer token the backend must present. The `MCP_` prefix is the name it had as an MCP server; kept so the token keeps its name everywhere. |
| `SPLUNK_TOKEN` | — **required** | Splunk auth token for a search-only role. |
| `SPLUNK_ALLOWED_INDEXES` | — **required** | Comma-separated allowlist, or `*` to opt out on purpose. Set the same list in `Backend/.env`: it builds the searches, this checks them. |
| `SPLUNK_BASE_URL` | — | Management port, not the web UI on 8000. |
| `SPLUNK_VERIFY_SSL` | `true` | Set `false` only for a self-signed lab cert. |
| `SPLUNK_TIMEOUT` | `60` | Seconds per search. |
| `SPLUNK_MAX_COUNT` | `200` | Hard ceiling on rows, whatever the caller asks for. |
| `MCP_PORT` | `8200` | Internal only — the service publishes no port. |

Generate the token with `openssl rand -hex 32`.

**Removed:** `/search`, `/summarise` and `/frequency` (the backend builds those searches now — they were parameters in, SPL out), `SPLUNK_ALERT_INDEX` and `SPLUNK_ALERT_NAME_FIELD` (the backend's settings now), and with the MCP layer: the six MCP tools (`list_indexes`, `describe_sourcetype`,
`search_events`, `summarise_events`, `alert_frequency`, `related_events`), the `/mcp`
endpoint, `MCP_ALLOWED_HOSTS` (it only guarded that endpoint) and `SPLUNK_CATALOG_FILE`
(it described the tools to a model; the backend has its own setting of that name). An
old `.env` that still holds them is harmless.

## Commands

```bash
docker compose up -d --build soc-mcp-splunk
docker compose logs -f soc-mcp-splunk
docker compose exec soc-mcp-splunk python -c \
  "import urllib.request,json; print(urllib.request.urlopen('http://localhost:8200/health').read())"
```

### Check it is connected

```bash
docker compose exec -T soc-mcp-splunk python check_connection.py
```

```json
{"connected":true,"base_url":"https://splunk.example.com:8089","latency_ms":140,"splunk_version":"9.2.1"}
```

It checks three things in order and says which one failed:

| `failed_at` | Meant | Usually |
| --- | --- | --- |
| `reach` | nothing answered, or what answered is not Splunk's management API | wrong `SPLUNK_BASE_URL` — the management port is `8089`, not the web UI on `8000` — or DNS, a firewall, a certificate the container does not trust (`SPLUNK_VERIFY_SSL`) |
| `auth` | `SPLUNK_TOKEN` was refused (401/403) | wrong or expired token |
| `search` | authenticated, but a search could not be run | the token's role lacks the `search` capability, or Splunk is overloaded |

```json
{"connected":false,"base_url":"https://splunk.example.com:8089","latency_ms":95,"failed_at":"auth","error":"Splunk rejected SPLUNK_TOKEN (401)"}
```

The script calls `GET /check-connection` with the connector's own token, read
from the container's environment so it is never on a command line. The route
answers `200` when connected and `502` when not, and sits behind the bearer
token unlike `/health`: each call goes out to Splunk and runs a search.

The search is a fixed `| makeresults` — it needs the same capability as a real
one, reads no index and returns one synthetic row. A pass means the token can
search. The deploy job runs this after the containers are up, and fails the
pipeline if it exits 1.

**Indexes.** When `SPLUNK_ALLOWED_INDEXES` is a list, the answer also says which
of them showed events in the last 30 days (a `| tstats count … by index`, built
from the allowlist through `spl.py`):

```json
{"connected":true, … "indexes":{"with_events":["notable"],"no_events_in_30d":["network"]},
 "warning":"no events seen in the last 30 days in network: the token may not be able to read them, or they are quiet. …"}
```

This is advice, never a failure. A search over an index the token cannot read
returns nothing rather than an error, so a quiet index and an unreadable one look
the same from here: the ones listed in `with_events` are certainly readable, and
for the others `GET /catalog` shows what the token can really see. It is skipped
when the allowlist is `*`.

Run a search by hand, from inside the network:

```bash
docker run --rm --network soc-network curlimages/curl -s -X POST \
  http://soc-mcp-splunk:8200/query \
  -H "Authorization: Bearer $MCP_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"spl":"search index=\"fortigate\" (srcip=\"10.1.100.11\" OR dstip=\"10.1.100.11\") | head 20"}'
```

Every result carries the SPL that produced it, which is the fastest way to spot a
wrong field name. [`../../Backend/docs/testing.md`](../../Backend/docs/testing.md)
works through a bad answer layer by layer.

## Field names are environment-specific

Which field carries which meaning is decided by the data catalogue the **backend** reads, not
by this service: it puts the right fields (`srcip`, not `src_ip`) into the SPL it writes. That
is what stops an empty answer being a wrong field name that reads as "nothing happened". The
alert index and the field holding an alert's name (`SPLUNK_ALERT_INDEX`,
`SPLUNK_ALERT_NAME_FIELD`, for the "how often has this fired" search) are the backend's settings
too, and assume Splunk ES by default.
