# soc-mcp-splunk

A small HTTP API in front of Splunk, for the backend. Standalone container, no
database, no job state, not reachable from outside `soc-network`. Splunk itself runs
outside this Docker network, on the company network, and is reached at
`SPLUNK_BASE_URL`.

There is **no MCP layer and no model** in this service. The name is from when it
published these searches as MCP tools for an agent to call; the backend now plans
every search itself (which index, which sourcetype, which fields carry the
indicator, from the data catalogue) and this runs it.

```
soc-core-worker --POST /search | /summarise | /frequency--> soc-mcp-splunk --Splunk REST--> Splunk
                     Bearer MCP_AUTH_TOKEN
```

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /search` | backend | One indicator across the fields that carry it, in one index and sourcetype. |
| `POST /summarise` | backend | Group and count instead of listing: distinct destinations, hits per hour, blocked against allowed. |
| `POST /frequency` | backend | How often an alert fired over the last N days (1-90) — routine noise or first sighting. |
| `GET /catalog` | an operator | Indexes, sourcetypes and fields this token can see. See below. |
| `GET /check-connection` | CI, an operator | Whether Splunk can be used, and where it stops if not. See below. |
| `GET /health` | container healthcheck | No token needed. |

Every result carries the `spl` that produced it, so a surprising answer can be
re-run by hand in Splunk.

Errors say whose they are: **400** is the request (a value the service will not put
into a search — the `error` names it), **502** is Splunk (the `error` carries its own
reason: unreachable, token refused, search denied), **401** is a missing or wrong
bearer token.

## Files

| File | Role |
| --- | --- |
| `server.py` | The routes and the Starlette app. |
| `spl.py` | Builds and validates every search string. The safety boundary. |
| `splunk_api.py` | HTTP client for the Splunk REST API, and the connection check. |
| `check_connection.py` | Calls `/check-connection` from inside the container; exit 0 or 1, so CI can branch on it. |
| `auth.py` | Bearer-token middleware in front of every route but `/health`. |
| `config.py` | Env to typed settings, plus the startup preconditions. |

`catalog/` holds the data catalogue and lookup plans. **The backend reads them, not
this service** — `soc-core-api` mounts the directory read-only. They stay here
because the scripts that produce them do (`../scripts`, `../docs/splunk-catalog.md`).

## The caller does not write SPL

Routes take structured parameters and `spl.py` builds the search string. This is
the main safety property of the service, and it is deliberate:

- SPL is not a read-only language. `| delete`, `| collect`, `| outputlookup`
  and `| script` all write or destroy. A caller free to hand over a search string
  is a caller that can be talked into handing over one of those.
- The alert text is attacker-influenced. A log line is a fine place to hide a
  value that tries to close a quote and append `| delete`.

So: values are quoted and escaped (`spl.quote_value`), field and index names
must match a strict pattern, time modifiers are validated, row counts are capped
at `SPLUNK_MAX_COUNT`, and every index is checked against the allowlist. The
backend is trusted to plan, not to be the only control.

Treat that as defence in depth, not as the only control — **the Splunk token
must belong to a role that cannot write regardless**: search-only, the target
indexes and no others, with `delete_by_keyword` and `run_script` removed. Use a
token, never a username and password.

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
| `SPLUNK_ALLOWED_INDEXES` | — **required** | Comma-separated allowlist, or `*` to opt out on purpose. |
| `SPLUNK_BASE_URL` | — | Management port, not the web UI on 8000. |
| `SPLUNK_VERIFY_SSL` | `true` | Set `false` only for a self-signed lab cert. |
| `SPLUNK_TIMEOUT` | `60` | Seconds per search. |
| `SPLUNK_MAX_COUNT` | `200` | Hard ceiling on rows, whatever the caller asks for. |
| `SPLUNK_ALERT_INDEX` | `notable` | Where correlation-search alerts land. Must be in the allowlist for `/frequency`. |
| `SPLUNK_ALERT_NAME_FIELD` | `search_name` | Splunk ES default; plain Splunk differs. |
| `MCP_PORT` | `8200` | Internal only — the service publishes no port. |

Generate the token with `openssl rand -hex 32`.

**Removed** with the MCP layer: the six MCP tools (`list_indexes`, `describe_sourcetype`,
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

Run a planned search by hand, from inside the network:

```bash
docker run --rm --network soc-network curlimages/curl -s -X POST \
  http://soc-mcp-splunk:8200/search \
  -H "Authorization: Bearer $MCP_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"indicator":"10.1.100.11","indicator_type":"ip","fields":["srcip","dstip"],"index":"fortigate"}'
```

Every result carries the SPL that produced it, which is the fastest way to spot a
wrong field name. [`../../Backend/docs/testing.md`](../../Backend/docs/testing.md)
works through a bad answer layer by layer.

## Field names are environment-specific

Which field carries which meaning is decided by the data catalogue the **backend**
reads, not by this service: it hands `/search` the fields to look in (`srcip`, not
`src_ip`). That is what stops an empty answer being a wrong field name that reads as
"nothing happened". `SPLUNK_ALERT_NAME_FIELD` is the one assumption made here, and it
assumes Splunk ES.
