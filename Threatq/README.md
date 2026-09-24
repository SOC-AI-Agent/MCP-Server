# soc-mcp-threatq

Indicator reputation from ThreatQ, two ways in.

```
soc-core-worker ──POST /lookup──────────────► soc-mcp-threatq ──REST──► ThreatQ
  (every alert, before any model runs)              │
                                                    │
soc-ai agent ──MCP: lookup_indicator────────────────┘
  (one indicator that turned up mid-analysis)
```

## Why two

**The route** is how the backend enriches every alert. Extracting the
indicators and checking them is exact work with one right answer, so it is not
left to a model to decide whether to bother — the worker does it every time,
before the agent sees anything. Plain HTTP, no MCP session to hold.

**The tool** covers what the backend cannot know in advance. An agent searching
Splunk turns up addresses that were not in the original alert and have never
been checked. One indicator at a time, on purpose: this is not an interface for
enumerating the platform.

Nothing here writes. ThreatQ operations can add indicators, change status and
fire actions, and the alert text steering the model is attacker-influenced —
a read-only account is the layer under that.

## Connecting it

### 1. Credentials

Two modes, set with `THREATQ_AUTH_MODE`:

```bash
# OAuth2 password grant — the usual ThreatQ REST scheme. The connector mints a
# token at THREATQ_TOKEN_PATH and refreshes it before expiry.
THREATQ_AUTH_MODE=oauth
THREATQ_CLIENT_ID=<from ThreatQ -> Settings -> API / Integrations>
THREATQ_EMAIL=<service account>
THREATQ_PASSWORD=<service account password>

# Or a flat token, sent as-is.
THREATQ_AUTH_MODE=bearer
THREATQ_TOKEN=<token>
```

The account must be **read-only**. See [`../../TOKENS.md`](../../docs/tokens.md).

### 2. Where ThreatQ is

```bash
THREATQ_BASE_URL=https://threatq.example.com
THREATQ_SEARCH_PATH=/api/indicators/search   # adjust if your deployment differs
THREATQ_CHECK_PATH=/api/indicators           # what /check-connection reads
THREATQ_VERIFY_SSL=true                      # false only for a self-signed lab cert
```

### 3. The token callers present to *this* service

```bash
THREATQ_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
```

Its own, not the Splunk connector's: one stolen token should not open both.
Without it the container refuses to start rather than serving an
unauthenticated way into threat intelligence.

### 4. Point the backend at it

```bash
THREATQ_LOOKUP_URL=http://soc-mcp-threatq:8300
THREATQ_MAX_INDICATORS=25
```

Enrichment is skipped when either the URL or the token is missing, and the
prompt then says the check did not happen — rather than implying the indicators
came back clean.

### 5. Start it

```bash
docker compose up -d --build soc-mcp-threatq
```

The container refuses to start until the credentials for the chosen auth mode
are set, so a missing value shows up here, in `docker compose logs
soc-mcp-threatq`, and not on the first alert.

### 6. Check it is connected

```bash
curl -s http://soc-mcp-threatq:8300/check-connection \
  -H "Authorization: Bearer $THREATQ_MCP_AUTH_TOKEN"
```

```json
{"connected":true,"base_url":"https://threatq.example.com","auth_mode":"oauth","latency_ms":212}
```

Nothing publishes this port, so run it from inside the network. The easy way
is the script beside the server, which reads the token from the container's own
environment and exits 0 only when connected:

```bash
docker compose exec -T soc-mcp-threatq python check_connection.py
```

The deploy job runs exactly that after the containers are up, and fails the
pipeline if it exits 1.

It checks four things in order and says which one failed:

| `failed_at` | Meant | Usually |
| --- | --- | --- |
| `reach` | the host did not answer | wrong `THREATQ_BASE_URL`, DNS, a firewall, or a certificate the container does not trust (`THREATQ_VERIFY_SSL`) |
| `auth` | the credentials were refused (401) | wrong `THREATQ_CLIENT_ID` / `THREATQ_EMAIL` / `THREATQ_PASSWORD`, or an expired `THREATQ_TOKEN` |
| `read` | authenticated, but the read did not succeed | the account cannot read indicators (403), or `THREATQ_CHECK_PATH` is wrong for this deployment |
| `search` | can read the collection, but the search a lookup uses failed | the role lacks `indicators_search` (ThreatQ permissions are per endpoint), or `THREATQ_SEARCH_PATH` is wrong — a `404` with no JSON body is a web server saying the path is not there |

```json
{"connected":false,"failed_at":"auth","error":"ThreatQ rejected the credentials (401) — check THREATQ_CLIENT_ID, THREATQ_EMAIL and THREATQ_PASSWORD","base_url":"https://threatq.example.com","auth_mode":"oauth","latency_ms":180}
```

`200` when connected, `502` when not. It reads one row, then searches for a value
nothing has (`soc-mcp-connection-check.invalid`), and throws both away: nothing is
written and nothing from ThreatQ comes back. The search is the same call a lookup
makes, so passing it predicts a lookup passing. It sits behind the
bearer token, unlike `/health`, because each call goes out to ThreatQ with the
service account.

`/health` stays open for the container healthcheck and only reports whether
ThreatQ answered — under `bearer` it does not tell you the token is accepted.
Use `/check-connection` for that.

### 7. Offer the tool to an agent

Register the server in the LLM server and add it to an agent's `mcp_servers`.
Only agents that follow up on their own findings need it — an agent working
from enrichment alone does not.

## The API

### `POST /lookup`

```bash
curl -s -X POST http://soc-mcp-threatq:8300/lookup \
  -H "Authorization: Bearer $THREATQ_MCP_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"indicators":[{"type":"ip","value":"45.83.122.9"},
                     {"type":"domain","value":"cdn.example.com"}]}'
```

```json
{"records":[
  {"type":"ip","value":"45.83.122.9","found":true,"score":90,"status":"Active",
   "sources":["Feed A","Feed B"],"adversaries":["APT29"],
   "first_seen":"2026-09-18T04:11:00Z"},
  {"type":"domain","value":"cdn.example.com","found":false}],
 "checked":2}
```

Types: `ip`, `domain`, `url`, `hash`, `email`. At most
`THREATQ_LOOKUP_MAX` (100) per call. **One indicator failing does not lose the
rest** — it comes back with `found: false` and an `error`, so a partial outage
still enriches what it can.

### Tool `lookup_indicator(value, indicator_type)`

One indicator. A record that does not exist comes back with a `note` saying so
in as many words, because the short version is what produces "not in threat
intel, therefore benign".

## `found: false` is not `clean`

The distinction is load-bearing and is repeated in three places — the tool's
docstring, the `note` on a miss, and how the backend renders enrichment into
the prompt — because a model given the short version prints the wrong one.

Threat intelligence trails an attacker. Infrastructure stood up this week has
no record anywhere. "No record" means **unknown**.

## Files

| File | Role |
| --- | --- |
| `server.py` | The lookup route, the tool, `/check-connection`, health, the app. |
| `threatq_api.py` | Credentials, token lifecycle, the REST call, the connection check. |
| `check_connection.py` | Calls `/check-connection` from inside the container; exit 0 or 1, so CI can branch on it. |
| `auth.py` | Bearer middleware in front of everything but `/health`. |
| `config.py` | Env to typed settings, plus the startup preconditions. |

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `THREATQ_MCP_AUTH_TOKEN` | — **required** | Token callers present to this service. |
| `THREATQ_AUTH_MODE` | `oauth` | `oauth` or `bearer`. |
| `THREATQ_CLIENT_ID` / `THREATQ_EMAIL` / `THREATQ_PASSWORD` | — **required if oauth** | |
| `THREATQ_TOKEN` | — **required if bearer** | |
| `THREATQ_BASE_URL` | `https://threatq.local` | |
| `THREATQ_SEARCH_PATH` | `/api/indicators/search` | Lookup by value. **Unverified** against a live instance. |
| `THREATQ_CHECK_PATH` | `/api/indicators` | Read by `/check-connection`. **Unverified** against a live instance. |
| `THREATQ_VERIFY_SSL` | `true` | |
| `THREATQ_TIMEOUT` | `60` | Seconds per call. |
| `THREATQ_LOOKUP_MAX` | `100` | Indicators per `/lookup`. |
| `THREATQ_MCP_PORT` | `8300` | Internal only — the service publishes no port. |
| `THREATQ_MCP_ALLOWED_HOSTS` | `soc-mcp-threatq:8300,localhost:8300,127.0.0.1:8300` | DNS-rebinding defence. |

## What this is built from

Shaped from ThreatQ's
[REST API Reference v5.12](https://helpcenter.threatq.com/assets/HTML/api/ThreatQ_REST_API_Reference_v5.12.0.html),
not from guesswork. Documented, and implemented accordingly:

| Documented | What it means here |
| --- | --- |
| `POST /api/token?grant_type=password&client_id=…` with `email` + `password` in the body | `THREATQ_AUTH_MODE=oauth` sends the query string as documented, and repeats the four fields in a form body because the reference does not show how the body is encoded |
| The access token goes in `Authorization: Bearer <token>` | sent that way in both modes |
| **Not documented:** a static API token, and the token's lifetime (`expires_in`) or a refresh flow | `THREATQ_AUTH_MODE=bearer` is therefore unverified — use `oauth` unless the ThreatQ team confirms a static token exists. `expires_in` is read if the response has it and assumed to be one hour if not; a 401 mid-lookup triggers one re-mint |
| Permissions are per endpoint (`GET /api/permissions/current` lists them, e.g. `indicators` and `indicators_search`) | ask for read on both: `/check-connection` reads `GET /api/indicators`, a lookup uses the search endpoint, and a role can hold one without the other |
| `client_id` is read from `https://<host>/assets/js/config.js` | where to find the value for `THREATQ_CLIENT_ID` |
| `GET /api/indicators` takes `limit`, `offset`, `sort`, `with` — **no value filter** | looking up by value is a search, not a GET |
| `POST /api/indicators/search`, criteria in ThreatQ's SOLR-like convention | `{"criteria": {"value": …, "type": …}}` |
| `with=` controls related objects: `score, sources, adversaries, status, type, attributes` | **requested explicitly** — see below |
| `404` is "Object not found" | treated as no record, not as an error |
| Records come back under `data` | both `data: []` and 404 mean no record |

### `with=` is the one that bites

Score, sources, adversaries and status are *related objects*. Ask for the
indicator without naming them and the reply is a valid record carrying only
`id`, `created_at` and `updated_at`:

```
$ curl -s -X POST "$TQ/api/indicators/search" -d '{"criteria":{"value":"45.83.122.9"}}'
{"data":[{"id":90001,"created_at":"…","updated_at":"…"}]}
```

No error, no empty result — just an indicator that looks unscored. Every
indicator would read as "nothing known", which is the same wrong answer as a
missing record but with no way to notice.

### Still inferred

| Inferred | Why it is a setting |
| --- | --- |
| The criteria key for an indicator's value is `value` | `THREATQ_SEARCH_PATH` and the criteria shape can be changed without touching code |
| `score` may arrive as `{"generated_score": …}` or as a number | both are unwrapped |
| Related objects may be `{"name": …}` or plain strings | both are handled |

One search against a live instance settles all three — and `/check-connection`
now makes one, though it searches for a value nothing has, so it proves the
account may search and the path is right, not that the criteria shape finds a
real indicator.

An earlier version of this connector proxied ThreatQ's own `/api/mcp` and
exposed its agent service as a tool. Both were removed: nothing called them,
and both rested on an assumption about ThreatQ's MCP endpoint that has never
been confirmed. The REST path here is the one the backend actually uses.
