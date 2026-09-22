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
THREATQ_INDICATOR_PATH=/api/indicators   # adjust if your deployment differs
THREATQ_VERIFY_SSL=true                  # false only for a self-signed lab cert
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
docker compose --profile threatq up -d --build soc-mcp-threatq
curl -s http://soc-mcp-threatq:8300/health
```

```json
{"status":"ok","server":"soc-threatq","threatq":true}
```

`threatq: false` means unreachable or the credentials were refused.

### 6. Offer the tool to an agent

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

## Running without a ThreatQ

ThreatQ ships as an appliance to licensed customers — there is no public image
to run beside Splunk's. So the stack carries a stand-in, and the whole
enrichment path works locally without one:

```bash
docker compose --profile threatq up -d --build soc-threatq-fake soc-mcp-threatq
```

It joins the network as `threatq`, so pointing at a real instance later is a
`THREATQ_BASE_URL` change and nothing else:

```bash
THREATQ_BASE_URL=http://threatq:8500     # stand-in
THREATQ_AUTH_MODE=oauth
THREATQ_CLIENT_ID=local-dev
THREATQ_EMAIL=dev@example.com
THREATQ_PASSWORD=local-dev
THREATQ_VERIFY_SSL=false
```

It knows four indicators — the ones in `samples/alerts.json` and the Splunk
test data — so an alert carried through the whole pipeline finds something at
the end of it. Everything else is deliberately unknown, because "no record" is
the case that gets misread as "clean".

Its tokens expire after **30 seconds**. An hour-long token would mean the
connector's refresh path never runs in testing; at 30 seconds it runs
constantly:

```
$ docker compose logs soc-mcp-threatq | grep -c "minted ThreatQ access token"
2
```

**What this proves and what it does not.** It shows the connector honours the
contract we believe ThreatQ has. It cannot show ThreatQ behaves that way — see
the unverified assumptions above. One curl against a real instance corrects
this file and `threatq_api.py` together.

## The test suite

```bash
./tests/test_lookup.sh
```

Starts a stand-in platform and the connector on a throwaway network and checks
both ways in, plus what matters more than the happy path: an indicator with no
record, a caller with no token, an empty request, and an invalid type.

```
14 passed, 0 failed
```

`tests/fake_threatq.py` knows three indicators and nothing else — the
interesting case is the fourth one.

## Files

| File | Role |
| --- | --- |
| `server.py` | The route, the tool, health, the app. |
| `threatq_api.py` | Credentials, token lifecycle, the REST call. |
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
| `THREATQ_INDICATOR_PATH` | `/api/indicators` | **Unverified** against a live instance. |
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
| `POST /api/token?grant_type=password&client_id=…` with `email` + `password` | `THREATQ_AUTH_MODE=oauth` sends exactly that |
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

The stand-in enforces this, so forgetting `with=` fails a test here rather than
producing confident nonsense in production.

### Still inferred

| Inferred | Why it is a setting |
| --- | --- |
| The criteria key for an indicator's value is `value` | `THREATQ_SEARCH_PATH` and the criteria shape can be changed without touching code |
| `score` may arrive as `{"generated_score": …}` or as a number | both are unwrapped |
| Related objects may be `{"name": …}` or plain strings | both are handled |

One search against a live instance settles all three.

An earlier version of this connector proxied ThreatQ's own `/api/mcp` and
exposed its agent service as a tool. Both were removed: nothing called them,
and both rested on an assumption about ThreatQ's MCP endpoint that has never
been confirmed. The REST path here is the one the backend actually uses.
