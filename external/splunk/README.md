# soc-splunk — a Splunk container to search

A Splunk Enterprise container (`splunk/splunk`) for `soc-mcp-splunk` to use in live
mode: a real Splunk, real SPL, no company network. "External" the way the company's
Splunk is — its own stack, reached at `SPLUNK_BASE_URL` — and holding the same
sample events `SPLUNK_MODE=mock` answers from, so a question has the same answer
either way.

```
soc-core-worker ──MCP──► soc-mcp-splunk ──REST, token──► soc-splunk:8089
   (Backend)               (../../Splunk)                  (this)
```

## Bring it up

```bash
docker network create soc-network        # once, if the stack has not made it
cp .env.example .env                     # set SPLUNK_PASSWORD (8+ characters)
docker compose up -d                     # first start takes a few minutes
python3 setup.py --write-env             # waits for Splunk, then sets it up

cd ../.. && docker compose up -d --build                           # soc-mcp-splunk, now live
docker compose exec -T soc-mcp-splunk python check_connection.py   # {"connected": true, ...}
```

`setup.py` (standard library only) does, as admin:

1. turns token authentication on;
2. creates the role `soc_search` — search only, index `main` only — and the user `soc-mcp`;
3. creates an authentication token for that user, valid 90 days;
4. indexes the sample events into `index=main sourcetype=fortigate`.

Without `--write-env` it only prints the lines for `MCP-Server/.env`. With it, it
writes them there: `SPLUNK_MODE=live`, `SPLUNK_BASE_URL=https://soc-splunk:8089`,
`SPLUNK_TOKEN`, `SPLUNK_ALLOWED_INDEXES=main`, `SPLUNK_VERIFY_SSL=false` (the
container's certificate is self-signed) and a blank `SPLUNK_SAIA_MCP_URL`.
`Backend/.env` does not change: it points at the connector either way.

The web UI is at <http://localhost:8000> (`admin` / `SPLUNK_PASSWORD`).

## Things to know

- **The sample events age out.** They are built relative to now and searches look at
  the last 24 hours. `python3 setup.py --seed-only` adds fresh ones; each run adds
  the set again, so counts grow.
- **Text-to-SPL is the template here.** Splunk AI Assistant for SPL is not in a plain
  Splunk container, so the connector writes the SPL itself
  ([Splunk/README.md](../../Splunk/README.md), "Modes").
- **No `notable` index.** This is not Splunk ES; "how often has this alert fired"
  finds nothing unless `SPLUNK_ALERT_INDEX` and `SPLUNK_ALERT_NAME_FIELD` in
  `MCP-Server/.env` name where alerts are.
- **amd64 only.** On Apple Silicon it runs emulated: enable Rosetta in Docker
  Desktop, and expect a slower start.
- **Licence.** Starting it accepts the Splunk General Terms
  (`SPLUNK_GENERAL_TERMS` in the compose file). It runs on the trial licence, which
  becomes the Free licence after 60 days; token authentication needs the trial or
  an Enterprise licence. `docker compose down -v` starts over.
- **The admin password is only applied on the first start.** Changing it in `.env`
  afterwards does nothing; `docker compose down -v` and start again.
- **Not for production data.** Self-signed TLS, an admin password in a file, ports
  on localhost. The company's Splunk is set up as in
  [Backend/docs/splunk-mcp.md](../../../Backend/docs/splunk-mcp.md).
