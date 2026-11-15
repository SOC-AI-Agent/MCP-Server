# soc-mcp-confluence

Confluence over MCP: the playbook space, **read-only**. It holds the Confluence
credentials and is the one thing that talks to Confluence. It hands pages over as
Confluence stores them and does not decide what a page means — which fields make a
playbook and which playbook covers an alert is soc-ai's work (extract, embed, match).

**Status: prepared, not yet on anyone's path.** The backend still reads Confluence
itself (`Backend/src/modules/enrichment/playbook-sync.service.ts`) and this
connector reads the same pages the same way, from the same settings, so moving the
backend over is a change of where it reads from, not of what it gets.

```
caller ──MCP /mcp, bearer──► soc-mcp-confluence ──REST v1/v2, read-only──► Confluence
                                (this)                                      Cloud or Server/DC
```

## Tools

| Tool | Returns |
| --- | --- |
| `confluence_read_pages()` | `{space_key, count, pages: [{id, title, version, url, body}]}` — every current page, `body` as storage-format XHTML. Large: a few hundred pages is megabytes. This is the shape soc-ai's `PUT /playbooks/index` takes. |
| `confluence_list_pages()` | The same without `body`: what exists, and the ids. |
| `confluence_get_page(page_id, format)` | One page. `format`: `storage` (default) or `text` (plain text, a line per block). A page outside the playbook space is refused, even if the account can see it. |

All three are annotated read-only. An unreadable space is a tool error, never an
empty list — a caller would take that for an empty space and drop every playbook.

## Routes

| Route | Does |
| --- | --- |
| `POST /mcp` | MCP (streamable HTTP, stateless, JSON responses). |
| `GET /pages` | What `confluence_read_pages` returns, for a caller that would rather not speak MCP. 502 when Confluence cannot be read. |
| `GET /check-connection` | Whether Confluence can be read, and where it stops if not. |
| `GET /health` | Container healthcheck. No token needed. |

Every route but `/health` needs `Authorization: Bearer $CONFLUENCE_MCP_AUTH_TOKEN`.
The MCP endpoint also checks the `Host` header against `CONFLUENCE_MCP_ALLOWED_HOSTS`
and answers 421 to anything else.

## Run it

```bash
# in ../.env: CONFLUENCE_MCP_AUTH_TOKEN (openssl rand -hex 32), CONFLUENCE_BASE_URL,
# CONFLUENCE_API_TOKEN, and CONFLUENCE_EMAIL (Cloud) — the same Confluence values as Backend/.env
docker compose --profile confluence up -d --build
docker compose exec -T soc-mcp-confluence python check_connection.py
```

```json
{"connected":true,"base_url":"https://acme.atlassian.net/wiki","space_key":"SOC","api":"v2","reads":"the whole space","latency_ms":212}
```

| `failed_at` | Meant | Usually |
| --- | --- | --- |
| `reach` | no answer, or an answer that is not Confluence's REST API | wrong `CONFLUENCE_BASE_URL` (missing `/wiki`?), DNS, a firewall, `CONFLUENCE_PROXY` needed or wrong, an SSO login page in front, a certificate the container does not trust |
| `auth` | the credentials were refused (401) | wrong or expired token; Cloud needs `CONFLUENCE_EMAIL`, Server/DC must not have it |
| `read` | authenticated, but the space is not visible | wrong space key, or the account has no access to it |

It is behind a compose profile because it refuses to start unconfigured, and a
stack without Confluence settings should still come up. There is no mock and no
sample playbook, on purpose: a made-up runbook comes back in the shape of a real
one, and nothing tells the analyst reading it that nobody wrote it for this estate.

## Configuration

Set in `../.env`. The Confluence settings mean what they mean in `Backend/.env`.

| Variable | Default | Notes |
| --- | --- | --- |
| `CONFLUENCE_MCP_AUTH_TOKEN` | — **required** | Bearer token a caller presents. Its own, not `MCP_AUTH_TOKEN`. |
| `CONFLUENCE_BASE_URL` | — **required** | The site (`https://org.atlassian.net/wiki`, `https://confluence.corp`), or an address from the browser: `…/spaces/SOC/overview` reads the whole space, `…/spaces/SOC/pages/123/…` that page and all under it, `…/spaces/SOC/folder/456` that folder (page and folder: Cloud only). |
| `CONFLUENCE_SPACE_KEY` | — **required** unless the URL names the space | The URL's space wins. |
| `CONFLUENCE_API_TOKEN` | — **required** | Cloud: an API token. Server/DC: a personal access token. A read-only account that sees only the playbook space. |
| `CONFLUENCE_EMAIL` | — | Cloud: the account's email (basic auth). Blank: the token is sent as a bearer. |
| `CONFLUENCE_API` | `auto` | `v2` for `*.atlassian.net`, `v1` otherwise; `v1` or `v2` forces one. |
| `CONFLUENCE_API_PATH` | `/rest/api` | v1 only. |
| `CONFLUENCE_PAGE_LIMIT` | `200` | Pages per request (v2: at most 250). The space is paged to the end either way. |
| `CONFLUENCE_PROXY` | — | An HTTP proxy for the Confluence calls. Blank: direct, and none taken from the environment. |
| `CONFLUENCE_VERIFY_SSL` | `true` | `false` only for a self-signed lab cert. For an internal CA: PEM in `../certs/`, `SSL_CERT_FILE=/certs/<file>.pem`. |
| `CONFLUENCE_TIMEOUT` | `60` | Seconds per request. |
| `CONFLUENCE_MCP_ALLOWED_HOSTS` | `soc-mcp-confluence:8600,localhost:8600,127.0.0.1:8600` | Host headers the MCP endpoint accepts. |
| `CONFLUENCE_MCP_PORT` | `8600` | Internal only — the service publishes no port. |

## Files

| File | Role |
| --- | --- |
| `server.py` | The MCP server, its three tools, and the plain routes. |
| `confluence_api.py` | The REST client: v1 and v2, paging, a page tree, one page, the connection check. |
| `config.py` | Env to typed settings, the base-URL reading, the startup preconditions. |
| `check_connection.py` | Calls `/check-connection` from inside the container; exit 0 or 1. |
| `auth.py` | Bearer-token middleware in front of every route but `/health`. |

## Moving the backend onto it

Not done here. What it takes: `PlaybookSyncService.readSpace` calls
`confluence_read_pages` (or `GET /pages`) instead of Confluence, with
`CONFLUENCE_MCP_URL=http://soc-mcp-confluence:8600` and `CONFLUENCE_MCP_AUTH_TOKEN`
in `Backend/.env`; the Confluence credentials, proxy and CA then leave the backend
for this repo's `.env`, and `scripts/confluence-check.ts` asks `/check-connection`.
