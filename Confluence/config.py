"""Env -> typed settings. Shares the root .env with the rest of the stack."""

import re
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict


def site_of(raw: str, space_key: str) -> dict[str, str]:
    """
    CONFLUENCE_BASE_URL as the site, the space it names, and — for a Cloud page or
    folder — what to read. Pasted from the browser's address bar:

      https://acme.atlassian.net/wiki/spaces/SOC/overview         -> .../wiki, SOC, the whole space
      https://acme.atlassian.net/wiki/spaces/SOC/pages/123/Title  -> .../wiki, SOC, page 123 and all under it
      https://acme.atlassian.net/wiki/spaces/SOC/folder/456       -> .../wiki, SOC, all in folder 456
      https://confluence.corp/display/SOC/Some+Page               -> site root, SOC, the whole space
      https://confluence.corp/spaces/viewspace.action?key=SOC     -> site root, SOC, the whole space
      https://acme.atlassian.net/wiki                             -> as it is, CONFLUENCE_SPACE_KEY

    The space named in the URL wins over CONFLUENCE_SPACE_KEY, which is for a plain
    site URL. A page or folder narrows the read to that part of the tree (Cloud,
    API v2); everything else reads the whole space. The same reading the backend
    gives the same setting (Backend: config/configuration.ts confluenceSite).
    """
    given, text = (space_key or "").strip(), (raw or "").strip()
    whole = {"root_type": "", "root_id": ""}
    url = urlsplit(text)
    if not url.scheme or not url.netloc:
        return {"base_url": text.rstrip("/"), "space_key": given, **whole}
    origin = f"{url.scheme}://{url.netloc}"
    path = url.path.rstrip("/")

    m = re.match(r"^(.*?)/(?:spaces|display)/([^/]+)(.*)$", path)
    if m and m.group(2) != "viewspace.action":
        site = {"base_url": origin + m.group(1), "space_key": unquote(m.group(2))}
        # Cloud's /spaces/KEY/pages/ID/Title (or pages/edit-v2/ID) and /spaces/KEY/folder/ID.
        page = re.match(r"^/pages/(?:edit-v2/)?(\d+)", m.group(3))
        if page:
            return {**site, "root_type": "page", "root_id": page.group(1)}
        folder = re.match(r"^/folder/(\d+)", m.group(3))
        if folder:
            return {**site, "root_type": "folder", "root_id": folder.group(1)}
        return {**site, **whole}
    # Server/DC's .action pages: the site is what comes before them, the space
    # their key= if they carry one (viewpage.action?pageId= does not).
    action = re.match(r"^(.*?)/(?:spaces|pages)/[^/]+\.action$", path)
    if action:
        query = parse_qs(url.query)
        key = (query.get("key") or query.get("spaceKey") or [given])[0]
        return {"base_url": origin + action.group(1), "space_key": key, **whole}
    return {"base_url": origin + path, "space_key": given, **whole}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── This service ────────────────────────────────────────────────────────
    CONFLUENCE_MCP_SERVER_NAME: str = "soc-confluence"
    CONFLUENCE_MCP_PORT: int = 8600
    # Its own token, not the Splunk connector's — one stolen token should not
    # open both. No default: an unauthenticated service hands the playbook space
    # to anything that lands on soc-network.
    CONFLUENCE_MCP_AUTH_TOKEN: str = ""
    # Host headers the MCP transport accepts (its DNS-rebinding defence).
    CONFLUENCE_MCP_ALLOWED_HOSTS: str = "soc-mcp-confluence:8600,localhost:8600,127.0.0.1:8600"

    # ── Confluence ──────────────────────────────────────────────────────────
    # https://your-org.atlassian.net/wiki (Cloud), https://confluence.corp
    # (Server/DC), or an address as the browser shows it — see site_of.
    CONFLUENCE_BASE_URL: str = ""
    # Only when the base URL is the bare site.
    CONFLUENCE_SPACE_KEY: str = ""
    # Cloud: email + API token as basic auth. Blank email: the token is a
    # Server/DC personal access token, sent as a bearer.
    CONFLUENCE_EMAIL: str = ""
    CONFLUENCE_API_TOKEN: str = ""
    # v2 (/api/v2/spaces/{id}/pages) for Cloud, where Atlassian is retiring v1;
    # v1 (<api path>/content) for Server/DC, which has only v1. auto picks v2 for
    # *.atlassian.net and v1 otherwise.
    CONFLUENCE_API: str = "auto"
    # v1 only. Cloud is <base>/wiki/rest/api, so with /wiki in the base this stays /rest/api.
    CONFLUENCE_API_PATH: str = "/rest/api"
    # Pages per request (v2 takes at most 250); the space is paged through to the end either way.
    CONFLUENCE_PAGE_LIMIT: int = 200
    # An HTTP proxy for the Confluence calls, e.g. the office proxy for Cloud from
    # a host with no direct way out. HTTPS goes through it as a CONNECT tunnel, so
    # the proxy sees the host name, never the token or the pages. Blank: direct —
    # and no proxy picked up from the environment either.
    CONFLUENCE_PROXY: str = ""
    # Set false only for a self-signed lab cert.
    CONFLUENCE_VERIFY_SSL: bool = True
    CONFLUENCE_TIMEOUT: int = 60

    @property
    def allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.CONFLUENCE_MCP_ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def site(self) -> dict[str, str]:
        return site_of(self.CONFLUENCE_BASE_URL, self.CONFLUENCE_SPACE_KEY)

    @property
    def base_url(self) -> str:
        return self.site["base_url"]

    @property
    def space_key(self) -> str:
        return self.site["space_key"]

    @property
    def api_version(self) -> str:
        chosen = self.CONFLUENCE_API.strip().lower()
        if chosen in ("v1", "v2"):
            return chosen
        host = urlsplit(self.base_url).hostname or ""
        return "v2" if host.endswith(".atlassian.net") else "v1"


settings = Settings()


def validate_startup() -> None:
    """Fail loudly at boot rather than serving a connector with nothing behind it.

    There is no mock and no sample playbook, deliberately: a made-up runbook comes
    back in the shape of a real one, and nothing tells the analyst reading it that
    nobody wrote it for this estate. Unconfigured means it does not start.
    """
    if settings.CONFLUENCE_API.strip().lower() not in ("auto", "v1", "v2"):
        raise RuntimeError(f"CONFLUENCE_API must be auto, v1 or v2, not {settings.CONFLUENCE_API!r}")
    missing = []
    if not settings.CONFLUENCE_MCP_AUTH_TOKEN:
        missing.append("CONFLUENCE_MCP_AUTH_TOKEN")
    if not settings.base_url:
        missing.append("CONFLUENCE_BASE_URL")
    if not settings.CONFLUENCE_API_TOKEN:
        missing.append("CONFLUENCE_API_TOKEN")
    if not settings.space_key:
        missing.append("CONFLUENCE_SPACE_KEY (or a CONFLUENCE_BASE_URL that names the space)")
    if missing:
        raise RuntimeError("refusing to start, unset required env: " + ", ".join(missing))
