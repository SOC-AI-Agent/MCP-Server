"""Env -> typed settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── This service ────────────────────────────────────────────────────────
    MCP_SERVER_NAME: str = "soc-confluence"
    CONFLUENCE_MCP_PORT: int = 8600
    # Its own token, not another connector's — one stolen token should not open
    # both.
    CONFLUENCE_MCP_AUTH_TOKEN: str = ""
    CONFLUENCE_MCP_ALLOWED_HOSTS: str = (
        "soc-mcp-confluence:8600,localhost:8600,127.0.0.1:8600"
    )

    # ── Confluence ──────────────────────────────────────────────────────────
    CONFLUENCE_BASE_URL: str = ""          # https://your-org.atlassian.net/wiki
    CONFLUENCE_SPACE_KEY: str = ""         # SOC
    CONFLUENCE_EMAIL: str = ""
    CONFLUENCE_API_TOKEN: str = ""
    CONFLUENCE_VERIFY_SSL: bool = True
    CONFLUENCE_TIMEOUT: int = 60
    # Cloud is /wiki/rest/api; Server and Data Center drop the /wiki prefix.
    CONFLUENCE_API_PATH: str = "/rest/api"
    CONFLUENCE_PAGE_LIMIT: int = 200

    # ── Matching ────────────────────────────────────────────────────────────
    # How close a renamed detection has to be before the router claims it.
    # 0.85 is the notebook's figure; below it, a miss reported honestly beats a
    # confident match to the wrong runbook.
    FUZZY_CUTOFF: float = 0.85
    # Re-read the space this often. Playbooks change without telling anyone, and
    # a stale one points at an index that was renamed.
    SYNC_INTERVAL_MINUTES: int = 30
    # Where to read playbooks from when Confluence is not configured. Lets the
    # stack run, and the tests run, without an Atlassian account.
    PLAYBOOK_FILE: str = "/playbooks/playbooks.json"
    # Whether falling back to that file is allowed.
    #
    # It must not be, in production. The fallback answers /match from a handful
    # of sample playbooks written to exercise the matcher — an analyst would
    # read criteria for a detection nobody wrote, presented exactly like a real
    # runbook, with the version number of a page that does not exist. There is
    # nothing in the response to tell the two apart.
    #
    # Set to "true" only on a workstation or in CI.
    ALLOW_SAMPLE_PLAYBOOKS: bool = False

    @property
    def allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.CONFLUENCE_MCP_ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def configured(self) -> bool:
        return bool(self.CONFLUENCE_BASE_URL and self.CONFLUENCE_API_TOKEN)


settings = Settings()


def missing_settings() -> list[str]:
    missing = []
    if not settings.CONFLUENCE_MCP_AUTH_TOKEN:
        missing.append("CONFLUENCE_MCP_AUTH_TOKEN")
    if not settings.configured and not settings.ALLOW_SAMPLE_PLAYBOOKS:
        missing.append(
            "CONFLUENCE_BASE_URL and CONFLUENCE_API_TOKEN — without them this "
            "connector would answer from the sample playbooks, which are made up. "
            "Set ALLOW_SAMPLE_PLAYBOOKS=true if that is what you want"
        )
    return missing
