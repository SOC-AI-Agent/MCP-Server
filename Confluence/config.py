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
    # There is no fallback file, and deliberately so.
    #
    # This used to read sample playbooks when Confluence was not configured, so
    # the stack would come up on a workstation. They came back through /match
    # in the shape of a real runbook — version number and all — and an analyst
    # reading "FALSE POSITIVE when: EICAR test file" had nothing telling them
    # nobody wrote that for this estate.
    #
    # Unconfigured now means unconfigured: the connector says so and answers
    # nothing. "No playbook covers this alert" is a fact someone can act on.
    # A made-up one is not.

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
    if not settings.configured:
        missing.append(
            "CONFLUENCE_BASE_URL and CONFLUENCE_API_TOKEN — this connector has "
            "nothing to read without them"
        )
    return missing
