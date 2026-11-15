"""Env -> typed settings. Shares the root .env with the rest of the stack."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── This service ────────────────────────────────────────────────────────
    MCP_SERVER_NAME: str = "soc-splunk"
    MCP_PORT: int = 8200
    # Callers (the backend) must send `Authorization: Bearer <this>`. No default:
    # an unauthenticated service is a shell into Splunk for anything that lands
    # on soc-network.
    MCP_AUTH_TOKEN: str = ""
    # Host headers the MCP transport accepts (its DNS-rebinding defence): the
    # compose name the backend uses, and localhost for the healthcheck.
    MCP_ALLOWED_HOSTS: str = "soc-mcp-splunk:8200,localhost:8200,127.0.0.1:8200"

    # mock: the MCP tools answer from mock.py — Text-to-SPL is a template and the
    #       data is a fixed set of events. Needs no Splunk and no Splunk token.
    # live: searches run against SPLUNK_BASE_URL — the Splunk container in
    #       external/splunk, or the company's. Text-to-SPL is the template
    #       (text_to_spl.py) unless SPLUNK_SAIA_MCP_URL names a Splunk MCP server
    #       with Splunk AI Assistant for SPL behind it.
    # Live by default, so a deployment that forgets to choose cannot serve
    # made-up data as if it were Splunk.
    SPLUNK_MODE: str = "live"

    # ── Splunk ──────────────────────────────────────────────────────────────
    SPLUNK_BASE_URL: str = "https://splunk:8089"
    SPLUNK_TOKEN: str = ""
    # Self-signed lab certs need this off; leaving it on is the safe default.
    SPLUNK_VERIFY_SSL: bool = True
    SPLUNK_TIMEOUT: int = 60

    # Comma-separated index allowlist. Every search is confined to it. "*"
    # disables the restriction and must be typed out on purpose.
    SPLUNK_ALLOWED_INDEXES: str = ""
    # Hard ceiling on rows returned to a caller, whatever it asks for.
    SPLUNK_MAX_COUNT: int = 200

    # Where fired alerts are, and the field holding an alert's name — told to
    # Text-to-SPL for "how often has this alert fired". Splunk ES defaults; a
    # plain Splunk install differs.
    SPLUNK_ALERT_INDEX: str = "notable"
    SPLUNK_ALERT_NAME_FIELD: str = "search_name"

    # ── Text-to-SPL by Splunk AI Assistant (optional, live only) ────────────
    # Splunk's own MCP Server app, https://<splunk>:8089/services/mcp. Set: each
    # request is forwarded to its Text-to-SPL tool. Blank: the template writes
    # the SPL. A plain Splunk container has no AI Assistant, so blank there.
    SPLUNK_SAIA_MCP_URL: str = ""
    # A Splunk token created with audience "mcp". Blank: SPLUNK_TOKEN is sent.
    SPLUNK_SAIA_MCP_TOKEN: str = ""
    SPLUNK_SAIA_TOOL: str = "saia_generate_spl"
    # Which argument of that tool takes the request. Blank: read from its schema.
    SPLUNK_SAIA_ARG: str = ""

    @property
    def mock(self) -> bool:
        return self.SPLUNK_MODE.strip().lower() == "mock"

    @property
    def saia(self) -> bool:
        """Text-to-SPL is forwarded to Splunk AI Assistant rather than templated."""
        return not self.mock and bool(self.SPLUNK_SAIA_MCP_URL.strip())

    @property
    def allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.MCP_ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def allowed_indexes(self) -> list[str]:
        return [i.strip() for i in self.SPLUNK_ALLOWED_INDEXES.split(",") if i.strip()]

    @property
    def index_restriction_disabled(self) -> bool:
        return self.allowed_indexes == ["*"]


settings = Settings()


def validate_startup() -> None:
    """Fail loudly at boot rather than silently serving an open Splunk proxy."""
    if settings.SPLUNK_MODE.strip().lower() not in ("mock", "live"):
        raise RuntimeError(f"SPLUNK_MODE must be mock or live, not {settings.SPLUNK_MODE!r}")
    missing = []
    if not settings.MCP_AUTH_TOKEN:
        missing.append("MCP_AUTH_TOKEN")
    if settings.mock:
        # Mock talks to no Splunk, so it needs no Splunk credentials.
        if missing:
            raise RuntimeError("refusing to start, unset required env: " + ", ".join(missing))
        return
    if not settings.SPLUNK_TOKEN:
        missing.append("SPLUNK_TOKEN")
    if not settings.allowed_indexes:
        missing.append("SPLUNK_ALLOWED_INDEXES (comma-separated, or '*' to opt out)")
    if missing:
        raise RuntimeError("refusing to start, unset required env: " + ", ".join(missing))
