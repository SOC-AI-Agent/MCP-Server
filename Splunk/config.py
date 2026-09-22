"""Env -> typed settings. Shares the root .env with the rest of the stack."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── MCP server ──────────────────────────────────────────────────────────
    MCP_SERVER_NAME: str = "soc-splunk"
    MCP_PORT: int = 8200
    # Callers (soc-ai) must send `Authorization: Bearer <this>`. No default:
    # an unauthenticated MCP server is a shell into Splunk for anything that
    # lands on soc-network.
    MCP_AUTH_TOKEN: str = ""
    # Host headers the transport accepts, its DNS-rebinding defence. The compose
    # service name is how soc-ai addresses this container; localhost is the
    # healthcheck.
    MCP_ALLOWED_HOSTS: str = "soc-mcp-splunk:8200,localhost:8200,127.0.0.1:8200"

    # ── Splunk ──────────────────────────────────────────────────────────────
    SPLUNK_BASE_URL: str = "https://splunk:8089"
    SPLUNK_TOKEN: str = ""
    # Self-signed lab certs need this off; leaving it on is the safe default.
    SPLUNK_VERIFY_SSL: bool = True
    SPLUNK_TIMEOUT: int = 60

    # A JSON file describing what each index and sourcetype holds and which
    # field carries which meaning. Written by a person after reading /catalog;
    # it is what the model is told, and what related_events searches on.
    # Unset means CIM field names, which are right only on a normalised estate.
    SPLUNK_CATALOG_FILE: str = "/catalog/splunk-catalog.json"

    # Comma-separated index allowlist. Every search is confined to it. "*"
    # disables the restriction and must be typed out on purpose.
    SPLUNK_ALLOWED_INDEXES: str = ""
    # Hard ceiling on rows returned to the model, whatever it asks for.
    SPLUNK_MAX_COUNT: int = 200

    # Where correlation-search alerts land, and the field holding their name.
    # Splunk ES defaults; override for a plain Splunk install.
    SPLUNK_ALERT_INDEX: str = "notable"
    SPLUNK_ALERT_NAME_FIELD: str = "search_name"

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
    missing = []
    if not settings.MCP_AUTH_TOKEN:
        missing.append("MCP_AUTH_TOKEN")
    if not settings.SPLUNK_TOKEN:
        missing.append("SPLUNK_TOKEN")
    if not settings.allowed_indexes:
        missing.append("SPLUNK_ALLOWED_INDEXES (comma-separated, or '*' to opt out)")
    if missing:
        raise RuntimeError("refusing to start, unset required env: " + ", ".join(missing))
