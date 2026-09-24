"""Env -> typed settings. Shares the root .env with the rest of the stack."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── This service ────────────────────────────────────────────────────────
    MCP_SERVER_NAME: str = "soc-splunk"
    MCP_PORT: int = 8200
    # Callers (the backend) must send `Authorization: Bearer <this>`. No default:
    # an unauthenticated service is a shell into Splunk for anything that lands
    # on soc-network. (The MCP_ prefix is the name it had as an MCP server; it is
    # kept so the token keeps its name in every .env and CI variable.)
    MCP_AUTH_TOKEN: str = ""

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
