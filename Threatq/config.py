"""Env -> typed settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── This service ────────────────────────────────────────────────────────
    MCP_SERVER_NAME: str = "soc-threatq"
    THREATQ_MCP_PORT: int = 8300
    # Callers must send `Authorization: Bearer <this>`. Its own token, not the
    # Splunk connector's — one stolen token should not open both.
    THREATQ_MCP_AUTH_TOKEN: str = ""
    THREATQ_MCP_ALLOWED_HOSTS: str = "soc-mcp-threatq:8300,localhost:8300,127.0.0.1:8300"

    # ── ThreatQ platform ────────────────────────────────────────────────────
    THREATQ_BASE_URL: str = "https://threatq.local"
    # Looking an indicator up by its value is a search, not a GET on the
    # collection: GET /api/indicators takes limit, offset, sort and with, and has
    # no value filter. Documented in the REST API Reference v5.12.
    THREATQ_SEARCH_PATH: str = "/api/indicators/search"
    # Score, sources, adversaries, status and attributes are related objects and
    # are ABSENT unless asked for by name. Without this the reply parses fine and
    # every indicator looks unscored, which is the worst kind of wrong.
    THREATQ_SEARCH_WITH: str = "score,sources,adversaries,status,type,attributes"
    THREATQ_VERIFY_SSL: bool = True
    THREATQ_TIMEOUT: int = 60

    # ── ThreatQ auth ────────────────────────────────────────────────────────
    # "oauth"  -> password grant against THREATQ_TOKEN_PATH, refreshed on expiry
    # "bearer" -> a static token in THREATQ_TOKEN, sent as-is
    THREATQ_AUTH_MODE: str = "oauth"
    THREATQ_TOKEN_PATH: str = "/api/token"
    THREATQ_CLIENT_ID: str = ""
    THREATQ_EMAIL: str = ""
    THREATQ_PASSWORD: str = ""
    THREATQ_TOKEN: str = ""

    # Cap on one POST /lookup. The backend checks every external indicator in an
    # alert, which is a handful; a number far above that is a caller looping.
    THREATQ_LOOKUP_MAX: int = 100

    @property
    def allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.THREATQ_MCP_ALLOWED_HOSTS.split(",") if h.strip()]


settings = Settings()

VALID_AUTH_MODES = frozenset({"oauth", "bearer"})


def validate_startup() -> None:
    """Fail loudly at boot rather than serving an unauthenticated proxy into
    threat intelligence."""
    missing = []

    if settings.THREATQ_AUTH_MODE not in VALID_AUTH_MODES:
        missing.append(f"THREATQ_AUTH_MODE must be one of {sorted(VALID_AUTH_MODES)}")
    if not settings.THREATQ_MCP_AUTH_TOKEN:
        missing.append("THREATQ_MCP_AUTH_TOKEN")

    if settings.THREATQ_AUTH_MODE == "bearer":
        if not settings.THREATQ_TOKEN:
            missing.append("THREATQ_TOKEN (required when THREATQ_AUTH_MODE=bearer)")
    else:
        for name in ("THREATQ_CLIENT_ID", "THREATQ_EMAIL", "THREATQ_PASSWORD"):
            if not getattr(settings, name):
                missing.append(f"{name} (required when THREATQ_AUTH_MODE=oauth)")

    if missing:
        raise RuntimeError("refusing to start, unset required env: " + ", ".join(missing))
