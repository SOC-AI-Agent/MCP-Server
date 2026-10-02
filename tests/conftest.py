"""Loads the connector with a throwaway environment.

`connector("Splunk")` puts it on the path, imports its server with a throwaway
environment, and takes it all back out afterwards. (There used to be three; the
backend now calls ThreatQ and Confluence directly.)

Nothing here contacts a platform. The platform URLs point at a closed local
port, so anything that does reach for one fails at once instead of waiting on a
DNS lookup.
"""

import importlib
import sys
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
CONNECTORS = ("Splunk",)

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
CLOSED = "http://127.0.0.1:9"

# Distinct, long values for the credentials each connector holds, so a test can
# assert that none of them ever appears in an answer.
SECRETS = {
    "Splunk": "splunk-secret-value",
}

ENV = {
    "Splunk": {
        "MCP_AUTH_TOKEN": TOKEN,
        "SPLUNK_TOKEN": SECRETS["Splunk"],
        "SPLUNK_ALLOWED_INDEXES": "main",
        "SPLUNK_BASE_URL": CLOSED,
    },
}

# Every module name any connector defines, so one connector's config.py is
# never mistaken for the next one's.
_OWN_MODULES = {
    path.stem for name in CONNECTORS for path in (ROOT / name).glob("*.py")
}


def _forget_connectors() -> None:
    for module in _OWN_MODULES:
        sys.modules.pop(module, None)


class Platform:
    """Stands in for the external platform. Every outgoing call a connector
    makes lands here, so nothing leaves the process and a test decides what the
    platform said."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = lambda request: httpx.Response(500)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def answer(self, response: httpx.Response) -> None:
        """The same reply to everything."""
        self._handler = lambda request: response

    def by_path(self, table: dict, default: httpx.Response | None = None) -> None:
        """A reply per URL path. A value that is an exception is raised, which is
        how a host that does not answer looks to the caller; one that is a function
        is called with the request, for a path that is asked more than one thing."""

        def handler(request: httpx.Request):
            reply = table.get(request.url.path, default or httpx.Response(404))
            if isinstance(reply, Exception):
                raise reply
            if callable(reply):
                return reply(request)
            return reply

        self._handler = handler


@pytest.fixture
def platform(monkeypatch):
    """Request this before `connector` or `client`: Splunk and ThreatQ build
    their HTTP client when the module is imported, so the swap has to be in
    place by then."""
    fake = Platform()
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fake)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return fake


@pytest.fixture
def connector(monkeypatch, tmp_path):
    """`connector("Splunk")` -> that connector's imported server module.
    Keyword arguments override the throwaway environment."""

    def load(name: str, **env):
        _forget_connectors()
        for key, value in {**ENV[name], **env}.items():
            monkeypatch.setenv(key, value)
        # Settings also read ./.env. Run from an empty directory so a real one
        # in the working directory can never leak into a test.
        monkeypatch.chdir(tmp_path)
        monkeypatch.syspath_prepend(str(ROOT / name))
        return importlib.import_module("server")

    yield load
    _forget_connectors()


@pytest.fixture
def client(connector):
    """`client("Splunk")` -> a test client. A crash comes back as a 500 to be
    asserted on, not as an exception thrown into the test."""

    def make(name: str, **env) -> TestClient:
        return TestClient(connector(name, **env).app, raise_server_exceptions=False)

    return make
