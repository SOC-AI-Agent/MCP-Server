#!/usr/bin/env python3
"""
Make the soc-splunk container usable by soc-mcp-splunk. Run after `docker compose up -d`.

    python3 setup.py                # everything; prints the lines for MCP-Server/.env
    python3 setup.py --write-env    # ...and writes them into MCP-Server/.env
    python3 setup.py --seed-only    # only add fresh sample events

What it does, as admin, over the management port published on this machine:

    1. waits for Splunk to answer (the first start takes a few minutes)
    2. turns token authentication on
    3. creates a search-only role confined to the index, and a service user with it
    4. creates an authentication token for that user — this is SPLUNK_TOKEN
    5. indexes the sample events (the same estate SPLUNK_MODE=mock answers from)

Safe to run again: what exists is kept, a new token is made each time, and the
sample events are added again with fresh times (they are built relative to now,
and searches look at the last 24 hours — re-seed when the old ones have aged out).

Standard library only. The admin password comes from .env beside this file and is
used here and nowhere else.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MCP_SERVER = HERE.parent.parent

INDEX = "main"
SOURCETYPE = "fortigate"
ROLE = "soc_search"
USER = "soc-mcp"
# How soc-mcp-splunk reaches the container, over soc-network.
INSIDE_URL = "https://soc-splunk:8089"

# The container's certificate is self-signed.
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE


def read_env(path: Path) -> dict[str, str]:
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


class Splunk:
    def __init__(self, base: str, password: str) -> None:
        self.base = base.rstrip("/")
        self._auth = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()

    def call(self, method: str, path: str, data: dict | None = None, raw: bytes | None = None,
             query: dict | None = None) -> tuple[int, dict | str]:
        url = f"{self.base}{path}?" + urllib.parse.urlencode({"output_mode": "json", **(query or {})})
        body = raw if raw is not None else (
            urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
        )
        request = urllib.request.Request(url, data=body, method=method, headers={"Authorization": self._auth})
        try:
            with urllib.request.urlopen(request, context=_TLS, timeout=60) as resp:
                status, text = resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode()
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    def must(self, what: str, method: str, path: str, ok: tuple[int, ...] = (200, 201), **kwargs) -> dict | str:
        status, body = self.call(method, path, **kwargs)
        if status not in ok:
            sys.exit(f"FAILED to {what}: {status} {str(body)[:400]}")
        return body

    def wait(self, seconds: int) -> None:
        print(f"waiting for Splunk at {self.base} ", end="", flush=True)
        deadline = time.monotonic() + seconds
        server_up = False
        while True:
            try:
                if not server_up:
                    status, body = self.call("GET", "/services/server/info")
                    if status == 200:
                        server_up = True
                        print(f" up — Splunk {body['entry'][0]['content']['version']}", end="", flush=True)
                    elif status == 401:
                        sys.exit("\nFAILED: Splunk refused the admin password. SPLUNK_PASSWORD in .env is only "
                                 "applied on the first start; `docker compose down -v` starts over.")
                if server_up:
                    kv_status, kv_body = self.call("GET", "/services/kvstore/status")
                    if kv_status == 200:
                        state = kv_body.get("entry", [{}])[0].get("content", {}).get("current", {}).get("status", "")
                        if state and state != "starting":
                            print(f" (kvstore {state})")
                            return
                    elif kv_status in (404, 501):
                        print()
                        return
            except (urllib.error.URLError, OSError, KeyError, TypeError):
                pass
            if time.monotonic() > deadline:
                sys.exit(f"\nFAILED: not ready in {seconds}s. `docker compose logs -f soc-splunk` shows where it is.")
            print(".", end="", flush=True)
            time.sleep(5)


def create_account(splunk: Splunk) -> str:
    splunk.must("turn token authentication on", "POST",
                "/services/admin/token-auth/tokens_auth", data={"disabled": "false"})
    print("token authentication  on")

    # Search only, and only this index — the same confinement SPLUNK_ALLOWED_INDEXES
    # asks for, enforced by Splunk as well.
    role = {"imported_roles": "user", "srchIndexesAllowed": INDEX, "srchIndexesDefault": INDEX}
    status, _ = splunk.call("GET", f"/services/authorization/roles/{ROLE}")
    if status == 200:
        splunk.must("update the role", "POST", f"/services/authorization/roles/{ROLE}", data=role)
    else:
        splunk.must("create the role", "POST", "/services/authorization/roles", data={"name": ROLE, **role})
    print(f"role                  {ROLE} (search, index={INDEX})")

    status, _ = splunk.call("GET", f"/services/authentication/users/{USER}")
    if status != 200:
        # Nobody signs in as this user; the token is how it is used.
        splunk.must("create the user", "POST", "/services/authentication/users",
                    data={"name": USER, "password": secrets.token_urlsafe(24), "roles": ROLE})
    else:
        splunk.must("update the user", "POST", f"/services/authentication/users/{USER}", data={"roles": ROLE})
    print(f"user                  {USER}")

    deadline = time.monotonic() + 180
    while True:
        status, made = splunk.call("POST", "/services/authorization/tokens",
                                   data={"name": USER, "audience": "soc-mcp-splunk", "expires_on": "+90d"})
        if status in (200, 201):
            break
        if status == 503 and time.monotonic() < deadline:
            time.sleep(5)
            continue
        sys.exit(f"FAILED to create the token: {status} {str(made)[:400]}")
    print("token                 created, expires in 90 days")
    return made["entry"][0]["content"]["token"]


def seed(splunk: Splunk) -> int:
    # The estate mock mode answers from, so a question has the same answer either way.
    sys.path.insert(0, str(MCP_SERVER / "Splunk"))
    import mock  # noqa: PLC0415 — standard library only, like this script

    lines = []
    for event in mock._events():
        fields = {k: v for k, v in event.items() if k not in ("_time", "_raw", "index", "sourcetype")}
        pairs = " ".join(f'{k}="{v}"' if " " in v else f"{k}={v}" for k, v in fields.items())
        # The time first, in a form Splunk recognises on its own; the rest is
        # key=value, which it extracts at search time.
        lines.append(f"{event['_time']} devname=FGT-01 {pairs}")
    splunk.must("index the sample events", "POST", "/services/receivers/stream", ok=(200, 204),
                raw="\n".join(lines).encode(),
                query={"index": INDEX, "sourcetype": SOURCETYPE, "host": "FGT-01", "source": "soc-sample"})
    print(f"sample events         {len(lines)} into index={INDEX} sourcetype={SOURCETYPE}")
    return len(lines)


def write_env(path: Path, values: dict[str, str]) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    left = dict(values)
    for n, line in enumerate(lines):
        key = line.partition("=")[0].strip()
        if key in left and not line.lstrip().startswith("#"):
            lines[n] = f"{key}={left.pop(key)}"
    lines.extend(f"{key}={value}" for key, value in left.items())
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write-env", action="store_true",
                        help="write the connection into MCP-Server/.env instead of only printing it")
    parser.add_argument("--seed-only", action="store_true", help="only add fresh sample events")
    parser.add_argument("--wait", type=int, default=600, help="seconds to wait for Splunk (default 600)")
    args = parser.parse_args()

    env = read_env(HERE / ".env")
    password = env.get("SPLUNK_PASSWORD", "")
    if not password:
        sys.exit("SPLUNK_PASSWORD is not set in external/splunk/.env (cp .env.example .env)")
    splunk = Splunk(f"https://127.0.0.1:{env.get('SPLUNK_MGMT_PORT') or '8089'}", password)

    splunk.wait(args.wait)
    if args.seed_only:
        seed(splunk)
        return
    token = create_account(splunk)
    seed(splunk)

    values = {
        "SPLUNK_MODE": "live",
        "SPLUNK_BASE_URL": INSIDE_URL,
        "SPLUNK_TOKEN": token,
        "SPLUNK_ALLOWED_INDEXES": INDEX,
        # The container's certificate is self-signed. Never for the company's Splunk.
        "SPLUNK_VERIFY_SSL": "false",
        # Not Splunk ES: no notable index. Nothing fires alerts here.
        "SPLUNK_SAIA_MCP_URL": "",
    }
    target = MCP_SERVER / ".env"
    if args.write_env:
        write_env(target, values)
        print(f"\nwrote the connection into {target}")
    else:
        print(f"\nPut these in {target} (or run again with --write-env):\n")
        for key, value in values.items():
            print(f"{key}={value}")
    print("\nThen: cd ../.. && docker compose up -d --build   # soc-mcp-splunk, now live")
    print("Check: GET /check-connection on soc-mcp-splunk (README.md)")


if __name__ == "__main__":
    main()
