#!/usr/bin/env python3
"""
Make soc-misp ready for the Backend: a read-only user with its own API key, and
the lab's indicators. Run after `docker compose up -d`. Standard library only.

    python3 setup.py                 # prints MISP_BASE_URL / MISP_API_KEY
    python3 setup.py --write-env     # also writes them into Backend/.env

Run it again and nothing doubles: an event already there (same title) is kept,
and the key in Backend/.env is reused while MISP still accepts it.

The events describe the lab's scenarios (Raw logs/ and gen_*.csv) the way a
threat-intelligence team would have them: what is known bad, with a verdict tag,
the event's threat level and a comment saying why — and a few known-good values,
so a false positive has something to be cleared by.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND_ENV = HERE.parents[2] / "Backend" / ".env"
# How the Backend worker reaches MISP: over soc-network, plain HTTP inside it.
INSIDE_URL = "http://soc-misp:8080"
SERVICE_EMAIL = "soc-ai@soc-lab.local"

MAL = 'soc-lab:verdict="malicious"'
SUS = 'soc-lab:verdict="suspicious"'
BENIGN = 'soc-lab:verdict="benign"'


def attr(type_: str, category: str, value: str, comment: str, verdict: str, to_ids: bool = True) -> dict:
    return {"type": type_, "category": category, "value": value, "comment": comment,
            "to_ids": to_ids, "Tag": [{"name": verdict}]}


EVENTS = [
    {
        "info": "SOC Lab - corp.local intrusion (24 Dec 2024)",
        "threat_level_id": "1", "analysis": "2", "date": "2024-12-24",
        "Tag": [{"name": "tlp:amber"}, {"name": 'misp-galaxy:threat-actor="Lab-APT"'}],
        "Attribute": [
            attr("ip-dst", "Network activity", "45.83.122.9",
                 "C2 server: HTTPS beacon about every 60 s; also serves /a.ps1 and /x.sh payloads", MAL),
            attr("url", "Network activity", "http://45.83.122.9/a.ps1",
                 "PowerShell stage downloaded by an encoded command started from a Word macro", MAL),
            attr("url", "Network activity", "http://45.83.122.9/x.sh",
                 "Shell script fetched with sudo wget after an SSH break-in", MAL),
            attr("domain", "Network activity", "exfil-dns.net",
                 "DNS tunnelling: long base32 labels in TXT queries carry the data out", MAL),
            attr("ip-src", "Network activity", "203.0.113.45",
                 "SSH brute force against internet-facing Linux servers; logged in as deploy", MAL),
        ],
    },
    {
        "info": "SOC Lab - KBTG-Bootcamp web intrusion (24 Dec 2024)",
        "threat_level_id": "2", "analysis": "2", "date": "2024-12-24",
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [
            attr("sha256", "Payload delivery", "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71",
                 "Service binary installed as jQTS (%systemroot%\\PKSnPlKq.exe): remote execution, PsExec-style", MAL),
            attr("filename", "Payload delivery", "PKSnPlKq.exe",
                 "Random 8-letter name of the remote-execution service binary", SUS),
            attr("ip-src", "Network activity", "192.168.56.129",
                 "Lab attacker host: feroxbuster directory scan, web shell use, then network logon", MAL),
        ],
    },
    {
        "info": "SOC Lab - known benign infrastructure",
        "threat_level_id": "4", "analysis": "2", "date": "2024-12-24",
        "Tag": [{"name": "tlp:green"}],
        "Attribute": [
            attr("ip-src", "Network activity", "198.51.100.165",
                 "Internet-wide SSH scanner: a few attempts, never a login; noise, not targeted", SUS, to_ids=False),
            attr("ip-dst", "Network activity", "142.250.4.100", "Google - ordinary office browsing", BENIGN, to_ids=False),
            attr("domain", "Network activity", "google.com", "Google - SPF and web lookups by the mail server", BENIGN, to_ids=False),
        ],
    },
]


def read_env(path: Path) -> dict[str, str]:
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


class Misp:
    def __init__(self, base: str, key: str) -> None:
        self.base, self.key = base.rstrip("/"), key

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        request = urllib.request.Request(
            self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": self.key, "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=60) as resp:
                text = resp.read().decode()
                status = resp.status
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode(errors="replace")
        try:
            return status, json.loads(text) if text else {}
        except json.JSONDecodeError:
            return status, text[:300]

    def must(self, what: str, method: str, path: str, body: dict | None = None) -> object:
        status, data = self.call(method, path, body)
        if status >= 300:
            sys.exit(f"{what}: MISP answered {status}: {str(data)[:400]}")
        return data

    def wait(self, seconds: int) -> str:
        print(f"waiting for MISP at {self.base} ", end="", flush=True)
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                status, data = self.call("GET", "/servers/getVersion")
                if status == 200 and isinstance(data, dict) and data.get("version"):
                    print(f" up — MISP {data['version']}")
                    return data["version"]
                if status in (401, 403):
                    sys.exit(f"\nMISP refused ADMIN_KEY ({status}). It is set on first start only: "
                             "recreate the volumes or use the key MISP has.")
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                pass
            print(".", end="", flush=True)
            time.sleep(5)
        sys.exit("\nMISP did not come up in time: docker compose logs soc-misp-core")


def service_key(admin: Misp, kept: str) -> str:
    """The read-only user's key: the one in Backend/.env while it still works, a new one otherwise."""
    if kept:
        status, data = Misp(admin.base, kept).call("GET", "/servers/getVersion")
        if status == 200 and isinstance(data, dict) and data.get("version"):
            print(f"read-only key          kept (Backend/.env)")
            return kept

    roles = admin.must("list roles", "GET", "/roles")
    read_only = next((r["Role"]["id"] for r in roles if r.get("Role", {}).get("name") == "Read Only"), None)
    if not read_only:
        sys.exit("no 'Read Only' role in MISP")

    users = admin.must("list users", "GET", "/admin/users")
    user = next((u["User"] for u in users if u.get("User", {}).get("email") == SERVICE_EMAIL), None)
    if user is None:
        me = admin.must("who am I", "GET", "/users/view/me")
        user = admin.must("create the read-only user", "POST", "/admin/users/add", {
            "email": SERVICE_EMAIL, "org_id": me["User"]["org_id"], "role_id": read_only,
            "change_pw": False, "disabled": False, "notify": False})["User"]
        print(f"read-only user         {SERVICE_EMAIL} created (role Read Only)")
    created = admin.must("create an auth key", "POST", f"/auth_keys/add/{user['id']}",
                         {"comment": "soc-core-worker: indicator lookups"})
    key = created.get("AuthKey", {}).get("authkey_raw")
    if not key:
        sys.exit(f"MISP did not return the new key: {str(created)[:300]}")
    print(f"read-only key          created for {SERVICE_EMAIL}")
    return key


def seed(admin: Misp) -> None:
    for event in EVENTS:
        found = admin.must("search events", "POST", "/events/restSearch",
                           {"returnFormat": "json", "eventinfo": event["info"], "metadata": True})
        if isinstance(found, dict) and found.get("response"):
            print(f"event                  kept: {event['info']}")
            continue
        made = admin.must("add event", "POST", "/events/add", {"Event": {**event, "distribution": "0"}})
        event_id = made["Event"]["id"]
        # Attribute-level verdict tags: /events/add takes them, but older versions
        # drop them, so they are attached explicitly.
        for a in made["Event"].get("Attribute", []):
            want = next(x for x in event["Attribute"] if x["value"].lower() == a["value"].lower())
            for tag in want["Tag"]:
                admin.call("POST", f"/attributes/addTag/{a['id']}/{tag['name']}/local:1")
        admin.must("publish", "POST", f"/events/publish/{event_id}")
        print(f"event                  added #{event_id}: {event['info']} ({len(event['Attribute'])} indicators)")


def write_env(path: Path, values: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    left = dict(values)
    for n, line in enumerate(lines):
        key = line.partition("=")[0].strip()
        if key in left and not line.lstrip().startswith("#"):
            lines[n] = f"{key}={left.pop(key)}"
    lines.extend(f"{key}={value}" for key, value in left.items())
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-env", action="store_true", help="write MISP_BASE_URL and MISP_API_KEY into Backend/.env")
    args = parser.parse_args()

    env = read_env(HERE / ".env")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", env.get("ADMIN_KEY", "")):
        sys.exit("ADMIN_KEY in external/misp/.env must be 40 hex characters (cp .env.example .env)")
    admin = Misp(f"http://127.0.0.1:{env.get('MISP_HTTP_PORT') or '8095'}", env["ADMIN_KEY"])
    admin.wait(900)

    key = service_key(admin, read_env(BACKEND_ENV).get("MISP_API_KEY", ""))
    seed(admin)

    check = Misp(admin.base, key).must("check the read-only key", "POST", "/attributes/restSearch",
                                       {"returnFormat": "json", "value": "45.83.122.9"})
    hits = len(check.get("response", {}).get("Attribute", []))
    print(f"read-only lookup       45.83.122.9 -> {hits} attribute(s)")

    values = {"MISP_BASE_URL": INSIDE_URL, "MISP_API_KEY": key}
    if args.write_env:
        write_env(BACKEND_ENV, values)
        print(f"wrote MISP_BASE_URL and MISP_API_KEY into {BACKEND_ENV}")
        print("then: cd Backend && docker compose up -d soc-core-api soc-core-worker")
    else:
        print("\nPut into Backend/.env:")
        print(f"MISP_BASE_URL={INSIDE_URL}")
        print("MISP_API_KEY=<printed only with --write-env, to keep it out of terminal logs>")


if __name__ == "__main__":
    main()
