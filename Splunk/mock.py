"""
A stand-in for Splunk behind its own MCP server, for development (SPLUNK_MODE=mock).

Splunk's MCP Server app turns a natural-language request into SPL with
`saia_generate_spl` (Splunk AI Assistant for SPL) and runs SPL with
`splunk_run_query`. This module does both against a small, fixed set of events, so
the backend's whole Text-to-SPL path can run with no Splunk at all.

Nothing here is clever on purpose. The SPL it writes is a template filled with the
values it finds in the request, and the search it runs understands index=,
sourcetype=, quoted values, `| table`, `| stats count by` and `| head` — enough to
answer the questions the requirements agent asks about an alert, and obviously not
Splunk. Every answer says `mock: true`.
"""

# So setup.py in external/splunk can import this with an older system python3.
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import text_to_spl
from text_to_spl import _IPV4

INDEX = "main"
SOURCETYPE = "fortigate"


def _events() -> list[dict]:
    """The estate: one FortiGate index, built relative to now so every event falls
    inside the default 24-hour window."""
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def at(minutes_ago: int) -> str:
        return (now - timedelta(minutes=minutes_ago)).isoformat()

    rows: list[dict] = []

    def add(minutes_ago: int, **fields: str) -> None:
        raw = " ".join(f'{k}="{v}"' if " " in v else f"{k}={v}" for k, v in fields.items())
        rows.append({"_time": at(minutes_ago), "index": INDEX, "sourcetype": SOURCETYPE,
                     **fields, "_raw": f"date={at(minutes_ago)[:10]} {raw}"})

    # An external address hammering the SSL VPN, then one success.
    for i, user in enumerate(["j.smith"] * 6 + ["admin"] * 3 + ["j.smith"]):
        add(95 - i * 4, type="event", subtype="vpn", srcip="45.83.122.9", dstip="203.0.113.10",
            dstport="443", user=user, action="ssl-login-fail" if i < 9 else "tunnel-up",
            msg="SSL user failed to logged in" if i < 9 else "SSL tunnel established")
    # An internal host talking out after the VPN session came up.
    for i, (dst, port, app) in enumerate([
        ("23.59.154.35", "80", "HTTP.BROWSER_Firefox"),
        ("44.215.36.185", "443", "SSL"),
        ("44.215.36.185", "443", "SSL"),
        ("44.215.36.185", "8443", "SSL"),
        ("185.220.101.4", "9001", "Tor"),
        ("10.1.100.20", "445", "SMB"),
        ("10.1.100.21", "445", "SMB"),
        ("10.1.100.22", "445", "SMB"),
    ]):
        add(50 - i * 3, type="traffic", subtype="forward", srcip="10.1.100.11", dstip=dst,
            dstport=port, app=app, user="j.smith",
            action="blocked" if dst == "185.220.101.4" else "close")
    # Background noise from other hosts.
    for i, (src, dst) in enumerate([
        ("10.1.100.44", "8.8.8.8"), ("10.1.100.44", "1.1.1.1"),
        ("10.1.100.52", "52.96.0.1"), ("10.1.100.52", "52.96.0.2"),
    ]):
        add(30 - i * 5, type="traffic", subtype="forward", srcip=src, dstip=dst,
            dstport="53" if dst in ("8.8.8.8", "1.1.1.1") else "443", action="close")
    return rows


# ── Text to SPL ────────────────────────────────────────────────────────────────

def generate_spl(prompt: str) -> dict:
    """What `saia_generate_spl` would hand back: the SPL, and how it was arrived at."""
    return text_to_spl.generate(prompt, mock=True)


# ── Running SPL ────────────────────────────────────────────────────────────────

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_KV = re.compile(r'\b(index|sourcetype|earliest|latest)\s*=\s*"?([^\s"|)]+)"?', re.IGNORECASE)


def run_query(query: str, limit: int) -> list[dict]:
    """Run SPL against the mock estate, as far as this module understands SPL."""
    base, *pipes = [p.strip() for p in query.split("|")]
    named = {k.lower(): v for k, v in _KV.findall(base)}
    reserved = set(named.values())
    values = [v for v in _QUOTED.findall(_KV.sub("", base)) if v and v not in reserved]
    values += [v for v in _IPV4.findall(_KV.sub("", base)) if v not in values]

    rows = [
        e for e in _events()
        if e["index"] == named.get("index", e["index"])
        and e["sourcetype"] == named.get("sourcetype", e["sourcetype"])
        and (not values or any(v in e["_raw"] for v in values))
    ]

    for pipe in pipes:
        command, _, args = pipe.partition(" ")
        command = command.lower()
        if command == "table" or command == "fields":
            keep = [f.strip() for f in args.replace(",", " ").split() if f.strip()]
            if "*" not in keep:
                rows = [{f: r[f] for f in keep if f in r} for r in rows]
        elif command == "stats" and " by " in f" {args} ":
            by = [f.strip() for f in args.split(" by ", 1)[1].replace(",", " ").split()]
            counts: dict[tuple, int] = {}
            for r in rows:
                key = tuple(r.get(f, "") for f in by)
                counts[key] = counts.get(key, 0) + 1
            rows = [{**dict(zip(by, key)), "count": str(n)} for key, n in counts.items()]
        elif command == "sort" and args.strip().startswith("-"):
            field = args.strip()[1:].strip()
            rows.sort(key=lambda r: int(r.get(field, 0) or 0), reverse=True)
        elif command == "head":
            try:
                rows = rows[: int(args.strip() or 10)]
            except ValueError:
                pass
    return rows[:limit]


def indexes() -> list[str]:
    return sorted({e["index"] for e in _events()})
