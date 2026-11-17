#!/usr/bin/env python3
"""
Index the lab's raw logs (../../Splunk/Raw logs/*.csv) into soc-splunk. Run after setup.py.

    python3 load_raw_logs.py

Each CSV is a Splunk export of `_raw` only: one event per row, no header. They go
into index=main — the only index the soc_search role can search — under:

    splunk_logs_apache.csv       sourcetype=access_combined   (Splunk's own)
    splunk_logs_sysmon.csv       sourcetype=sysmon            (defined here)
    splunk_logs_wineventlog.csv  sourcetype=wineventlog       (defined here)

and the synthetic scenarios from generate_logs.py (gen_*.csv):

    gen_wineventlog_auth.csv     sourcetype=wineventlog       4625 / 4624 on FS-01
    gen_linux_secure.csv         sourcetype=linux_secure      sshd and sudo on web-02 (defined here)
    gen_fortigate.csv            sourcetype=fortigate         key=value, extracted at search time
    gen_dns.csv                  sourcetype=bind_query        BIND query log of ns-01 (defined here)
    gen_sysmon.csv               sourcetype=sysmon            WS-12 and FS-01 (host is in Computer)

A plain Splunk container has no Sysmon, Windows or Unix add-on, so the
sourcetypes defined here carry the minimum those add-ons would: where an event
ends, where its time is, and the field extractions
Backend/catalog/splunk-catalog.json names.

Events keep their own times (24 Dec 2024), so a search needs a window that
reaches them. A file whose events are already indexed (same sourcetype and
source) is skipped: run it twice and nothing doubles.
"""

from __future__ import annotations

import csv
import sys
import time
import zipfile
from pathlib import Path

from setup import HERE, INDEX, MCP_SERVER, Splunk, read_env

LOGS = MCP_SERVER / "Splunk" / "Raw logs"
LOGS_ZIP = MCP_SERVER / "Splunk" / "Raw_logs.zip"
HOST = "KBTG-Bootcamp"
APP = "/servicesNS/nobody/search"

# file, sourcetype, host. The Apache log does not name its server.
FILES = [
    ("splunk_logs_apache.csv", "access_combined", "apache"),
    ("splunk_logs_sysmon.csv", "sysmon", HOST),
    ("splunk_logs_wineventlog.csv", "wineventlog", HOST),
    ("gen_wineventlog_auth.csv", "wineventlog", "FS-01"),
    ("gen_linux_secure.csv", "linux_secure", "web-02"),
    ("gen_fortigate.csv", "fortigate", "FGT-01"),
    ("gen_dns.csv", "bind_query", "ns-01"),
    ("gen_sysmon.csv", "sysmon", "corp-endpoints"),
]

TRANSFORMS = {
    # <Data Name='Image'>C:\...</Data>  ->  Image=C:\...
    "sysmon_data": {"REGEX": r"<Data Name='([^']+)'>([^<]*)</Data>", "FORMAT": "$1::$2", "MV_ADD": "true"},
    # "\tAccount Name:\t\tSYSTEM"  ->  Account_Name=SYSTEM (twice in a 4624: subject, then the logon)
    "wineventlog_message": {"REGEX": r"(?m)^[ \t]*([A-Za-z][A-Za-z ]*[A-Za-z]):[ \t]+(\S[^\r\n]*?)[ \t]*$",
                            "FORMAT": "$1::$2", "MV_ADD": "true", "CLEAN_KEYS": "true"},
}
PROPS = {
    "sysmon": {
        "SHOULD_LINEMERGE": "false", "TRUNCATE": "0", "KV_MODE": "none",
        "TIME_PREFIX": "SystemTime='", "MAX_TIMESTAMP_LOOKAHEAD": "40", "TZ": "UTC",
        "REPORT-sysmon_data": "sysmon_data",
        "EXTRACT-eventcode": r"<EventID>(?<EventCode>\d+)</EventID>",
        "EXTRACT-computer": r"<Computer>(?<Computer>[^<]+)</Computer>",
        # Hashes is "SHA256=..." in this Sysmon config.
        "EXTRACT-sha256": r"SHA256=(?<SHA256>[0-9A-Fa-f]{64})",
    },
    "wineventlog": {
        "SHOULD_LINEMERGE": "false", "TRUNCATE": "0",
        "LINE_BREAKER": r"([\r\n]+)(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M)",
        "TIME_FORMAT": "%m/%d/%Y %I:%M:%S %p", "MAX_TIMESTAMP_LOOKAHEAD": "25",
        # The export has no zone; Sysmon's UTC times put this machine at UTC-8.
        "TZ": "US/Pacific",
        "REPORT-wineventlog_message": "wineventlog_message",
    },
    "linux_secure": {
        "SHOULD_LINEMERGE": "false", "TIME_FORMAT": "%Y-%m-%dT%H:%M:%S%:z", "MAX_TIMESTAMP_LOOKAHEAD": "30",
        "EXTRACT-process": r"^\S+ \S+ (?<process>[\w.-]+)(?:\[(?<pid>\d+)\])?:",
        "EXTRACT-sshd": r"sshd\[\d+\]: (?<action>Failed|Accepted) (?<auth_method>\S+) for (?:invalid user )?"
                        r"(?<user>\S+) from (?<src>\S+) port (?<src_port>\d+)",
        "EXTRACT-sudo": r"sudo:\s+(?<user>\S+) : .*?USER=(?<target_user>\S+) ; COMMAND=(?<command>.+)$",
    },
    "bind_query": {
        "SHOULD_LINEMERGE": "false", "TIME_FORMAT": "%d-%b-%Y %H:%M:%S.%3N", "MAX_TIMESTAMP_LOOKAHEAD": "25",
        "TZ": "UTC",
        "EXTRACT-query": r"client @\S+ (?<src>[\d.]+)#(?<src_port>\d+) \([^)]*\): query: (?<query>\S+) IN (?<record_type>\w+)",
    },
}


def define(splunk: Splunk, conf: str, name: str, settings: dict[str, str]) -> None:
    status, _ = splunk.call("GET", f"{APP}/configs/conf-{conf}/{name}")
    if status == 200:
        splunk.must(f"update {conf} [{name}]", "POST", f"{APP}/configs/conf-{conf}/{name}", data=settings)
    else:
        splunk.must(f"create {conf} [{name}]", "POST", f"{APP}/configs/conf-{conf}", data={"name": name, **settings})
    # Global: soc-mcp searches from whatever app its token lands in.
    splunk.must(f"share {conf} [{name}]", "POST", f"{APP}/configs/conf-{conf}/{name}/acl",
                data={"sharing": "global", "owner": "nobody"})


def count(splunk: Splunk, sourcetype: str, source: str = "*") -> int:
    body = splunk.must("count events", "POST", "/services/search/jobs", data={
        "search": f'| tstats count where index={INDEX} sourcetype={sourcetype} source="{source}"',
        "exec_mode": "oneshot", "earliest_time": "0", "latest_time": "now"})
    rows = body.get("results", []) if isinstance(body, dict) else []
    return int(rows[0]["count"]) if rows else 0


def load(splunk: Splunk, path: Path, sourcetype: str, host: str) -> int:
    sent, batch, size = 0, [], 0
    query = {"index": INDEX, "sourcetype": sourcetype, "host": host, "source": path.name}

    def flush() -> None:
        nonlocal batch, size
        if batch:
            splunk.must(f"index {path.name}", "POST", "/services/receivers/stream", ok=(200, 204),
                        raw=("\n".join(batch) + "\n").encode(), query=query)
            batch, size = [], 0

    csv.field_size_limit(10**9)
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip():
                continue
            batch.append(row[0].replace("\r\n", "\n"))
            size += len(row[0])
            sent += 1
            if size > 8_000_000:
                flush()
                print(f"  {path.name}: {sent}", flush=True)
    flush()
    return sent


def main() -> None:
    env = read_env(HERE / ".env")
    if not env.get("SPLUNK_PASSWORD"):
        sys.exit("SPLUNK_PASSWORD is not set in external/splunk/.env (cp .env.example .env)")
    splunk = Splunk(f"https://127.0.0.1:{env.get('SPLUNK_MGMT_PORT') or '8089'}", env["SPLUNK_PASSWORD"])
    splunk.wait(600)

    for name, settings in TRANSFORMS.items():
        define(splunk, "transforms", name, settings)
    for name, settings in PROPS.items():
        define(splunk, "props", name, settings)

    if LOGS_ZIP.exists() and any(not (LOGS / f).exists() for f, _, _ in FILES):
        with zipfile.ZipFile(LOGS_ZIP) as zf:
            zf.extractall(LOGS_ZIP.parent)
        print(f"extracted {LOGS_ZIP.name} -> {LOGS}")

    for filename, sourcetype, host in FILES:
        path = LOGS / filename
        if not path.exists():
            print(f"{filename}: not in {LOGS}, skipped")
            continue
        have = count(splunk, sourcetype, filename)
        if have:
            print(f"{filename}: already has {have} events in sourcetype={sourcetype}, skipped")
            continue
        sent = load(splunk, path, sourcetype, host)
        print(f"{filename}: {sent} events sent to index={INDEX} sourcetype={sourcetype}")

    time.sleep(15)  # indexing is behind the last POST
    for filename, sourcetype, _ in FILES:
        print(f"index={INDEX} sourcetype={sourcetype} source={filename}: {count(splunk, sourcetype, filename)} events")


if __name__ == "__main__":
    main()
