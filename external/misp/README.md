# soc-misp — threat intelligence for the lab

[MISP](https://www.misp-project.org/) is an open-source threat-intelligence
platform (TIP), the free counterpart of ThreatQ. This stack runs one with the
lab's indicators in it, so the Backend can say *what is known* about an IP,
domain, URL or hash before the model writes a verdict.

```
alert → Backend worker → POST http://soc-misp:8080/attributes/restSearch (read-only key)
                       → "THREAT INTELLIGENCE (MISP)" block in the prompt
```

When `MISP_BASE_URL` and `MISP_API_KEY` are set in `Backend/.env`, MISP is used
**in place of** ThreatQ. Blank, the Backend falls back to ThreatQ (or to "NOT
CHECKED" when neither is configured).

## Run

```bash
cd MCP-Server/external/misp
cp .env.example .env              # fill every secret (openssl rand -hex 16 / -hex 20 for ADMIN_KEY)
docker compose up -d              # first start takes a few minutes (schema, warninglists)
python3 setup.py --write-env      # read-only user + lab IOCs; writes MISP_* into Backend/.env
cd ../../../Backend && docker compose up -d soc-core-api soc-core-worker
```

`setup.py` is safe to run again: events already there are kept, and the key in
`Backend/.env` is reused while MISP still accepts it.

| What | Where |
| --- | --- |
| Web UI | http://localhost:8095 — `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env` |
| API from the Backend | `http://soc-misp:8080` over `soc-network` |
| Backend's user | `soc-ai@soc-lab.local`, role **Read Only**, its own auth key |

The admin key (`ADMIN_KEY`) is used by `setup.py` only. The Backend gets the
read-only user's key, so a leaked Backend `.env` cannot change MISP.

## What is loaded

Three events, each attribute tagged with a verdict (`soc-lab:verdict="..."`),
a comment saying why, and the event's threat level:

| Event | Indicators |
| --- | --- |
| SOC Lab - corp.local intrusion (High) | `45.83.122.9` C2, its `/a.ps1` and `/x.sh` URLs, `exfil-dns.net` DNS tunnel, `203.0.113.45` SSH brute force — actor `Lab-APT` |
| SOC Lab - KBTG-Bootcamp web intrusion (Medium) | SHA256 of `PKSnPlKq.exe`, the file name, `192.168.56.129` lab attacker |
| SOC Lab - known benign infrastructure (Undefined) | `198.51.100.165` SSH scanner (suspicious, noise), `142.250.4.100` and `google.com` (benign) |

They match the scenarios in `Splunk/Raw logs/` and the simulator alerts
`FSR-LAB-001`..`042`: a true positive finds its indicator here as malicious, a
false positive finds it benign or not at all. "Not found" means never seen —
the prompt says so as UNKNOWN, never as clean.

Add your own in the web UI (Event Actions → Add Event); the Backend sees them on
the next alert, no sync needed.

## Notes

- Trimmed from [misp-docker](https://github.com/MISP/misp-docker), images pinned
  to `MISP_TAG` (`v2.5.51`): no mail relay, misp-modules or misp-guard, and a
  256 MB InnoDB buffer. About 1.5 GB of RAM in all.
- Plain HTTP: reached over `soc-network`, and from this machine on 127.0.0.1
  only. On a VPS, open the UI through an SSH tunnel rather than the firewall.
- No feeds are fetched. To add public feeds: Sync Actions → Feeds → load the
  defaults, enable a few, Fetch.
- Start over: `docker compose down -v` (the `ADMIN_KEY` is applied on first start only).
