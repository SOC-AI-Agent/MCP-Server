
import sys

if sys.version_info < (3, 12):
    raise SystemExit(
        f"needs Python 3.12 (the version the services run), found "
        f"{sys.version.split()[0]}.\n"
        "macOS ships 3.9 as python3; use the project venv:\n"
        "  python3.12 -m venv .venv && .venv/bin/python -m pip install -q -r scripts/requirements.txt\n"
        "  .venv/bin/python " + " ".join(sys.argv)
    )
#!/usr/bin/env python3
"""
Group a Splunk catalogue into query agents, one per data domain.

An analysing agent should not choose between two hundred sourcetypes, and no
prompt holds them. So sourcetypes are grouped the way a Tier 1 analyst thinks —
network, endpoint, identity, email, alerts — and each group gets its own query
agent whose prompt covers only its own data.

    curl -s "$MCP/catalog?values=true" -H "Authorization: Bearer $TOKEN" \\
      | python3 scripts/plan_query_agents.py -o build/

Writes a catalogue slice and an agent definition per domain, and a report
saying what went where, what was ambiguous, and whether any domain's prompt is
too large to be one agent.

It classifies from field names and sourcetype names, which is a guess. Every
assignment it is not sure about is listed for review — the same bargain as the
role guesses in make_catalog_template.py, and for the same reason: a name is
evidence, not a decision.
"""

import argparse
import json
import re
from pathlib import Path

# ── Where the domains come from ─────────────────────────────────────────────
#
# These five are written here, not learned. They are how SOC teams already
# divide their work, and a fixed taxonomy is explainable: you can read why a
# sourcetype landed where it did, which an embedding cannot tell you.
#
# They are also a guess about YOUR estate. One with OT, cloud audit or database
# logs needs domains that are not here. Two ways out:
#
#   --domains mine.json   replace or extend this table without touching code
#   --discover            ignore it and group by what the data actually shares
#
# A domain is defined by the questions it answers, not by vendor or index.
# `fields` and `roles` are matched against what the sourcetype actually carries;
# `name` against the sourcetype's own name. Weights say how much each is worth:
# a field called `parent_process` is near-proof of endpoint data, while `user`
# appears nearly everywhere and means almost nothing on its own.
DOMAINS: dict[str, dict] = {
    "network": {
        "asks": "what a host or address connected to",
        "roles": {"src_ip": 3, "dest_ip": 3, "dest_port": 2},
        # Address fields are matched by name as well as by role: a raw /catalog
        # export carries no roles, and a sourcetype full of addresses under an
        # unfamiliar vendor name would otherwise score nothing here.
        "fields": {"src_ip": 3, "dest_ip": 3, "srcip": 3, "dstip": 3,
                   "source_ip": 3, "destination_ip": 3, "clientip": 3, "c_ip": 3,
                   "dstport": 2, "dest_port": 2, "bytes_out": 2, "bytes_in": 2,
                   "protocol": 1, "proto": 1, "service": 1, "url": 2, "uri": 2,
                   "http_method": 2, "dns_query": 3, "query": 1, "answer": 1,
                   "sentbyte": 2, "rcvdbyte": 2, "dstcountry": 2},
        "name": {r"firewall|fortigate|palo|asa|checkpoint|fw": 4,
                 r"proxy|bluecoat|squid|zscaler|websense": 4,
                 r"dns|bind|infoblox": 4,
                 r"netflow|flow|ipfix|conn": 3,
                 r"ids|ips|suricata|snort|zeek|bro": 3},
    },
    "endpoint": {
        "asks": "what ran on a machine, and which files were involved",
        "roles": {"hash": 3},
        "fields": {"process_name": 4, "parent_process": 4, "parent_process_name": 4,
                   "process_id": 2, "command_line": 4, "image": 2, "process_exec": 3,
                   "file_hash": 3, "md5": 2, "sha1": 2, "sha256": 2, "imphash": 3,
                   "file_path": 2, "filename": 1, "registry_path": 4,
                   "service_name": 2, "signature": 1},
        "name": {r"edr|sysmon|carbonblack|crowdstrike|sentinelone|defender": 4,
                 r"osquery|winevent|wineventlog|xmlwineventlog": 3,
                 r"\bav\b|antivirus|symantec|mcafee": 3},
    },
    "identity": {
        "asks": "who signed in, from where, and whether it worked",
        "roles": {"user": 2},
        "fields": {"logon_type": 4, "authentication": 3, "auth_method": 3,
                   "src_user": 2, "user_agent": 1, "account_name": 3,
                   "samaccountname": 4, "session_id": 2, "mfa": 3,
                   "failure_reason": 3, "privileged": 3},
        "name": {r"\bad\b|active_?directory|ldap|kerberos": 4,
                 r"okta|azure_?ad|entra|adfs|saml|oauth": 4,
                 r"vpn|radius|tacacs": 3,
                 r"auth|login|logon|sudo|pam": 3},
    },
    "email": {
        "asks": "who received a message, and what it carried",
        "roles": {"domain": 1},
        "fields": {"sender": 4, "recipient": 4, "mail_from": 4, "rcpt_to": 4,
                   "subject": 4, "message_id": 4, "attachment": 3,
                   "spam_score": 3, "dkim": 3, "spf": 3},
        "name": {r"o365|office365|exchange|smtp|mail": 4,
                 r"proofpoint|mimecast|ironport|barracuda": 4},
    },
    "alert": {
        "asks": "how often a detection has fired",
        "roles": {},
        "fields": {"search_name": 4, "rule_name": 4, "rule_id": 3,
                   "urgency": 3, "risk_score": 3, "disposition": 2,
                   "owner": 1, "notable": 4},
        "name": {r"notable|correlation|risk|incident|case": 4,
                 r"alert|detection": 3},
    },
}

# A sourcetype lands in a domain when it scores this well, so one carrying both
# network and identity signals — a VPN log — reaches both. Splitting it in two
# would lose exactly the question it answers best.
ASSIGN_THRESHOLD = 4
# Below this, the top score is not convincing enough to act on unreviewed.
CONFIDENT = 7

# What a sourcetype costs in an agent's prompt: its name, a line of purpose, and
# a line of roles. Measured against the generated prompts, close enough to
# decide whether a domain needs splitting.
LINES_PER_SOURCETYPE = 3
CHARS_PER_LINE = 70
# A prompt should not eat more than a third of the window: the alert, the tool
# schemas and several rounds of results share what is left.
PROMPT_BUDGET_FRACTION = 1 / 3


def score(name: str, fields: list[str], roles: dict, index: str = "") -> dict[str, int]:
    # The index name is often the clearest signal there is — `netflow/ipfix`
    # says network through the index, not the sourcetype — so both are matched,
    # with the index worth slightly less because index layout follows retention
    # and access control as much as meaning.
    lower_name = f"{name} {index}".lower()
    lower_fields = {f.lower() for f in fields}
    out: dict[str, int] = {}

    for domain, spec in DOMAINS.items():
        total = 0
        for field, weight in spec["fields"].items():
            if field in lower_fields:
                total += weight
        for role, weight in spec["roles"].items():
            if roles.get(role):
                total += weight
        for pattern, weight in spec["name"].items():
            if re.search(pattern, name.lower()):
                total += weight
            elif index and re.search(pattern, index.lower()):
                total += max(weight - 1, 1)
        if total:
            out[domain] = total
    return out


def classify(name: str, fields: list[str], roles: dict,
             index: str = "") -> tuple[list[str], dict, bool]:
    """(domains, scores, confident)."""
    scores = score(name, fields, roles, index)
    if not scores:
        return [], scores, False

    best = max(scores.values())
    hit = sorted([d for d, s in scores.items() if s >= ASSIGN_THRESHOLD],
                 key=lambda d: -scores[d])
    return hit, scores, best >= CONFIDENT


# Fields every sourcetype carries. Two logs sharing only `host` and `_time`
# share nothing, and leaving them in makes everything look related.
UBIQUITOUS = {"host", "source", "sourcetype", "_time", "_raw", "index",
              "splunk_server", "linecount", "punct", "eventtype", "tag",
              "date_hour", "date_mday", "date_minute", "date_month",
              "date_second", "date_wday", "date_year", "date_zone", "timestamp"}


def jaccard(a: set, b: set) -> float:
    """How much two sourcetypes' field sets overlap, 0 to 1."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def discover(rows: list[dict], threshold: float) -> list[list[dict]]:
    """
    Group by what the data shares, with no idea of what a domain is.

    Agglomerative: start with every sourcetype alone, repeatedly merge the two
    closest groups, stop when the closest pair is no longer similar enough.
    Similarity between groups is the average over their members, so one odd
    sourcetype cannot drag a whole group along behind it.

    What comes out is unnamed. It says these logs describe the same kind of
    thing — deciding that the thing is "network" is a person's job, and the
    report suggests a name by matching each group against the table above.
    """
    sets = [set(f.lower() for f in r["fields"]) - UBIQUITOUS for r in rows]
    groups = [[i] for i in range(len(rows))]

    while len(groups) > 1:
        best = (0.0, None, None)
        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                pairs = [jaccard(sets[a], sets[b]) for a in groups[i] for b in groups[j]]
                avg = sum(pairs) / len(pairs)
                if avg > best[0]:
                    best = (avg, i, j)

        if best[0] < threshold:
            break
        _, i, j = best
        groups[i] = groups[i] + groups[j]
        groups.pop(j)

    return [[rows[i] for i in g] for g in
            sorted(groups, key=lambda g: -len(g))]


def suggest_name(members: list[dict], used: set) -> tuple[str, str]:
    """
    Name a discovered group by scoring it against the written-down domains.

    Only a suggestion: the group is real, the label is a guess at what to call
    it. `unnamed-N` when nothing fits, which is the honest answer for data the
    table was not written for.
    """
    totals: dict[str, int] = {}
    for row in members:
        for domain, value in score(row["sourcetype"], row["fields"], row["roles"],
                                   row["index"]).items():
            totals[domain] = totals.get(domain, 0) + value

    ranked = sorted(totals.items(), key=lambda kv: -kv[1])
    for name, value in ranked:
        if name not in used and value >= CONFIDENT:
            return name, f"matches the {name} signals"

    common = set.intersection(*[set(f.lower() for f in m["fields"]) - UBIQUITOUS
                                for m in members]) if members else set()
    hint = ", ".join(sorted(common)[:4]) or "no fields in common"
    return "", hint


def read_catalog(payload: dict) -> list[dict]:
    """Accept either a /catalog export or a catalogue template."""
    out = []

    # Template shape: {"indexes": {name: {"sourcetypes": {st: {...}}}}}
    indexes = payload.get("indexes") or {}
    if indexes and isinstance(next(iter(indexes.values()), None), dict) \
            and "sourcetypes" in next(iter(indexes.values())):
        for index, entry in indexes.items():
            for st, meta in (entry.get("sourcetypes") or {}).items():
                out.append({
                    "index": index, "sourcetype": st,
                    "fields": list(meta.get("fields") or []),
                    "roles": meta.get("roles") or {},
                    "purpose": meta.get("purpose", ""),
                    "notes": meta.get("notes") or [],
                    "events": meta.get("_events", 0),
                })
        return out

    # Export shape: {"indexes": {name: [{sourcetype, events}]},
    #                "fields": {"index/sourcetype": {field: {...}}}}
    field_map = payload.get("fields") or {}
    for index, sourcetypes in indexes.items():
        for st in sourcetypes:
            key = f"{index}/{st['sourcetype']}"
            fields = field_map.get(key) or {}
            out.append({
                "index": index, "sourcetype": st["sourcetype"],
                "fields": [f for f in fields if not isinstance(fields.get(f), str)],
                "roles": {}, "purpose": "", "notes": [],
                "events": st.get("events", 0),
            })
    return out


PROMPT_TEMPLATE = """You turn a request for log data into a Splunk search and report what the logs show.

You do NOT write SPL. You call a tool with structured parameters and the tool builds the search.

You cover {asks}. If a requirement is about something else, say so plainly rather than searching for it here.

== WHICH TOOL ==

related_events(indicator, indicator_type)
  "what else touched X" — one entity across every field it could appear in.
  indicator_type: ip, host, user, hash, domain.

search_events(index, filters, earliest, latest, max_count)
  A specific search: one index, exact field=value pairs.

alert_frequency(alert_name, days)
  How often a named detection has fired.

list_indexes()
  Call it if you are unsure what is available.

== WHAT YOU CAN SEARCH ==

{catalogue}

== HOW TO ANSWER ==

At most two tool calls. If the first returns nothing, ask whether you used the
right field before concluding there is no data.

One event per line. Never two events on the same line:

  Searched <index/sourcetype>, <time range>, <what you filtered on> (N events).
  - <time>  <field>=<value>  <field>=<value>

If nothing matched, write the Searched line with (0 events) and nothing else.
An empty result means nothing matched this search — not that nothing happened.

Never invent events, counts, times or addresses."""


def catalogue_block(rows: list[dict]) -> str:
    lines = []
    for row in sorted(rows, key=lambda r: (-r["events"], r["sourcetype"])):
        lines.append(f"index `{row['index']}`, sourcetype `{row['sourcetype']}`"
                     + (f" — {row['purpose']}" if row["purpose"] else " — TODO"))
        roles = row.get("roles") or {}
        if roles:
            lines.append("  " + "  ".join(f"{r}={f}" for r, f in sorted(roles.items())))
        else:
            lines.append("  roles: TODO — see docs/splunk-catalog.md")
        for note in row.get("notes") or []:
            lines.append(f"  WARNING: {note}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export", nargs="?", help="/catalog JSON; omit to read stdin")
    ap.add_argument("-o", "--out", default="build", help="output directory")
    ap.add_argument("--num-ctx", type=int, default=8192,
                    help="the agents' context window, for the size warning")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--min-events", type=int, default=0,
                    help="ignore sourcetypes quieter than this")
    ap.add_argument("--only-indexes",
                    help="comma-separated: keep only these indexes. The cheapest "
                         "cut there is — most of an estate is metrics, audit and "
                         "compliance data an analysing agent never needs.")
    ap.add_argument("--skip-indexes", default="",
                    help="comma-separated indexes to drop")
    ap.add_argument("--by-index", action="store_true",
                    help="one agent per index, no classification at all")
    ap.add_argument("--domains", help="JSON replacing the built-in domain table")
    ap.add_argument("--discover", action="store_true",
                    help="ignore the domain table and group by shared fields")
    ap.add_argument("--similarity", type=float, default=0.25,
                    help="--discover: how much two sourcetypes must share to "
                         "join, 0 to 1 (default 0.25)")
    args = ap.parse_args()

    if args.domains:
        DOMAINS.clear()
        DOMAINS.update(json.loads(Path(args.domains).read_text()))
        print(f"using {len(DOMAINS)} domains from {args.domains}", file=sys.stderr)

    raw = Path(args.export).read_text() if args.export else sys.stdin.read()
    rows = read_catalog(json.loads(raw))

    if args.only_indexes:
        keep = {i.strip() for i in args.only_indexes.split(",") if i.strip()}
        before = len(rows)
        rows = [r for r in rows if r["index"] in keep]
        print(f"kept {len(rows)} of {before} sourcetypes from {len(keep)} indexes",
              file=sys.stderr)
    if args.skip_indexes:
        drop = {i.strip() for i in args.skip_indexes.split(",") if i.strip()}
        before = len(rows)
        rows = [r for r in rows if r["index"] not in drop]
        print(f"dropped {before - len(rows)} sourcetypes in {sorted(drop)}",
              file=sys.stderr)

    if args.min_events:
        rows = [r for r in rows if r["events"] >= args.min_events]

    if not rows:
        print("no sourcetypes in that export", file=sys.stderr)
        return 1

    grouped: dict[str, list[dict]] = {d: [] for d in DOMAINS}
    unassigned: list[dict] = []
    review: list[dict] = []

    if args.by_index:
        # No classification at all. Index layout is driven by retention and
        # access control rather than by meaning, so this fragments a domain
        # spread over several indexes — but it needs no rules and no review,
        # and on an estate whose indexes are already named by domain it lands
        # in much the same place.
        for row in rows:
            grouped.setdefault(row["index"], []).append(row)
        for index in grouped:
            DOMAINS.setdefault(index, {"asks": f"whatever index `{index}` holds",
                                       "roles": {}, "fields": {}, "name": {}})
        print(f"grouped by index: {len(grouped)} agents\n", file=sys.stderr)
    elif args.discover:
        # Groups come from the data. Names are suggested afterwards, and a group
        # the table has no word for keeps a placeholder rather than being forced
        # into a domain it does not belong to.
        clusters = discover(rows, args.similarity)
        grouped, used = {}, set()
        for n, members in enumerate(clusters, start=1):
            name, why = suggest_name(members, used)
            if name:
                used.add(name)
            else:
                name = f"unnamed-{n}"
            grouped[name] = members
            DOMAINS.setdefault(name, {"asks": f"logs that share: {why}",
                                      "roles": {}, "fields": {}, "name": {}})
            print(f"  group {n}: {len(members):3} sourcetypes -> {name:12} ({why})",
                  file=sys.stderr)
        print(file=sys.stderr)
    else:
        for row in rows:
            domains, scores, confident = classify(row["sourcetype"], row["fields"],
                                                  row["roles"], row["index"])
            row["_scores"] = scores
            if not domains:
                unassigned.append(row)
                continue
            for d in domains:
                grouped[d].append(row)
            if not confident or len(domains) > 1:
                review.append({**row, "_domains": domains})

    out = Path(args.out)
    (out / "catalog").mkdir(parents=True, exist_ok=True)
    (out / "agents").mkdir(parents=True, exist_ok=True)

    budget = int(args.num_ctx * PROMPT_BUDGET_FRACTION)
    report = []

    for domain, members in grouped.items():
        if not members:
            continue

        slice_ = {"indexes": {}}
        for row in members:
            idx = slice_["indexes"].setdefault(row["index"], {"purpose": "TODO",
                                                              "sourcetypes": {}})
            idx["sourcetypes"][row["sourcetype"]] = {
                "purpose": row["purpose"] or "TODO",
                "roles": row["roles"],
                "fields": row["fields"],
                "notes": row["notes"],
            }
        (out / "catalog" / f"{domain}.json").write_text(
            json.dumps(slice_, indent=2, ensure_ascii=False) + "\n")

        prompt = PROMPT_TEMPLATE.format(asks=DOMAINS[domain]["asks"],
                                        catalogue=catalogue_block(members))
        # Rough token count. Four characters per token is the usual rule of
        # thumb and is close enough to decide whether a domain needs splitting.
        tokens = len(prompt) // 4
        agent = {
            "name": f"{domain}-query",
            "description": f"Query agent for {DOMAINS[domain]['asks']}.",
            "model": args.model,
            "system_prompt": prompt,
            "temperature": 0.1,
            "num_ctx": args.num_ctx,
            "max_steps": 3,
            "max_tool_chars": 4000,
            "mcp_servers": ["splunk"],
            "delegates": [],
            "allowed_tools": None,
            "enabled": True,
        }
        (out / "agents" / f"{domain}-query.json").write_text(
            json.dumps(agent, indent=2, ensure_ascii=False) + "\n")

        report.append({"domain": domain, "sourcetypes": len(members),
                       "tokens": tokens, "over_budget": tokens > budget})

    # The analysing agent's delegates, one per domain that has data.
    analyst_delegates = [
        {"tool": f"ask_{d['domain']}", "agent": f"{d['domain']}-query",
         "argument": "requirement",
         "description": (f"Ask the {d['domain']} query agent for log data about "
                         f"{DOMAINS[d['domain']]['asks']}. Describe what you need in "
                         "plain language, naming the entity and the time range. It "
                         "knows the schema, so do not write a query and do not name "
                         "fields.")}
        for d in report
    ]
    (out / "agents" / "_analyst-delegates.json").write_text(
        json.dumps({"delegates": analyst_delegates}, indent=2, ensure_ascii=False) + "\n")

    # ── report ──────────────────────────────────────────────────────────────
    print(f"{len(rows)} sourcetypes -> {len(report)} query agents"
          f"   (budget {budget} tokens each, {PROMPT_BUDGET_FRACTION:.0%} of {args.num_ctx})\n",
          file=sys.stderr)
    for r in sorted(report, key=lambda r: -r["sourcetypes"]):
        flag = "  OVER BUDGET — split this one further" if r["over_budget"] else ""
        print(f"  {r['domain']:10} {r['sourcetypes']:3} sourcetypes  "
              f"~{r['tokens']:5} tokens{flag}", file=sys.stderr)

    if unassigned:
        print(f"\n{len(unassigned)} matched no domain — decide by hand, or leave out:",
              file=sys.stderr)
        for row in unassigned[:15]:
            print(f"  {row['index']}/{row['sourcetype']}", file=sys.stderr)
        if len(unassigned) > 15:
            print(f"  … and {len(unassigned) - 15} more", file=sys.stderr)

    if review:
        print(f"\n{len(review)} need review — either a weak match or landing in "
              "more than one domain:", file=sys.stderr)
        for row in review[:15]:
            scores = ", ".join(f"{d}={s}" for d, s in
                               sorted(row["_scores"].items(), key=lambda kv: -kv[1]))
            print(f"  {row['sourcetype']:28} -> {', '.join(row['_domains']):20} ({scores})",
                  file=sys.stderr)
        if len(review) > 15:
            print(f"  … and {len(review) - 15} more", file=sys.stderr)

    print(f"\nwritten to {out}/", file=sys.stderr)
    print("  catalog/<domain>.json   mount at SPLUNK_CATALOG_FILE, one connector each,",
          file=sys.stderr)
    print("                          or merge into one file if you run a single connector",
          file=sys.stderr)
    print("  agents/<domain>-query.json   POST to the LLM server", file=sys.stderr)
    print("  agents/_analyst-delegates.json   PATCH onto the analysing agent",
          file=sys.stderr)
    print("\nEvery purpose and every role still says TODO where the export could not "
          "know it.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
