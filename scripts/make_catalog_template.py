
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
Turn a /catalog export into a catalog template for a person to fill in.

The export knows what exists. It cannot know what any of it is *for*, or which
field carries which meaning — that is the part a person writes, and the part
that stops an agent searching `host` when the address it wants is in `srcip`.

So this writes the skeleton: every index and sourcetype, every field name, and
a `roles` block pre-filled with guesses that are marked as guesses. What it
leaves empty is what needs a human:

    purpose   one line, what this holds and what it is for
    roles     meaning -> the field name in THIS sourcetype
    notes     what is easy to get wrong

    curl -s "$MCP/catalog" -H "Authorization: Bearer $MCP_AUTH_TOKEN" \\
      | python3 scripts/make_catalog_template.py --split -o catalog/

One file per index with --split, which is what you want on an estate with more
sourcetypes than fit in a screen. Re-running keeps anything already written:
it fills gaps and never overwrites a line someone wrote by hand.
"""

import argparse
import json
from pathlib import Path

# Guesses only, from field names. Every one lands in the file tagged for review,
# because a name that looks right is regularly wrong — `host` on a forwarded
# syslog feed is the forwarder, not the machine the alert is about.
ROLE_HINTS: dict[str, tuple[str, ...]] = {
    "src_ip":    ("src_ip", "srcip", "source_ip", "src", "clientip", "client_ip"),
    "dest_ip":   ("dest_ip", "dstip", "destination_ip", "dest", "dst_ip", "serverip"),
    "src_port":  ("src_port", "srcport", "source_port"),
    "dest_port": ("dest_port", "dstport", "destination_port", "port"),
    "user":      ("user", "username", "user_name", "src_user", "account", "samaccountname"),
    "host":      ("host", "hostname", "dvc", "device", "devname", "computer", "dest_host"),
    "hash":      ("file_hash", "hash", "md5", "sha1", "sha256"),
    "domain":    ("domain", "query", "url_domain", "dns_query", "fqdn"),
    "action":    ("action", "status", "result", "disposition", "outcome"),
}

# Present in nearly every event and never the answer to "which field holds the
# source address", so they only add noise to a file someone has to read.
BORING = {
    "date", "date_hour", "date_mday", "date_minute", "date_month", "date_second",
    "date_wday", "date_year", "date_zone", "timestamp", "timeendpos", "timestartpos",
    "linecount", "punct", "splunk_server", "index", "source", "eventtype", "tag",
}

TODO = "TODO"


def guess_roles(fields: list[str]) -> tuple[dict[str, str], list[str]]:
    """Map roles to field names where a name matches. Returns (roles, guessed)."""
    lower = {f.lower(): f for f in fields}
    roles: dict[str, str] = {}
    guessed: list[str] = []
    for role, candidates in ROLE_HINTS.items():
        for candidate in candidates:
            if candidate in lower:
                roles[role] = lower[candidate]
                guessed.append(role)
                break
    return roles, guessed


def build(export: dict, existing: dict) -> dict:
    """Merge the export into whatever has already been written."""
    out_indexes = dict(existing.get("indexes", {}))
    fields_by_pair: dict[str, list[str]] = {}
    for key, fields in (export.get("fields") or {}).items():
        if isinstance(fields, dict) and "error" not in fields:
            fields_by_pair[key] = sorted(f for f in fields if f not in BORING)

    for index_name, sourcetypes in (export.get("indexes") or {}).items():
        index_entry = out_indexes.setdefault(index_name, {})
        index_entry.setdefault("purpose", TODO)
        st_out = index_entry.setdefault("sourcetypes", {})

        for st in sourcetypes:
            name = st["sourcetype"]
            fields = fields_by_pair.get(f"{index_name}/{name}", [])
            entry = st_out.setdefault(name, {})

            # Never overwrite prose someone wrote.
            entry.setdefault("purpose", TODO)
            entry.setdefault("notes", [])

            roles, guessed = guess_roles(fields)
            written = entry.setdefault("roles", {})
            for role, field in roles.items():
                written.setdefault(role, field)

            # Field list is refreshed from the export: it is a fact, not prose.
            if fields:
                entry["fields"] = fields

            review = [r for r in guessed if r not in entry.get("_reviewed", [])]
            if review:
                entry["_review_roles"] = sorted(review)
            entry["_events"] = st.get("events", 0)

    return {"indexes": out_indexes}


def stats(catalog: dict) -> tuple[int, int, int]:
    total = done = fields = 0
    for index in catalog.get("indexes", {}).values():
        for st in (index.get("sourcetypes") or {}).values():
            total += 1
            fields += len(st.get("fields", []))
            if st.get("purpose") != TODO and st.get("roles"):
                done += 1
    return total, done, fields


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export", nargs="?", help="/catalog JSON; omit to read stdin")
    ap.add_argument("-o", "--out", default="catalog", help="output file or directory")
    ap.add_argument("--split", action="store_true", help="one file per index")
    ap.add_argument("--min-events", type=int, default=0,
                    help="skip sourcetypes with fewer events than this")
    args = ap.parse_args()

    raw = Path(args.export).read_text() if args.export else sys.stdin.read()
    export = json.loads(raw)

    if args.min_events:
        export["indexes"] = {
            i: [s for s in sts if s.get("events", 0) >= args.min_events]
            for i, sts in (export.get("indexes") or {}).items()
        }
        export["indexes"] = {i: s for i, s in export["indexes"].items() if s}

    out = Path(args.out)
    if args.split:
        out.mkdir(parents=True, exist_ok=True)
        written = []
        for index_name in (export.get("indexes") or {}):
            path = out / f"{index_name}.json"
            prior = json.loads(path.read_text()) if path.exists() else {}
            one = {"indexes": {index_name: (export.get("indexes") or {})[index_name]}}
            one_export = {**export, "indexes": one["indexes"]}
            merged = build(one_export, prior)
            path.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
            written.append(path)
        catalog = {"indexes": {}}
        for path in written:
            catalog["indexes"].update(json.loads(path.read_text())["indexes"])
    else:
        path = out if out.suffix == ".json" else out / "splunk-catalog.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        prior = json.loads(path.read_text()) if path.exists() else {}
        catalog = build(export, prior)
        path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
        written = [path]

    total, done, fields = stats(catalog)
    for path in written:
        print(f"wrote {path}", file=sys.stderr)
    print(f"\n{total} sourcetypes, {fields} fields, {done} already described.",
          file=sys.stderr)
    if total - done:
        print(f"{total - done} still marked {TODO} — fill in `purpose`, check `roles`,",
              file=sys.stderr)
        print("and add `notes` for anything easy to get wrong.", file=sys.stderr)
        if not export.get("cim_normalised", True):
            print("\nThis estate is not CIM-normalised, so the guessed roles are the",
                  file=sys.stderr)
            print("only mapping there is. They need reading.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
