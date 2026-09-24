#!/usr/bin/env python3
"""Export a Splunk data catalog: indexes, sourcetypes, and their fields."""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


if sys.version_info < (3, 12):
    raise SystemExit(
        f"needs Python 3.12, found {sys.version.split()[0]}. "
        "Use python3.12 or the project virtual environment."
    )


def auth_header(value: str) -> str:
    if value.startswith("Bearer "):
        return value
    encoded = base64.b64encode(value.encode()).decode()
    return f"Basic {encoded}"


def request_json(url: str, auth: str, form: dict[str, str], insecure: bool) -> dict[str, Any]:
    body = urlencode(form).encode()
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": auth_header(auth),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    context = ssl._create_unverified_context() if insecure else None

    try:
        with urlopen(request, context=context) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200]
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc

    if not raw:
        raise RuntimeError("Splunk returned an empty body")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Splunk returned invalid JSON: {exc}") from exc


def search(
    splunk_url: str,
    auth: str,
    search_text: str,
    window: str,
    insecure: bool,
) -> dict[str, Any]:
    return request_json(
        f"{splunk_url.rstrip('/')}/services/search/jobs",
        auth,
        {
            "search": search_text,
            "exec_mode": "oneshot",
            "earliest_time": window,
            "latest_time": "now",
            "output_mode": "json",
        },
        insecure,
    )


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"set {name}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def export_catalog() -> int:
    splunk_url = require_env("SPLUNK_URL")
    auth = require_env("SPLUNK_AUTH")
    window = os.environ.get("WINDOW", "-30d")
    sample = int(os.environ.get("SAMPLE", "200"))
    output = Path(os.environ.get("OUT", "splunk-catalog"))
    insecure = os.environ.get("SPLUNK_INSECURE", "1") == "1"
    output.mkdir(parents=True, exist_ok=True)

    def run(search_text: str) -> dict[str, Any]:
        try:
            return search(splunk_url, auth, search_text, window, insecure)
        except RuntimeError as exc:
            print(f"\nexport failed talking to {splunk_url}: {exc}", file=sys.stderr)
            print(f"  search was: {search_text}", file=sys.stderr)
            raise SystemExit(1) from exc

    print("1/4  data models (is this estate CIM-normalised?)")
    model_rows = run("| rest /services/data/models | table title").get("results", [])
    model_names = [row["title"] for row in model_rows if "title" in row]
    external = [name for name in model_names if not name.startswith("internal_")]
    print("     ", ", ".join(external) if external else "(none beyond Splunk internals — fields are NOT CIM-normalised)")
    write_json(output / "datamodels.json", model_names)

    print("2/4  indexes and sourcetypes")
    rows = run("| tstats count where index=* by index, sourcetype").get("results", [])
    by_index: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        index = row["index"]
        sourcetype = row["sourcetype"]
        by_index.setdefault(index, []).append(
            {"sourcetype": sourcetype, "events": int(row["count"])}
        )
    for index, sourcetypes in sorted(by_index.items()):
        total = sum(item["events"] for item in sourcetypes)
        names = ", ".join(item["sourcetype"] for item in sourcetypes[:4])
        print(f"      {index:22} {total:>12,} events  {names}")
    write_json(output / "indexes.json", by_index)

    pairs = [(index, item["sourcetype"]) for index, items in by_index.items() for item in items]
    print(f"3/4  fields per sourcetype (sampling {sample} events each)")
    for index, sourcetype in pairs:
        safe = f"{index}__{sourcetype}"
        safe = "".join(char if char.isalnum() or char in "_-" else "_" for char in safe)
        query = (
            f'search index="{index}" sourcetype="{sourcetype}" '
            f"| head {sample} | fieldsummary maxvals=3"
        )
        field_rows = run(query).get("results", [])
        fields: dict[str, dict[str, Any]] = {}
        for row in field_rows:
            name = row["field"]
            if name.startswith("_") or name in {"punct", "linecount", "eventtype", "tag"}:
                continue
            try:
                values = json.loads(row.get("values", "[]"))[:3]
                examples = [str(value["value"])[:40] for value in values]
            except (KeyError, TypeError, json.JSONDecodeError):
                examples = []
            fields[name] = {
                "distinct": row.get("distinct_count"),
                "examples": examples,
            }
        write_json(
            output / f"fields__{safe}.json",
            {"index": index, "sourcetype": sourcetype, "fields": fields},
        )
        print(f"      {index} / {sourcetype}: {len(fields)} fields")

    print("4/4  summary")
    hints = {
        "ip": ("src_ip", "dest_ip", "src", "dest", "srcip", "dstip", "clientip", "dest_ip"),
        "user": ("user", "src_user", "user_name", "username", "account"),
        "host": ("host", "dvc", "dest_host", "devname", "hostname", "computer"),
        "hash": ("file_hash", "hash", "md5", "sha256", "sha1"),
        "domain": ("query", "domain", "dest_host", "url_domain", "url"),
    }
    docs: list[str] = []
    field_map = {kind: [] for kind in hints}
    for path in sorted(output.glob("fields__*.json")):
        data = json.loads(path.read_text())
        names = sorted(data["fields"])
        docs.extend([
            f"### index `{data['index']}` · sourcetype `{data['sourcetype']}`\n",
            "| field | distinct | examples |",
            "| --- | --- | --- |",
        ])
        for name in names:
            field = data["fields"][name]
            docs.append(f"| `{name}` | {field['distinct']} | {', '.join(field['examples']) or '—'} |")
        docs.append("")
        for kind, candidates in hints.items():
            for name in names:
                if name in candidates and name not in field_map[kind]:
                    field_map[kind].append(name)

    header = [
        "# Splunk data catalog",
        "",
        "Generated by export_splunk_catalog.py. Paste the tables into an agent's data guide,",
        "and use field-map.json as the starting point for SPLUNK_FIELD_MAP.",
        "",
        f"CIM data models: {', '.join(external) if external else '**none** — fields are not normalised'}",
        "",
    ]
    (output / "catalog.md").write_text("\n".join(header + docs))
    write_json(output / "field-map.json", field_map)
    print("      catalog.md, field-map.json")
    print(f"\nwritten to {output}/")
    for path in sorted(output.iterdir()):
        print(path.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(export_catalog())
