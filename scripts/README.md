# scripts/

Operator tools. They talk to Splunk and the services over HTTP and read JSON —
nothing to install beyond the right Python.

## Python 3.12

The services run `python:3.12-slim`, and these match it. macOS ships 3.9 as
`python3`, which is old enough that the scripts will not parse, so they check
the version and say so rather than failing with a syntax error.

```bash
python3.12 -m venv .venv
.venv/bin/python scripts/<name>.py
```

`python3.12` comes from Homebrew (`brew install python@3.12`). `.venv/` is
gitignored.

## What is here

| Script | Does |
| --- | --- |
| [`export_splunk_catalog.py`](export_splunk_catalog.py) | Pulls indexes, sourcetypes and fields out of Splunk into JSON and a Markdown summary. |
| [`verify_catalog_export.py`](verify_catalog_export.py) | Says whether an export is complete enough to use. Exit 0 or 1, so CI can branch on it. |
| [`make_catalog_template.py`](make_catalog_template.py) | Turns that export into a catalogue skeleton, guessing the role map and marking every guess for review. |
| [`plan_query_agents.py`](plan_query_agents.py) | **Obsolete** — no agent searches Splunk any more. Groups sourcetypes into query agents — by a domain table, by your own table, by index, or by what the data shares. |

The Splunk export is a Python script; the rest read its output.

Related scripts in the other repos:

- `derive_signatures.py` — **Backend** repo, `scripts/`. Suggests field
  signatures for unplaced alerts; low-sample candidates are review-only by default.
- `run_mockup.py` — was **LLM-Server** repo, `scripts/`: put recovered ES
  notables through an agent and printed the trace. LLM-Server is retired; the
  agent platform is now [Agent-Server](../../Agent-Server/readme.md), which has
  no equivalent script — test an agent from its own admin UI's "ทดสอบ Agent" tab,
  or `POST /v1/agents/{slug}/chat` directly (see `Agent-Server/readme.md`).

### Exporting

```bash
SPLUNK_URL=https://splunk.example.com:8089 \
SPLUNK_AUTH='Bearer eyJ…' \
OUT=Splunk/table \
  python3 scripts/export_splunk_catalog.py
```

`SPLUNK_INSECURE=1` (the default) skips certificate verification, which is what
a self-signed lab Splunk needs. Set it to `0` against a real certificate. CI
sets `0`.

A failed call stops the export and says why — a bad token, an unreachable port
and an unverifiable certificate each get their own line. Without that a 401
came back as an empty body, the export finished happily, and the catalogue it
wrote said this estate has no indexes at all.

### Checking an export

```bash
python3 scripts/verify_catalog_export.py Splunk/table
```

The question is not whether the directory exists. An export that died after
writing `indexes.json` leaves one behind, and a catalogue listing three of an
estate's two hundred sourcetypes is worse than none: the agent is told the
estate is small, searches what it was given, finds nothing, and reports that
nothing happened. So this checks that every sourcetype the enumeration found
has its fields file, and that each file parses.

CI runs it twice — before exporting, to decide whether one is needed, and after,
to decide whether to commit. One definition, so the two can never disagree.

## Where they fit

```
Splunk ──export_splunk_catalog.py──► make_catalog_template.py ──► catalog/*.json
            │                  (Splunk/table/)
                                                │
                                                └──► plan_query_agents.py ──► agents/*.json

alerts that could not be placed ──► derive_signatures.py (Backend) ──► ALERT_SOURCE_SIGNATURES
```

Each one stops where a person has to decide something — what a sourcetype is
for, which field carries which meaning, which domain a family belongs to. None
of that is in the data, and pretending otherwise is how an agent ends up
confidently searching the wrong field.

See [`../docs/splunk-catalog.md`](../docs/splunk-catalog.md).
