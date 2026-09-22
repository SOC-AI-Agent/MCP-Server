"""
The playbook record, and reading it out of Confluence.

The schema is the contract between the wiki and everything downstream, and it
is not free prose: a playbook is a set of named fields, some of which identify
which detection it covers and some of which an analyst acts on. That split
decides the whole design, and it was settled in notebooks/playbook_rag.ipynb —
this module is that work as a service.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("playbooks")

# Identify which playbook applies. Embedded, when an embedding tier exists.
MATCHED_FIELDS = ["alert_name", "rule_description", "true_condition", "false_condition"]
# What the analyst then acts on. Never used for matching: embedding a contact
# would match on people's names and a version number carries no meaning at all.
METADATA_FIELDS = [
    "use_case_category", "version", "splunk_query", "work_around",
    "target_audience", "contact",
]

# Confluence label -> our field. A label that is not here is ignored rather
# than guessed at: a page that grows a new row should not silently change what
# the matcher sees.
FIELD_LABELS = {
    "alert name": "alert_name",
    "alert": "alert_name",
    "use case": "alert_name",
    "use case / alert name": "alert_name",
    "use case name": "alert_name",
    "use case category": "use_case_category",
    "category": "use_case_category",
    "aliases": "aliases",
    "rule description": "rule_description",
    "description": "rule_description",
    "true condition": "true_condition",
    "false condition": "false_condition",
    "version": "version",
    "splunk query": "splunk_query",
    "work around": "work_around",
    "workaround": "work_around",
    "step to work": "work_around",
    "target audience": "target_audience",
    "contact": "contact",
    "contact info": "contact",
}


@dataclass
class Playbook:
    page_id: str
    # Confluence keeps the use case name and the alert name in one column, so
    # this is both: the routing key, and what an analyst calls the detection.
    alert_name: str
    use_case_category: str = ""
    rule_description: str = ""
    true_condition: str = ""
    false_condition: str = ""
    # The same detection under other names. FortiSOAR and Confluence do not
    # always agree, and detections get renamed without the playbook following.
    aliases: list[str] = field(default_factory=list)
    version: str = ""
    # Parameters for a search, never raw SPL. Storing the analyst's search
    # verbatim and running it would let anyone with edit access to the space
    # run arbitrary SPL as the service account, and SPL is not read-only:
    # `| delete`, `| collect`, `| outputlookup` and `| script` all write or
    # destroy. So this is a dict the Splunk connector builds a search from.
    splunk_query: dict | None = None
    work_around: str = ""
    target_audience: str = ""
    contact: str = ""
    url: str = ""
    source: str = "file"

    def as_dict(self) -> dict[str, Any]:
        return {
            "page_id": self.page_id,
            "alert_name": self.alert_name,
            "aliases": self.aliases,
            "url": self.url,
            "source": self.source,
            **{f: getattr(self, f) for f in MATCHED_FIELDS if f != "alert_name"},
            **{f: getattr(self, f) for f in METADATA_FIELDS},
        }


_TAGS = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _text(html: str) -> str:
    """Confluence stores cells as storage-format XHTML; we want the words."""
    return _WS.sub(" ", _TAGS.sub(" ", html or "")).replace("&nbsp;", " ").strip()


def _split_aliases(value: str) -> list[str]:
    return [a.strip() for a in re.split(r"[,;\n]", value or "") if a.strip()]


def _parse_query(value: str) -> dict | None:
    """
    `splunk_query` holds parameters, so the cell should be JSON.

    A cell that is not JSON is dropped with a warning rather than passed on as
    a string. Downstream would have to guess what to do with it, and guessing
    at a search is the failure this whole system is built to avoid.
    """
    value = (value or "").strip().strip("`")
    if not value:
        return None
    if value.lower().startswith("json"):
        value = value[4:].strip()
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        logger.warning("splunk_query is not JSON, ignoring it: %.80s", value)
        return None
    return parsed if isinstance(parsed, dict) else None


def from_rows(page_id: str, rows: dict[str, str], url: str = "", source: str = "confluence") -> Playbook | None:
    """
    One page's Page Properties rows -> a playbook, or None if it has no name.

    A page without an alert name cannot be routed to, so it is not a playbook
    for our purposes. Saying so is better than indexing something nothing will
    ever match.
    """
    fields: dict[str, Any] = {}
    for label, value in rows.items():
        name = FIELD_LABELS.get(label.strip().lower())
        if not name:
            continue
        if name == "aliases":
            fields["aliases"] = _split_aliases(value)
        elif name == "splunk_query":
            fields["splunk_query"] = _parse_query(value)
        else:
            fields[name] = value.strip()

    if not fields.get("alert_name"):
        logger.warning("page %s has no alert name — skipped", page_id)
        return None
    return Playbook(page_id=page_id, url=url, source=source, **fields)


def from_file(path: str) -> list[Playbook]:
    """Playbooks from a JSON file, for a stack with no Confluence to read."""
    try:
        with open(path) as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        logger.info("no playbook file at %s", path)
        return []
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("playbook file %s unreadable: %s", path, exc)
        return []

    out: list[Playbook] = []
    for entry in raw if isinstance(raw, list) else raw.get("playbooks", []):
        if not entry.get("alert_name"):
            continue
        known = {k: v for k, v in entry.items() if k in Playbook.__annotations__}
        known.setdefault("page_id", entry.get("alert_name"))
        known["source"] = "file"
        out.append(Playbook(**known))
    logger.info("loaded %d playbook(s) from %s", len(out), path)
    return out
