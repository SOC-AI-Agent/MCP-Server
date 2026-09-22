"""
The curated data catalog — what the model is told about this Splunk.

`/catalog` enumerates the estate for an operator; this is the other half: a file
a person writes after reading that, describing what each index and sourcetype
holds, which field carries which meaning, and what is easy to get wrong.

The distinction matters. Enumeration says `srcip` and `host` both exist. Only a
person can say that `host` is the syslog forwarder and the address the alert is
about lives in `srcip` — and that sentence is what stops an agent reporting
"nothing found" after searching the wrong field.

It drives three things, so one file edit fixes all of them:

  * list_indexes      — what exists, and what each part is for
  * describe_sourcetype — the field map for one sourcetype
  * related_events    — which fields to search for an indicator

With no file configured every one of those falls back to CIM names, which is
correct on a normalised estate and wrong everywhere else.
"""

import json
import logging
from pathlib import Path
from typing import Any

from config import settings

logger = logging.getLogger("catalog")

# Canonical roles. A catalog maps these to whatever the sourcetype actually
# calls them, so a tool can ask for "the source address" without knowing which
# vendor wrote the log.
ROLES = ("src_ip", "dest_ip", "src_port", "dest_port", "user", "host", "hash", "domain", "action")

# Used when no catalog is configured. Splunk CIM names: right on a normalised
# estate, wrong on raw vendor logs — which is exactly the case the catalog file
# exists to handle.
CIM_FALLBACK: dict[str, list[str]] = {
    "ip": ["src_ip", "dest_ip", "src", "dest"],
    "host": ["host", "dvc", "dest_host"],
    "user": ["user", "src_user", "user_name"],
    "hash": ["file_hash", "hash", "md5", "sha256"],
    "domain": ["query", "domain", "dest_host", "url_domain"],
}

# An indicator type maps to one or more roles; `related_events` searches all of
# them, because "this IP" means either end of a connection.
INDICATOR_ROLES: dict[str, tuple[str, ...]] = {
    "ip": ("src_ip", "dest_ip"),
    "host": ("host",),
    "user": ("user",),
    "hash": ("hash",),
    "domain": ("domain",),
}

_catalog: dict[str, Any] = {}


def load() -> dict[str, Any]:
    """Read the catalog file, once, at startup. Never fatal: a broken catalog
    should degrade to CIM names rather than stop the connector answering."""
    global _catalog
    path = settings.SPLUNK_CATALOG_FILE.strip()
    if not path:
        logger.info("no SPLUNK_CATALOG_FILE — falling back to CIM field names")
        _catalog = {}
        return _catalog

    try:
        raw = json.loads(Path(path).read_text())
    except FileNotFoundError:
        logger.error("catalog file %s not found — falling back to CIM field names", path)
        _catalog = {}
        return _catalog
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("catalog file %s unreadable (%s) — falling back to CIM names", path, exc)
        _catalog = {}
        return _catalog

    indexes = raw.get("indexes")
    if not isinstance(indexes, dict):
        logger.error("catalog file %s has no 'indexes' object — ignoring it", path)
        _catalog = {}
        return _catalog

    _catalog = raw
    total = sum(len(i.get("sourcetypes", {})) for i in indexes.values())
    logger.info("catalog loaded: %d indexes, %d sourcetypes", len(indexes), total)
    return _catalog


def loaded() -> bool:
    return bool(_catalog.get("indexes"))


def indexes() -> dict[str, Any]:
    return _catalog.get("indexes", {})


def sourcetype(name: str) -> dict[str, Any] | None:
    """Find one sourcetype's entry, whichever index it sits under."""
    for index_name, index in indexes().items():
        entry = (index.get("sourcetypes") or {}).get(name)
        if entry is not None:
            return {**entry, "index": index_name, "sourcetype": name}
    return None


def summary() -> list[dict[str, Any]]:
    """
    The compact map handed to the model by list_indexes.

    Deliberately small: it is read on every run that touches Splunk, and every
    token here is one taken from the alert. Purpose and key fields only — the
    full field list is a describe_sourcetype call away.
    """
    out = []
    for index_name, index in indexes().items():
        sourcetypes = []
        for st_name, st in (index.get("sourcetypes") or {}).items():
            roles = st.get("roles") or {}
            sourcetypes.append({
                "sourcetype": st_name,
                "purpose": st.get("purpose", ""),
                # The roles are what the model needs to build a filter; listing
                # every field here would triple the size for no extra accuracy.
                "key_fields": {r: f for r, f in roles.items() if r in ROLES},
            })
        out.append({
            "index": index_name,
            "purpose": index.get("purpose", ""),
            "sourcetypes": sourcetypes,
        })
    return out


def fields_for_role(role: str, index: str | None = None) -> list[str]:
    """
    Every field name that carries `role`, across the catalog.

    Deduplicated and order-stable so the SPL an indicator search produces does
    not change between calls for no reason.
    """
    found: list[str] = []
    for index_name, index_entry in indexes().items():
        if index is not None and index_name != index:
            continue
        for st in (index_entry.get("sourcetypes") or {}).values():
            field = (st.get("roles") or {}).get(role)
            if field and field not in found:
                found.append(field)
    return found


def fields_for_indicator(indicator_type: str, index: str | None = None) -> list[str]:
    """Field names to search for an indicator, catalog first, CIM as fallback."""
    if loaded():
        fields: list[str] = []
        for role in INDICATOR_ROLES.get(indicator_type, ()):
            for field in fields_for_role(role, index):
                if field not in fields:
                    fields.append(field)
        if fields:
            return fields
        logger.warning(
            "catalog has no field for indicator_type=%r — using CIM names", indicator_type
        )
    return CIM_FALLBACK.get(indicator_type, [])
