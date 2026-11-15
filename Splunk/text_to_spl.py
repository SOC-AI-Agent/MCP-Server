"""
Text-to-SPL without Splunk AI Assistant: a template.

Splunk's own Text-to-SPL (`saia_generate_spl`, Splunk AI Assistant for SPL) exists
only in a Splunk that has the assistant — not in a plain Splunk container, and not
in mock mode. This writes the search instead: the index, sourcetype and window the
request names, the values found in it as search terms, and a count when the
question is one. No model, and nothing clever on purpose.

Used in SPLUNK_MODE=mock, and in live when SPLUNK_SAIA_MCP_URL is blank.
"""

# So setup.py in external/splunk can import this with an older system python3.
from __future__ import annotations

import re

MOCK_INDEX = "main"


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
# \b after the key, so `user_agent: …` is not read as a user called "_agent".
_USER = re.compile(r"\buser(?:name)?\b\s*[=:]?\s*\"?([A-Za-z0-9_.\-@\\]{2,64})", re.IGNORECASE)
_INDEX_HINT = re.compile(r"\bindex\s*[=:]?\s*\"?([A-Za-z0-9_\-]+)", re.IGNORECASE)
_SOURCETYPE_HINT = re.compile(r"\bsourcetype\s*[=:]?\s*\"?([A-Za-z0-9_:\-]+)", re.IGNORECASE)
_EARLIEST_HINT = re.compile(r"\bearliest\s*[=:]?\s*\"?([^\s\",)]+)", re.IGNORECASE)
_LATEST_HINT = re.compile(r"\blatest\s*[=:]?\s*\"?([^\s\",)]+)", re.IGNORECASE)
# Questions about how much, or with whom, read better as a count than as a list.
# "45.83.122.9 is in srcip or dstip" — the field names lookup.build_prompt gives.
_FIELD = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*"
_FIELDS_HINT = re.compile(rf"\bis in ({_FIELD}(?: or {_FIELD})*)")
_AGGREGATE = re.compile(
    r"\b(how many|count|top|most|frequen|which (?:hosts?|address|destinations?|ports?)|"
    r"talk(?:ed|ing)? to|connect(?:ed|ions?)? to|destinations?|distinct)\b",
    re.IGNORECASE,
)


def _hint(pattern: re.Pattern, prompt: str, default: str | None) -> str | None:
    """A value named in the request, without the sentence's punctuation after it."""
    found = pattern.search(prompt)
    return found.group(1).rstrip(".,;:") if found else default


def generate(prompt: str, mock: bool = False) -> dict:
    """The SPL for a request, and how it was arrived at.

    mock=True is the development estate: its index when none is named, and its
    columns in the answer. Otherwise nothing about the data is assumed — the index
    and field names are the ones the request names.
    """
    values: list[str] = []
    for found in (_IPV4.findall(prompt) + _HASH.findall(prompt)
                  + [m.group(1).rstrip(".,;:") for m in _USER.finditer(prompt)]):
        if found not in values:
            values.append(found)

    index = _hint(_INDEX_HINT, prompt, MOCK_INDEX if mock else None)
    sourcetype = _hint(_SOURCETYPE_HINT, prompt, None)
    earliest = _hint(_EARLIEST_HINT, prompt, "-24h")
    latest = _hint(_LATEST_HINT, prompt, "now")

    parts = ["search"]
    if index:
        parts.append(f'index="{index}"')
    if sourcetype:
        parts.append(f'sourcetype="{sourcetype}"')
    if values:
        terms = " OR ".join(f'"{v}"' for v in values)
        parts.append(f"({terms})" if len(values) > 1 else terms)
    parts.append(f'earliest="{earliest}" latest="{latest}"')

    if mock:
        by, columns = "srcip, dstip, dstport, action", "_time, srcip, dstip, dstport, user, action, msg"
    else:
        # Group by the fields the request says the values sit in; whole events otherwise.
        named = [f for group in _FIELDS_HINT.findall(prompt) for f in re.split(r"\s+or\s+", group.strip())]
        by, columns = ", ".join(dict.fromkeys(named)) or "sourcetype", None

    if _AGGREGATE.search(prompt):
        tail = f"| stats count by {by} | sort - count | head 20"
    else:
        # `fields *`: searches run in fast mode, which extracts only the fields a
        # search names — without it the rows would be _raw and nothing else.
        tail = f"| table {columns} | head 50" if columns else "| head 50 | fields *"

    return {
        "spl": " ".join(parts) + " " + tail,
        "explanation": (
            f"{'MOCK: a' if mock else 'A'} template filled with the values found in the request "
            f"({', '.join(values) or 'none'}), not Splunk AI Assistant for SPL."
        ),
        "generator": "template",
        "mock": mock,
    }
