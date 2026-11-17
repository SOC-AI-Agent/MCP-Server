"""
Text-to-SPL without Splunk AI Assistant: a template.

Splunk's own Text-to-SPL (`saia_generate_spl`, Splunk AI Assistant for SPL) exists
only in a Splunk that has the assistant — not in a plain Splunk container, and not
in mock mode. This writes the search instead: the index, sourcetype and window the
request names, the values found in it as search terms, and a count when the
question is one. No model, and nothing clever on purpose.

The request is the one lookup.build_prompt writes, so its three structured lines
are read as written rather than guessed at:

    Field names in this data: V is in f1 or f2; ...   -> (f1="V" OR f2="V"), one per value, all required
    Only events where f="v" and g="w".                -> f="v" g="w"
    Summarise: count, dc(f) by a, b per 1h sorted by -count.   -> | bin | stats ... by ... | sort

A value searched in its field is what makes "what did this address reach" a
different search from "what reached it"; as a bare term the two are the same.

Used in SPLUNK_MODE=mock, and in live when SPLUNK_SAIA_MCP_URL is blank. Mock
mode reads none of the structured lines: its search (mock.py) understands terms,
`| table`, `| stats count by` and `| head`, and nothing else.
"""

# So setup.py in external/splunk can import this with an older system python3.
from __future__ import annotations

import re

MOCK_INDEX = "main"


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
# Require an explicit `=` or `:` so English prose like "user associated" is not
# read as a user called "associated".
_USER = re.compile(r"\buser(?:name)?\b\s*[=:]\s*\"?([A-Za-z0-9_.\-@\\]{2,64})", re.IGNORECASE)
_INDEX_HINT = re.compile(r"\bindex\s*[=:]?\s*\"?([A-Za-z0-9_\-]+)", re.IGNORECASE)
_SOURCETYPE_HINT = re.compile(r"\bsourcetype\s*[=:]?\s*\"?([A-Za-z0-9_:\-]+)", re.IGNORECASE)
_EARLIEST_HINT = re.compile(r"\bearliest\s*[=:]?\s*\"?([^\s\",)]+)", re.IGNORECASE)
_LATEST_HINT = re.compile(r"\blatest\s*[=:]?\s*\"?([^\s\",)]+)", re.IGNORECASE)
_FIELD = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*"
# Questions about how much, or with whom, read better as a count than as a list.
_AGGREGATE = re.compile(
    r"\b(how many|count|top|most|frequen|which (?:hosts?|address|destinations?|ports?)|"
    r"talk(?:ed|ing)? to|connect(?:ed|ions?)? to|destinations?|distinct)\b",
    re.IGNORECASE,
)

# The structured lines of lookup.build_prompt.
# "45.83.122.9 is in srcip or dstip; FGT-01 is in devname"
_HINTS_LINE = re.compile(r"^Field names in this data: (.+)\. Use these field names\.$", re.MULTILINE)
_HINT = re.compile(rf"^(.+) is in ({_FIELD}(?: or {_FIELD})*)$")
_FILTERS_LINE = re.compile(r"^Only events where (.+)\.$", re.MULTILINE)
_FILTER = re.compile(rf'({_FIELD})="([^"]*)"')
_SUMMARY_LINE = re.compile(
    r"^Summarise: (?P<metrics>.+?)(?: by (?P<by>.+?))?(?: per (?P<span>\S+?))?(?: sorted by (?P<sort>\S+?))?\.$",
    re.MULTILINE,
)
_METRIC = re.compile(rf"^([a-z_]+)(?:\(({_FIELD})\))?$")
# lookup-plans.json's names for them, and SPL's.
_STATS_FN = {"count": "count", "distinct_count": "dc", "dc": "dc", "values": "values",
             "sum": "sum", "avg": "avg", "min": "min", "max": "max"}
_SPAN = re.compile(r"^\d+(?:s|m|h|d|w|mon)$")


def _hint(pattern: re.Pattern, prompt: str, default: str | None) -> str | None:
    """A value named in the request, without the sentence's punctuation after it."""
    found = pattern.search(prompt)
    return found.group(1).rstrip(".,;:") if found else default


def _quote(value: str) -> str:
    """A value as an SPL quoted literal. A backslash written once matches nothing:
    `User="CORP\\bob"` has to reach Splunk as `CORP\\\\bob`. (spl.quote_value does
    the same; this file imports nothing so setup.py can load it.)"""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _hints(prompt: str) -> dict[str, list[str]]:
    """Each value the request places in a field, and the fields: {value: [field, ...]}."""
    placed: dict[str, list[str]] = {}
    line = _HINTS_LINE.search(prompt)
    for part in line.group(1).split("; ") if line else []:
        found = _HINT.match(part)
        if found:
            fields = placed.setdefault(found.group(1), [])
            fields.extend(f for f in re.split(r"\s+or\s+", found.group(2)) if f not in fields)
    return placed


def _stats(prompt: str) -> str | None:
    """The request's `Summarise:` line as SPL, or None when it has none this can write."""
    found = _SUMMARY_LINE.search(prompt)
    if not found:
        return None
    metrics = []
    for metric in found.group("metrics").split(", "):
        parsed = _METRIC.match(metric.strip())
        fn = _STATS_FN.get(parsed.group(1)) if parsed else None
        if not fn or (fn != "count" and not parsed.group(2)):
            return None
        metrics.append(f"{fn}({parsed.group(2)})" if parsed.group(2) else fn)
    by = [f for f in (found.group("by") or "").split(", ") if f]
    span = found.group("span")
    if any(not re.fullmatch(_FIELD, f) for f in by) or (span and not _SPAN.match(span)):
        return None

    out = ""
    if span:
        # One row per span: the shape "is it a steady beat" is read from.
        out, by = f"| bin _time span={span} ", ["_time", *by]
    out += f"| stats {', '.join(metrics)}" + (f" by {', '.join(by)}" if by else "")
    sort = found.group("sort") or ""
    key = sort.lstrip("+-")
    if key == "count" or key in by:
        out += f" | sort {'- ' if sort.startswith('-') else ''}{key}"
    # A span's rows are the answer in time order; a cut would drop the latest ones.
    return out if span else f"{out} | head 20"


# Fields that store a full path (e.g. `%systemroot%\PKSnPlKq.exe` or `C:\Windows\PKSnPlKq.exe`)
# when the alert indicator is just the filename (`PKSnPlKq.exe`), or a path without query string.
PATH_FIELDS = {
    "Image", "ParentImage", "Service_File_Name", "TargetFilename", "SourceImage", "TargetImage", "ImageLoaded",
}
_PATH_FIELDS = PATH_FIELDS


def _match_expr(field: str, value: str) -> str:
    if field == "SHA256" and len(value) == 32 and re.fullmatch(r"[0-9A-Fa-f]{32}", value):
        return f"Hashes={_quote('*' + value + '*')}"
    if field == "Image":
        val = f"*{value}" if ("\\" not in value and "/" not in value and not value.startswith("*")) else value
        return f"Image={_quote(val)} OR ParentImage={_quote(val)}"
    if field in _PATH_FIELDS and "\\" not in value and "/" not in value and not value.startswith("*"):
        return f"{field}={_quote('*' + value)}"
    if field == "uri_path" and "?" in value:
        return f'uri={_quote(value)} OR uri_path={_quote(value.split("?", 1)[0])}'
    return f"{field}={_quote(value)}"


def generate(prompt: str, mock: bool = False) -> dict:
    """The SPL for a request, and how it was arrived at.

    mock=True is the development estate: its index when none is named, and its
    columns in the answer. Otherwise nothing about the data is assumed — the index
    and field names are the ones the request names.
    """
    placed = {} if mock else _hints(prompt)
    filter_line = None if mock else _FILTERS_LINE.search(prompt)
    filters = _FILTER.findall(filter_line.group(1)) if filter_line else []
    stats = None if mock else _stats(prompt)

    # Values with no field named for them: searched as bare terms only when the
    # request carries no structured fieldHints or filters (or in mock mode).
    values: list[str] = []
    if mock or (not placed and not filters):
        scan = prompt if mock else _SUMMARY_LINE.sub("", _FILTERS_LINE.sub("", _HINTS_LINE.sub("", prompt)))
        for found in (_IPV4.findall(scan) + _HASH.findall(scan)
                      + [m.group(1).rstrip(".,;:") for m in _USER.finditer(scan)]):
            if found not in values and found not in placed:
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
    # Every placed value has to be there: details narrow a search, they do not widen it.
    for value, fields in placed.items():
        exprs = [_match_expr(f, value) for f in fields]
        alternatives = " OR ".join(exprs)
        parts.append(f"({alternatives})" if len(exprs) > 1 or " OR " in alternatives else alternatives)
    parts.extend(f"{f}={_quote(v)}" for f, v in filters)
    if values:
        # Mock mode's search compares a term as written, so it is left unescaped there.
        terms = " OR ".join(f'"{v}"' if mock else _quote(v) for v in values)
        parts.append(f"({terms})" if len(values) > 1 else terms)
    parts.append(f'earliest="{earliest}" latest="{latest}"')

    if mock:
        by, columns = "srcip, dstip, dstport, action", "_time, srcip, dstip, dstport, user, action, msg"
    else:
        # Group by the fields the request says the values sit in; whole events otherwise.
        named = [f for fields in placed.values() for f in fields]
        by, columns = ", ".join(dict.fromkeys(named)) or "sourcetype", None

    if stats:
        tail = stats
    elif _AGGREGATE.search(prompt):
        tail = f"| stats count by {by} | sort - count | head 20"
    else:
        # `fields *`: searches run in fast mode, which extracts only the fields a
        # search names — without it the rows would be _raw and nothing else.
        tail = f"| table {columns} | head 50" if columns else "| head 50 | fields *"

    searched = [*placed, *(v for _, v in filters), *values]
    return {
        "spl": " ".join(parts) + " " + tail,
        "explanation": (
            f"{'MOCK: a' if mock else 'A'} template filled with the values found in the request "
            f"({', '.join(searched) or 'none'}), not Splunk AI Assistant for SPL."
        ),
        "generator": "template",
        "mock": mock,
    }
