"""
SPL construction, done here and never by the model.

Tools take structured parameters; this module turns them into the one search
string that reaches Splunk. Nothing a caller supplies is interpolated raw, so a
value carried in from an attacker-controlled log field cannot close the quote
and append `| delete`.
"""

import re

from mcp.server.mcpserver.exceptions import ToolError

from config import settings

_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,63}$")
_INDEX_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}$")
_TIME_RE = re.compile(
    r"^(?:now"
    r"|[+-]?\d{1,6}(?:s|m|h|d|w|mon|y)(?:@[a-z]{1,3})?"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?"
    r"|\d{10})$"
)

MAX_VALUE_LEN = 512


def quote_value(value: str) -> str:
    """Render a value as an SPL double-quoted literal."""
    if not isinstance(value, str):
        value = str(value)
    if len(value) > MAX_VALUE_LEN:
        raise ToolError(f"value too long (max {MAX_VALUE_LEN} chars)")
    if any(ch in value for ch in "\r\n\x00"):
        raise ToolError("value may not contain newlines or null bytes")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def check_field(name: str) -> str:
    if not _FIELD_RE.match(name):
        raise ToolError(f"invalid field name: {name!r}")
    return name


def check_time(value: str, label: str) -> str:
    if not _TIME_RE.match(value):
        raise ToolError(
            f"invalid {label}: {value!r} — use a relative modifier (-24h, -7d@d), "
            f"an ISO-8601 timestamp, an epoch, or 'now'"
        )
    return value


def check_count(requested: int) -> int:
    if requested < 1:
        raise ToolError("max_count must be >= 1")
    return min(requested, settings.SPLUNK_MAX_COUNT)


def check_index(name: str) -> str:
    """Reject anything outside the configured allowlist."""
    if not _INDEX_RE.match(name):
        raise ToolError(f"invalid index name: {name!r}")
    if settings.index_restriction_disabled:
        return name
    if name not in settings.allowed_indexes:
        raise ToolError(
            f"index {name!r} is not allowed; permitted: {', '.join(settings.allowed_indexes)}"
        )
    return name


def index_clause(index: str | None) -> str:
    """`index=` for one index, or an OR over the whole allowlist when unscoped."""
    if index is not None:
        return f"index={quote_value(check_index(index))}"
    if settings.index_restriction_disabled:
        return "index=*"
    terms = [f"index={quote_value(i)}" for i in settings.allowed_indexes]
    return "(" + " OR ".join(terms) + ")" if len(terms) > 1 else terms[0]


def equality_terms(filters: dict[str, str]) -> str:
    """`field="value"` pairs, ANDed."""
    return " ".join(
        f"{check_field(field)}={quote_value(value)}"
        for field, value in filters.items()
        if value is not None
    )


# Aggregation functions a caller may ask for, and how each is written. An
# allowlist rather than a check, because the whole point of building SPL here is
# that no caller-supplied string reaches the search — `fn` is a key into this,
# never text that gets interpolated.
STATS_FUNCTIONS = {
    "count": "count",
    "distinct_count": "dc",
    "sum": "sum",
    "avg": "avg",
    "min": "min",
    "max": "max",
    # The values themselves, not just how many. Capped by Splunk at
    # `maxvalues`; useful for "which destinations", dangerous for a field with
    # a million distinct values, so callers get a small ceiling.
    "values": "values",
}

# 5m, 1h, 1d. Splunk accepts more, but a span is a bucket size and these are
# the sizes anyone means.
_SPAN_RE = re.compile(r"^\d{1,4}(?:s|m|h|d)$")

MAX_GROUP_BY = 4
MAX_METRICS = 6
MAX_VALUES = 20


def check_span(value: str) -> str:
    if not _SPAN_RE.match(value):
        raise ToolError(
            f"invalid span: {value!r} — use a bucket size like 5m, 1h or 1d"
        )
    return value


def stats_clause(metrics: list[dict], group_by: list[str]) -> str:
    """
    `| stats count, dc(dstip) as dstip_distinct by srcip, action`

    Every field goes through check_field and every function through the
    allowlist above, so nothing a caller wrote is interpolated into SPL. The
    output column is named after what produced it, because a column called
    `dc(dstip)` is awkward to read and impossible to sort on by name.
    """
    if not metrics:
        raise ToolError("at least one metric is required")
    if len(metrics) > MAX_METRICS:
        raise ToolError(f"too many metrics (max {MAX_METRICS})")
    if len(group_by) > MAX_GROUP_BY:
        raise ToolError(f"too many group_by fields (max {MAX_GROUP_BY})")

    parts: list[str] = []
    for metric in metrics:
        name = (metric or {}).get("fn")
        if name not in STATS_FUNCTIONS:
            raise ToolError(
                f"unknown metric {name!r}; available: {', '.join(sorted(STATS_FUNCTIONS))}"
            )
        fn = STATS_FUNCTIONS[name]
        if name == "count":
            parts.append("count")
            continue
        field = (metric or {}).get("field")
        if not field:
            raise ToolError(f"metric {name!r} needs a field")
        check_field(field)
        column = f"{field}_{name}"
        if name == "values":
            parts.append(f"values({field}) as {column}")
        else:
            parts.append(f"{fn}({field}) as {column}")

    clause = "stats " + ", ".join(parts)
    if group_by:
        clause += " by " + ", ".join(check_field(f) for f in group_by)
    return clause


def sort_clause(sort: str | None, allowed: set[str]) -> str:
    """
    `| sort -count`. The column must be one the stats above actually produced —
    sorting on a column that does not exist is silently ignored by Splunk, and
    the caller would read the first rows as the largest.
    """
    if not sort:
        return ""
    descending = sort.startswith("-")
    column = sort[1:] if descending else sort
    if column not in allowed:
        raise ToolError(
            f"cannot sort on {column!r}; the search produces: {', '.join(sorted(allowed))}"
        )
    return f"| sort {'-' if descending else ''}{check_field(column)} "


def any_of_terms(fields: list[str], value: str) -> str:
    """`(a="v" OR b="v")` — one indicator across several possible field names."""
    quoted = quote_value(value)
    return "(" + " OR ".join(f"{check_field(f)}={quoted}" for f in fields) + ")"
