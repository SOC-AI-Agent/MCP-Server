"""
What this service will and will not run.

The backend writes the SPL (Backend: modules/enrichment/spl.ts) and sends it to
/query. It is built there from a plan, with every value quoted and every name
checked, but this service does not take that on trust: `check_query` refuses anything
that is not a read-only search over an allowed index, whoever wrote it. The same rules,
checked twice — a bug in one place, or a caller that is not the backend, should not be
enough to run `| delete`.

The quoting helpers below are what /catalog and the connection check use to build the
few searches this service writes for itself.
"""

import re

from config import settings


class QueryError(ValueError):
    """Something this service will not run. Routes answer it with a 400."""


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
        raise QueryError(f"value too long (max {MAX_VALUE_LEN} chars)")
    if any(ch in value for ch in "\r\n\x00"):
        raise QueryError("value may not contain newlines or null bytes")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def check_time(value: str, label: str) -> str:
    if not _TIME_RE.match(value):
        raise QueryError(
            f"invalid {label}: {value!r} — use a relative modifier (-24h, -7d@d), "
            f"an ISO-8601 timestamp, an epoch, or 'now'"
        )
    return value


def check_count(requested: int) -> int:
    if requested < 1:
        raise QueryError("count must be >= 1")
    return min(requested, settings.SPLUNK_MAX_COUNT)


def check_index(name: str) -> str:
    """Reject anything outside the configured allowlist."""
    if not _INDEX_RE.match(name):
        raise QueryError(f"invalid index name: {name!r}")
    if settings.index_restriction_disabled:
        return name
    if name not in settings.allowed_indexes:
        raise QueryError(
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


# ── check_query ─────────────────────────────────────────────────────────────

# The commands the backend's own searches use, and nothing else. An allowlist,
# because the list of SPL commands that write or reach out (delete, collect,
# outputlookup, outputcsv, sendemail, script, run, map, rest, dbxquery, ...) is long
# and grows with every release; the list of commands a read-only search needs is short.
ALLOWED_COMMANDS = frozenset({"search", "tstats", "makeresults", "bin", "stats", "sort", "head"})
# Searches over data. A `makeresults` on its own reads nothing, so it needs no index.
_READS_DATA = frozenset({"search", "tstats"})

MAX_QUERY_LEN = 4000

_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
_COMMAND = re.compile(r"\s*([A-Za-z_]+)")
# `index="main"`, as it is looked for in the query as written…
_INDEX_TERM = re.compile(r'\bindex\s*=\s*"((?:[^"\\]|\\.)*)"')
# …and as it looks once every quoted literal has been reduced to "".
_QUOTED_INDEX_TERM = re.compile(r'\bindex\s*=\s*""')
# Any other way of naming an index: `index=main`, `index=*`, `index IN (…)`, `index!=…`.
_OTHER_INDEX_TERM = re.compile(r"\bindex\s*(?:!=|<=|>=|=|<|>|\s+IN\b|\s+NOT\b)", re.IGNORECASE)


def check_query(query: object) -> str:
    """
    Refuse anything that is not a read-only search over an allowed index.

    Quoted literals are set aside first, so a value like `blocked" | delete | head 1`
    — safely inside its quotes, as the backend writes it — is not mistaken for a
    command, and a real `| delete` outside any quotes is not missed. What is left is
    checked for: subsearches and macros (which can hide a second search), any command
    outside the short list above, and an index that is not named as `index="allowed"`.
    """
    if not isinstance(query, str) or not query.strip():
        raise QueryError("spl is required")
    query = query.strip()
    if len(query) > MAX_QUERY_LEN:
        raise QueryError(f"spl too long (max {MAX_QUERY_LEN} chars)")
    if any(ch in query for ch in "\r\n\x00"):
        raise QueryError("spl may not contain newlines or null bytes")

    bare = _QUOTED.sub('""', query)
    if '"' in bare.replace('""', ""):
        raise QueryError("spl has an unbalanced quote")
    if any(ch in bare for ch in "[]`"):
        raise QueryError("subsearches and macros are not allowed")

    segments = bare.split("|")
    commands: list[str] = []
    for position, segment in enumerate(segments):
        if position == 0 and not segment.strip():
            continue  # a query that opens with a pipe, like `| tstats ...`
        match = _COMMAND.match(segment)
        if not match:
            raise QueryError("spl has an empty command")
        name = match.group(1).lower()
        if position == 0 and name != "search":
            raise QueryError("spl must start with `search` or a `|` command")
        if name not in ALLOWED_COMMANDS:
            raise QueryError(
                f"command {name!r} is not allowed; permitted: {', '.join(sorted(ALLOWED_COMMANDS))}"
            )
        commands.append(name)

    if settings.index_restriction_disabled or not _READS_DATA & set(commands):
        return query

    # Any index named some other way — unquoted, a wildcard, IN (...), != — is refused
    # before anything is read into the allowlist check, because those are the forms
    # that would slip a name past it.
    if _OTHER_INDEX_TERM.search(_QUOTED_INDEX_TERM.sub("", bare)):
        raise QueryError('an index must be written index="name", quoted and exact')
    named = _INDEX_TERM.findall(query)
    if not named:
        raise QueryError('the search must name an index, as index="name"')
    for raw in named:
        check_index(raw.replace('\\"', '"').replace("\\\\", "\\"))
    return query
