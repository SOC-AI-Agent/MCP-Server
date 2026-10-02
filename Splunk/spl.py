"""
What this service will and will not run.

Two checks, for two callers:

- `check_readonly`, for `splunk_run_query`: SPL that Text-to-SPL wrote, so the whole
  read-only language is allowed and a denylist refuses what writes, deletes, sends
  data out or executes — in subsearches too. The backend runs the same list
  (Backend: modules/enrichment/spl-guard.ts) before it sends anything.
- `check_query`, for `POST /query`: a strict allowlist for SPL a person sends by hand.

Neither takes its caller on trust — a bug in one place, or a caller that is not the
backend, should not be enough to run `| delete`.

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


# What a generated search may not do. A denylist, unlike ALLOWED_COMMANDS above:
# SPL written by Splunk AI Assistant uses the whole read-only language (table, eval,
# where, dedup, timechart, ...), and refusing all of that would refuse most of what
# it writes. These are the commands that write, delete, send data out or execute:
# Splunk's own list of risky commands (SPL safeguards), plus summaryindex (collect's
# alias), outputtext, rest, crawl and DB Connect's dbxquery/dbxoutput. Splunk's
# safeguard is only a warning in Splunk Web; a search sent over the API gets no such
# check, hence this.
# https://help.splunk.com/en/splunk-cloud-platform/administer/manage-users-and-security/10.5.2605/best-practices-for-splunk-platform-security/spl-safeguards-for-risky-commands
# The backend (Backend: modules/enrichment/spl-guard.ts) keeps the same list.
FORBIDDEN_COMMANDS = frozenset({
    "delete", "collect", "mcollect", "meventcollect", "tscollect", "summaryindex",
    "outputlookup", "outputcsv", "outputtext", "sendemail", "sendalert", "script",
    "run", "runshellscript", "map", "dump", "rest", "dbxquery", "dbxoutput", "crawl",
})
_ANY_INDEX_TERM = re.compile(r'\bindex\s*=\s*"?([^\s"|)\]]+)"?', re.IGNORECASE)


def check_readonly(query: object) -> str:
    """
    Refuse a generated search that writes, deletes, sends data out or executes, or
    that reads an index outside SPLUNK_ALLOWED_INDEXES (when one is set).

    For SPL that came from Text-to-SPL rather than from the backend's own plans. Every
    command is checked, including those inside a subsearch; a macro is refused because
    what it expands to cannot be seen from here.
    """
    if not isinstance(query, str) or not query.strip():
        raise QueryError("query is required")
    query = query.strip()
    if len(query) > MAX_QUERY_LEN:
        raise QueryError(f"query too long (max {MAX_QUERY_LEN} chars)")
    if "\x00" in query:
        raise QueryError("query may not contain null bytes")

    bare = _QUOTED.sub('""', query)
    if '"' in bare.replace('""', ""):
        raise QueryError("query has an unbalanced quote")
    if "`" in bare:
        raise QueryError("macros are not allowed: what they expand to cannot be checked")

    for segment in re.split(r"[|\[]", bare):
        match = _COMMAND.match(segment)
        if match and match.group(1).lower() in FORBIDDEN_COMMANDS:
            raise QueryError(f"command {match.group(1).lower()!r} is not allowed in a read-only search")

    if settings.allowed_indexes and not settings.index_restriction_disabled:
        for name in _ANY_INDEX_TERM.findall(query):
            if "*" in name or name not in settings.allowed_indexes:
                raise QueryError(
                    f"index {name!r} is not allowed; permitted: {', '.join(settings.allowed_indexes)}"
                )
    return query


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
