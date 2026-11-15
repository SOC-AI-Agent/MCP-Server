"""
One requirement, start to finish: the prompt, the SPL, the check, the rows.

The backend's Splunk stage used to do this itself (Backend:
modules/enrichment/splunk-mcp.service.ts and spl-guard.ts) and call this service
twice per requirement. It now sends what stage 1 stored — the question, the details
from the alert, where to look — to one tool, `splunk_lookup`, and everything
Splunk-shaped happens here:

    build_prompt      the text Text-to-SPL gets
    writer_prompt     the same, with the answer format, for an agent that writes the SPL
    spl_of            the SPL in what Text-to-SPL — or that agent — answered
    with_time_window  the alert's window, when the SPL set none
    with_all_fields   every field of the events, when the SPL names no columns
    spl.check_readonly  nothing that writes, deletes, sends or executes
    trim_row / render what a small model can read

No model runs here. The functions are pure; server.py does the calling.
"""

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from config import settings

# Whole events do not fit a small model's context: keep the fields that carry
# meaning plus a bounded slice of _raw. `host` and `source` on forwarded syslog
# name the forwarder, not the machine the alert is about.
MAX_RAW_CHARS = 800
DROPPED_FIELDS = frozenset({
    "_bkt", "_cd", "_indextime", "_serial", "_si", "_sourcetype", "_kv",
    "linecount", "punct", "splunk_server", "eventtype", "tag", "timestamp", "host", "source",
    # The event's time again, in pieces, and where in _raw it was read from.
    "date_hour", "date_mday", "date_minute", "date_month", "date_second", "date_wday",
    "date_year", "date_zone", "timestartpos", "timeendpos",
})


class FieldHint(BaseModel):
    model_config = ConfigDict(extra="ignore")
    value: str = ""
    fields: list[str] = Field(default_factory=list)


class Metric(BaseModel):
    model_config = ConfigDict(extra="ignore")
    fn: str
    field: str | None = None


class Summary(BaseModel):
    model_config = ConfigDict(extra="ignore")
    group_by: list[str] = Field(default_factory=list)
    metrics: list[Metric] = Field(default_factory=list)
    span: str | None = None
    sort: str | None = None


class Question(BaseModel):
    """What stage 1 stored for one requirement. Names as the backend stores them."""

    # The stored plan carries more (indicatorType, ...); what is not used is not an error.
    model_config = ConfigDict(extra="ignore")

    requirement: str
    index: str | None = None
    sourcetype: str | None = None
    # Where the alert itself came from; said when the requirement is not aimed anywhere.
    alertIndex: str | None = None
    alertSourcetype: str | None = None
    # Details from the alert the requirements agent listed: device, source, user, ...
    context: dict[str, Any] = Field(default_factory=dict)
    # Which field each value sits in here, from the catalogue.
    fieldHints: list[FieldHint] = Field(default_factory=list)
    # The indicator and its fields, on lookups the backend planned itself (no fieldHints).
    indicator: str | None = None
    fields: list[str] = Field(default_factory=list)
    # A playbook's own search: field=value pairs, already this estate's field names.
    filters: dict[str, Any] = Field(default_factory=dict)
    # A playbook's grouped count, fields already resolved.
    summarise: Summary | None = None
    # "How often has this alert fired": the alert's name.
    frequencyOf: str | None = None
    earliest: str | None = None
    latest: str | None = None


_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T")


def to_splunk_time(value: str | None, fallback: str) -> str:
    """A time for SPL's inline earliest=/latest=. They take relative times (-24h) or
    epoch seconds, not the ISO 8601 the alert window is stored in."""
    if not value:
        return fallback
    if _ISO.match(value):
        try:
            return str(int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()))
        except ValueError:
            return value
    return value


def _describe_summary(s: Summary) -> str:
    """A grouped count as one line: "count, dc(dstip) by dstip, dstport per 1h sorted by -count"."""
    metrics = ", ".join(f"{m.fn}({m.field})" if m.field else m.fn for m in s.metrics) or "count"
    parts = [
        metrics,
        f"by {', '.join(s.group_by)}" if s.group_by else "",
        f"per {s.span}" if s.span else "",
        f"sorted by {s.sort}" if s.sort else "",
    ]
    return " ".join(p for p in parts if p)


def _scope(index: str | None, sourcetype: str | None) -> str:
    return " ".join(p for p in (index and f"index={index}", sourcetype and f"sourcetype={sourcetype}") if p)


def alert_frequency_error() -> str | None:
    """Why an alert-frequency query (`frequencyOf`) cannot run on this Splunk, or None."""
    alert_index = settings.SPLUNK_ALERT_INDEX.strip()
    if not alert_index:
        return "alert frequency check is disabled (SPLUNK_ALERT_INDEX is unset)"
    if not settings.mock and not settings.index_restriction_disabled:
        if alert_index not in settings.allowed_indexes:
            return (
                f"alert frequency check is unavailable: SPLUNK_ALERT_INDEX ({alert_index!r}) "
                f"is not in SPLUNK_ALLOWED_INDEXES ({', '.join(settings.allowed_indexes)})"
            )
    return None


def build_prompt(q: Question) -> tuple[str, str, str]:
    """
    The prompt Text-to-SPL gets — the question, the details from the alert it is
    about, where to look, which field each value sits in here, and when — and the
    window, as (prompt, earliest, latest).

        What else did 45.83.122.9 touch in the 24 hours around the alert.
        Details from the alert:
        - source: 45.83.122.9
        - device: FGT-01
        Search index=main sourcetype=fortigate
        Field names in this data: 45.83.122.9 is in srcip or dstip; FGT-01 is in devname. Use these field names.
        Time range: earliest=1790831054 latest=1790917454

    The details and the field names are what Text-to-SPL cannot know on its own:
    which device and which kind of event the question is about, and that this
    estate says `srcip` where CIM says `src_ip`.
    """
    earliest = to_splunk_time(q.earliest, "-24h")
    latest = to_splunk_time(q.latest, "now")
    where = _scope(q.index, q.sourcetype)
    came_from = _scope(q.alertIndex, q.alertSourcetype)

    lines = [re.sub(r"[.\s]+$", "", q.requirement) + "."]
    # Only flat values: they are written as "- key: value" lines.
    details = [(k, v) for k, v in q.context.items() if isinstance(v, (str, int, float, bool))]
    if details:
        lines.append("Details from the alert:")
        lines.extend(f"- {key}: {value}" for key, value in details)
    alert_index = settings.SPLUNK_ALERT_INDEX.strip()
    if q.frequencyOf and alert_index:
        # The alert's own index is the wrong place to count alerts in.
        lines.append(
            f"Fired alerts are in index={alert_index}; "
            f"the alert name is in the field {settings.SPLUNK_ALERT_NAME_FIELD}."
        )
    elif where:
        lines.append(f"Search {where}")
    elif came_from:
        lines.append(f"The alert came from {came_from}")
    if q.filters:
        lines.append("Only events where " + " and ".join(f'{f}="{v}"' for f, v in q.filters.items()) + ".")
    if q.summarise:
        lines.append(f"Summarise: {_describe_summary(q.summarise)}.")
    # Lookups the backend planned itself carry the indicator's fields, not hints.
    hints = q.fieldHints or (
        [FieldHint(value=q.indicator, fields=q.fields)] if q.indicator and q.fields else []
    )
    hints = [h for h in hints if h.value and h.fields]
    if hints:
        lines.append(
            "Field names in this data: "
            + "; ".join(f"{h.value} is in {' or '.join(h.fields)}" for h in hints)
            + ". Use these field names."
        )
    # Values last and unpunctuated: a trailing full stop read as part of the time
    # or the index name is a search for something that does not exist.
    lines.append(f"Time range: earliest={earliest} latest={latest}")
    return "\n".join(lines), earliest, latest


def writer_prompt(prompt: str, limit: int) -> str:
    """
    What an agent that writes the SPL is shown: the request, then the shape of the
    answer. The format is appended here rather than left to the agent's system
    prompt, so what comes back can be read whatever that prompt says — the same
    arrangement as the requirements agent's ANSWER FORMAT.

    Nothing in it is a control. What the agent writes is checked like any other
    SPL (spl.check_readonly), and the token's role decides what can be read.
    """
    if settings.mock:
        where = "Search index=main unless the request names another."
    elif settings.index_restriction_disabled:
        where = "Search the index the request names."
    else:
        where = (
            f"Indexes you may search: {', '.join(settings.allowed_indexes)}. Use the one the request "
            "names; a search over any other index is refused."
        )
    return "\n".join([
        "--- SPLUNK SEARCH REQUEST ---",
        prompt,
        "--- END OF REQUEST ---",
        "",
        "--- ANSWER FORMAT ---",
        "Write ONE Splunk SPL search that answers the request, inside a ```spl code block, and nothing else.",
        f"- Start with `search index=...`. {where}",
        "- Put the time range in the search exactly as given: earliest=... latest=...",
        "- Use the field names the request gives, spelled exactly. Do not guess a field name: a value",
        '  with no field name given is searched as a quoted term, e.g. "203.0.113.7".',
        '- A value said to be in "A or B" is searched in both: (A="v" OR B="v"). Different values are ANDed.',
        '- Quote every value. Write a backslash inside quotes twice: User="CORP\\\\bob".',
        "- Filter before the first pipe, not with `| search` or `| where` after it. No subsearches, no comments.",
        "- Read-only. Never delete, collect, outputlookup, outputcsv, sendemail, sendalert, map, rest,",
        "  script, run or any command that writes or sends data. No macros (backticks).",
        f"- A question about how many, how often or which: count with `stats`. Otherwise end with `| head {min(limit, 50)}`.",
        "",
        "Example of the shape (the values here are not from this request):",
        "```spl",
        'search index=main sourcetype=fortigate earliest=-24h latest=now (srcip="203.0.113.7" OR dstip="203.0.113.7") '
        "| stats count by srcip, dstip, dstport, action | sort - count | head 20",
        "```",
    ])


# Any language tag: a model asked for ```spl answers ```splunk, ```sql or none.
_FENCED = re.compile(r"```[A-Za-z]*[ \t]*\n([\s\S]*?)```")
_SPL_LINE = re.compile(r"^(search\s|index\s*=|\|)", re.IGNORECASE)


def _one_line(spl: str) -> str:
    """A search written over several lines, as one: it is stored and shown as text."""
    return " ".join(line.strip() for line in spl.strip().splitlines() if line.strip())


def spl_of(payload: Any) -> str:
    """The SPL in what Text-to-SPL answered — a field, a fenced block, or the first
    line that is one."""
    if isinstance(payload, dict):
        for key in ("spl", "query", "search"):
            if isinstance(payload.get(key), str):
                return _one_line(payload[key])
    text = "" if payload is None else str(payload)
    fenced = _FENCED.search(text)
    if fenced:
        return _one_line(fenced.group(1))
    return next((line.strip() for line in text.split("\n") if _SPL_LINE.match(line.strip())), "")


_HAS_WINDOW = re.compile(r"\b(earliest|latest)\s*=", re.IGNORECASE)


def with_time_window(spl: str, earliest: str, latest: str) -> str:
    """
    The alert's window, put into a search that does not set its own.

    The search is run as written, so the window has to be in it; Text-to-SPL is
    asked for it, and this is the fallback when it leaves it out. Only a search
    that starts with `search` or `index=` is changed — one that opens with a
    generating command (`| tstats ...`) is left as written.
    """
    if _HAS_WINDOW.search(spl):
        return spl
    window = f"earliest={earliest} latest={latest}"
    if re.match(r"search\s", spl, re.IGNORECASE):
        return re.sub(r"^search\s+", f"search {window} ", spl, count=1, flags=re.IGNORECASE)
    if re.match(r"index\s*=", spl, re.IGNORECASE):
        return f"search {window} {spl}"
    return spl


# Commands that decide a search's columns themselves. A search with none of them
# returns events, and — run through the API — only the fields it happens to name.
_NAMES_COLUMNS = frozenset({
    "stats", "chart", "timechart", "top", "rare", "table", "fields", "tstats", "mstats",
    "sistats", "sichart", "sitimechart", "sitop", "sirare", "geostats", "contingency",
    "xyseries", "transpose", "eventcount", "metadata",
})
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def with_all_fields(spl: str, limit: int) -> str:
    """
    Every field of the events, for a search that returns events and names no columns.

    A search sent over the REST API extracts only the fields it mentions: `index=main
    "10.1.100.11" | head 50` comes back as _raw and nothing an analyst can read
    column by column. `| fields *` asks for all of them. `| head` goes in first when
    the search has none, so the extraction is over the rows that are kept and not
    over everything in the window.

    A search that opens with a generating command, or has a subsearch, is left as
    written.
    """
    bare = _QUOTED.sub('""', spl)
    if bare.lstrip().startswith("|") or "[" in bare:
        return spl
    commands = {m.group(1).lower() for m in (re.match(r"\s*([A-Za-z_]+)", seg) for seg in bare.split("|")[1:]) if m}
    if commands & _NAMES_COLUMNS:
        return spl
    head = "" if commands & {"head", "tail"} else f" | head {limit}"
    return f"{spl.rstrip()}{head} | fields *"


def trim_row(row: dict) -> dict:
    trimmed = {}
    for key, value in row.items():
        if key in DROPPED_FIELDS:
            continue
        if key == "_raw" and isinstance(value, str) and len(value) > MAX_RAW_CHARS:
            value = f"{value[:MAX_RAW_CHARS]}… [{len(value) - MAX_RAW_CHARS} chars truncated]"
        trimmed[key] = value
    return trimmed


def render(spl: str, rows: list[dict], capped: bool, limit: int, mock: bool) -> str:
    """The answer as an analyst reads it: what ran, how much came back, the rows."""
    count = len(rows)
    head = f"Splunk ran: {spl}\n{f'At least {count}' if capped else count} row(s)."
    if capped:
        head += f" Stopped at {limit}; there may be more."
    if mock:
        head += "\nMOCK DATA from the development connector — not real Splunk results."
    if count == 0:
        return f"{head}\nNothing matched in that window."
    lines = [
        "- " + "  ".join(f"{k}={v}" for k, v in row.items() if v is not None and v != "" and k != "_raw")
        for row in rows
    ]
    return "\n".join([head, *lines])
