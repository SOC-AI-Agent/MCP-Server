import sys

if sys.version_info < (3, 12):
    raise SystemExit(
        f"needs Python 3.12 (the version the services run), found "
        f"{sys.version.split()[0]}.\n"
        "macOS ships 3.9 as python3; use the project venv:\n"
        "  python3.12 -m venv .venv && .venv/bin/python -m pip install -q -r scripts/requirements.txt\n"
        "  .venv/bin/python " + " ".join(sys.argv)
    )
#!/usr/bin/env python3
"""
Decide whether a Splunk catalog export is complete enough to use.

    python3 scripts/verify_catalog_export.py Splunk/table

Exit 0 means usable, 1 means not. There is one definition of "usable" and both
callers share it: CI asks this before exporting (is there already one?) and
again afterwards (did the export actually work?). Two separate checks would
drift, and the day they disagree is the day a half-written catalog gets
committed because the "is it there?" test was looser than the "did it work?"
test.

A directory that exists is not the question. An export that died after writing
indexes.json leaves a directory behind, and a catalog listing 3 of an estate's
200 sourcetypes is worse than no catalog at all: the agent is told the estate
is small, searches the handful it was given, finds nothing, and reports that
nothing happened. Missing is recoverable; confidently incomplete is not.
"""

import argparse
import glob
import json
import os


class Incomplete(Exception):
    """Why this export cannot be used."""


def _load(path: str) -> object:
    if not os.path.isfile(path):
        raise Incomplete(f"{os.path.basename(path)} is missing")
    try:
        with open(path) as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise Incomplete(f"{os.path.basename(path)} is not valid JSON ({exc})") from exc
    except OSError as exc:
        raise Incomplete(f"{os.path.basename(path)} is unreadable ({exc})") from exc


def check(directory: str) -> dict:
    """Return a summary of the export, or raise Incomplete saying what is wrong."""
    if not os.path.isdir(directory):
        raise Incomplete(f"{directory} does not exist")

    indexes = _load(os.path.join(directory, "indexes.json"))
    if not isinstance(indexes, dict) or not indexes:
        raise Incomplete("indexes.json holds no indexes")

    # Every index/sourcetype pair the enumeration found should have its fields
    # exported. A pair without one means the per-sourcetype loop stopped early
    # — the failure this whole check exists to catch.
    expected = {
        (index, entry["sourcetype"])
        for index, entries in indexes.items()
        if isinstance(entries, list)
        for entry in entries
        if isinstance(entry, dict) and entry.get("sourcetype")
    }
    if not expected:
        raise Incomplete("indexes.json lists no sourcetypes")

    found, empty = set(), []
    for path in glob.glob(os.path.join(directory, "fields__*.json")):
        data = _load(path)
        if not isinstance(data, dict):
            raise Incomplete(f"{os.path.basename(path)} is not an object")
        pair = (data.get("index"), data.get("sourcetype"))
        found.add(pair)
        if not data.get("fields"):
            empty.append(f"{pair[0]}/{pair[1]}")

    missing = expected - found
    if missing:
        listed = ", ".join(f"{i}/{s}" for i, s in sorted(missing)[:5])
        more = f" (+{len(missing) - 5} more)" if len(missing) > 5 else ""
        raise Incomplete(f"{len(missing)} sourcetype(s) have no fields file: {listed}{more}")

    # datamodels.json decides whether CIM names are safe to assume, so an
    # export without it leaves that question open rather than answered.
    _load(os.path.join(directory, "datamodels.json"))

    return {
        "indexes": len(indexes),
        "sourcetypes": len(expected),
        # Not fatal: a sourcetype with no events in the sample window really
        # does have no fields to report. Worth printing so nobody reads a
        # silent zero as a full answer.
        "empty": empty,
    }


def main() -> int:
    # Not __doc__: the version guard runs before the docstring, so the
    # docstring is not the module's first statement and __doc__ is None.
    parser = argparse.ArgumentParser(
        description="Decide whether a Splunk catalog export is complete enough to use."
    )
    parser.add_argument("directory", help="the export directory to check")
    parser.add_argument("--quiet", action="store_true", help="say nothing, just set the exit code")
    args = parser.parse_args()

    try:
        summary = check(args.directory)
    except Incomplete as exc:
        if not args.quiet:
            print(f"unusable: {exc}")
        return 1

    if not args.quiet:
        print(
            f"usable: {summary['indexes']} indexes, "
            f"{summary['sourcetypes']} sourcetypes"
        )
        if summary["empty"]:
            shown = ", ".join(summary["empty"][:5])
            more = f" (+{len(summary['empty']) - 5} more)" if len(summary["empty"]) > 5 else ""
            print(f"  no fields sampled for: {shown}{more}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
