#!/usr/bin/env bash
# Export a Splunk data catalog: indexes, sourcetypes, and the fields in each.
#
#   SPLUNK_URL=https://splunk.example.com:8089 \
#   SPLUNK_AUTH='Bearer eyJ…'  \
#   ./export_catalog.sh
#
# Writes machine-readable JSON plus a Markdown summary meant to be pasted into
# an agent's data guide.
set -euo pipefail

: "${SPLUNK_URL:?set SPLUNK_URL, e.g. https://splunk.example.com:8089}"
: "${SPLUNK_AUTH:?set SPLUNK_AUTH as 'user:password' or 'Bearer <token>'}"
WINDOW="${WINDOW:--30d}"
SAMPLE="${SAMPLE:-200}"
OUT="${OUT:-splunk-catalog}"
# Lab Splunks use self-signed certs, so skipping verification stays the default
# here. Set SPLUNK_INSECURE=0 when the cert is real — CI does, because pulling
# the estate's schema over a connection anyone can sit in the middle of is a
# different risk from doing it on your own laptop against a container.
SPLUNK_INSECURE="${SPLUNK_INSECURE:-1}"

mkdir -p "$OUT"
if [[ "$SPLUNK_AUTH" == Bearer* ]]; then AUTH=(-H "Authorization: $SPLUNK_AUTH")
else AUTH=(-u "$SPLUNK_AUTH"); fi
if [[ "$SPLUNK_INSECURE" == "1" ]]; then TLS=(-k); else TLS=(); fi
# Expanded as ${TLS[@]+...}: under `set -u`, bash 3.2 — which is what
# macOS ships — treats "${TLS[@]}" on an empty array as an unbound
# variable and aborts, so verifying the certificate would break the
# script rather than verify anything.

search() {
  # `local body` and the assignment are kept apart, and the call is followed by
  # `|| status=$?`. Both matter under `set -e`: a bare `body=$(curl ...)` that
  # fails exits the script before any check below it can run, and `local` of
  # its own resets $?. Between them the error handling here never ran at all.
  local body
  local status=0
  # --fail-with-body turns an HTTP error into a non-zero exit while still
  # showing what Splunk said. Without it a 401 is "success" with no results,
  # and the export finishes cleanly having written an empty catalog — which
  # reads exactly like an estate that genuinely has no indexes.
  body=$(curl -sS --fail-with-body ${TLS[@]+"${TLS[@]}"} "${AUTH[@]}" \
    -X POST "$SPLUNK_URL/services/search/jobs" \
    --data-urlencode "search=$1" --data-urlencode 'exec_mode=oneshot' \
    --data-urlencode "earliest_time=$WINDOW" --data-urlencode 'latest_time=now' \
    --data-urlencode 'output_mode=json') || status=$?

  if [ "$status" -ne 0 ]; then
    echo "" >&2
    echo "export failed talking to $SPLUNK_URL (curl exit $status)" >&2
    case "$status" in
      60) echo "  certificate verification — set SPLUNK_INSECURE=1 for a self-signed lab cert" >&2 ;;
      22) echo "  HTTP error — check SPLUNK_AUTH and whether the token has expired" >&2 ;;
      7)  echo "  could not connect — is the management port (8089) reachable from here?" >&2 ;;
      28) echo "  timed out — Splunk is reachable but did not answer in time" >&2 ;;
    esac
    [ -n "$body" ] && echo "  Splunk said: $(printf '%s' "$body" | head -c 200)" >&2
    echo "  search was: $1" >&2
    return "$status"
  fi
  if [ -z "$body" ]; then
    echo "" >&2
    echo "Splunk returned an empty body for: $1" >&2
    return 1
  fi
  printf '%s' "$body"
}

echo "1/4  data models (is this estate CIM-normalised?)"
search '| rest /services/data/models | table title' | python3 -c "
import json,sys
names = [r['title'] for r in json.load(sys.stdin).get('results', [])]
external = [n for n in names if not n.startswith('internal_')]
print('     ', ', '.join(external) if external else '(none beyond Splunk internals — fields are NOT CIM-normalised)')
json.dump(names, open('$OUT/datamodels.json','w'), indent=2)"

echo "2/4  indexes and sourcetypes"
search '| tstats count where index=* by index, sourcetype' | python3 -c "
import json,sys,collections
rows = json.load(sys.stdin).get('results', [])
by_index = collections.defaultdict(list)
for r in rows:
    by_index[r['index']].append({'sourcetype': r['sourcetype'], 'events': int(r['count'])})
for idx, sts in sorted(by_index.items()):
    total = sum(s['events'] for s in sts)
    print(f\"      {idx:22} {total:>12,} events  {', '.join(s['sourcetype'] for s in sts[:4])}\")
json.dump(by_index, open('$OUT/indexes.json','w'), indent=2)
# Trailing newline matters: without it \`read\` returns false on the last line
# and the loop below silently never runs.
with open('$OUT/_pairs.txt','w') as f:
    for r in rows:
        f.write(f\"{r['index']}\t{r['sourcetype']}\n\")"

echo "3/4  fields per sourcetype (sampling $SAMPLE events each)"
while IFS=$'\t' read -r index sourcetype; do
  [ -z "${index:-}" ] && continue
  safe="${index}__${sourcetype//[^A-Za-z0-9_-]/_}"
  search "search index=\"$index\" sourcetype=\"$sourcetype\" | head $SAMPLE | fieldsummary maxvals=3" \
    | python3 -c "
import json,sys
fields = {}
for r in json.load(sys.stdin).get('results', []):
    name = r['field']
    # _raw is the whole event; punct/linecount/eventtype/tag are Splunk
    # bookkeeping. None of them help anyone decide which field means 'source IP'.
    if name.startswith('_') or name in ('punct','linecount','eventtype','tag'):
        continue
    try:
        vals = [str(v['value'])[:40] for v in json.loads(r.get('values','[]'))[:3]]
    except Exception:
        vals = []
    fields[name] = {'distinct': r.get('distinct_count'), 'examples': vals}
json.dump({'index': '$index', 'sourcetype': '$sourcetype', 'fields': fields},
          open('$OUT/fields__$safe.json','w'), indent=2)
print(f'      $index / $sourcetype: {len(fields)} fields')"
done < "$OUT/_pairs.txt"

echo "4/4  summary"
python3 - "$OUT" <<'PY'
import glob, json, os, sys
out = sys.argv[1]

# Guesses only — the names are a hint, the meaning is a human's call.
HINTS = {
    "ip":     ("src_ip","dest_ip","src","dest","srcip","dstip","clientip","dest_ip"),
    "user":   ("user","src_user","user_name","username","account"),
    "host":   ("host","dvc","dest_host","devname","hostname","computer"),
    "hash":   ("file_hash","hash","md5","sha256","sha1"),
    "domain": ("query","domain","dest_host","url_domain","url"),
}

docs, field_map = [], {k: [] for k in HINTS}
for path in sorted(glob.glob(os.path.join(out, "fields__*.json"))):
    d = json.load(open(path))
    names = sorted(d["fields"])
    docs.append(f"### index `{d['index']}` · sourcetype `{d['sourcetype']}`\n")
    docs.append("| field | distinct | examples |")
    docs.append("| --- | --- | --- |")
    for n in names:
        f = d["fields"][n]
        docs.append(f"| `{n}` | {f['distinct']} | {', '.join(f['examples']) or '—'} |")
    docs.append("")
    for kind, candidates in HINTS.items():
        for n in names:
            if n in candidates and n not in field_map[kind]:
                field_map[kind].append(n)

models = json.load(open(os.path.join(out, "datamodels.json")))
external = [m for m in models if not m.startswith("internal_")]

header = [
    "# Splunk data catalog",
    "",
    "Generated by export_catalog.sh. Paste the tables into an agent's data guide,",
    "and use field-map.json as the starting point for SPLUNK_FIELD_MAP.",
    "",
    f"CIM data models: {', '.join(external) if external else '**none** — fields are not normalised'}",
    "",
]
open(os.path.join(out, "catalog.md"), "w").write("\n".join(header + docs))
json.dump(field_map, open(os.path.join(out, "field-map.json"), "w"), indent=2)
print(f"      catalog.md, field-map.json")
PY

rm -f "$OUT/_pairs.txt"
echo
echo "written to $OUT/"
ls -1 "$OUT"
