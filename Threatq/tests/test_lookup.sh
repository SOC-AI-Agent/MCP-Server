#!/usr/bin/env bash
# End-to-end test for soc-mcp-threatq against the stand-in platform.
#
#   ./tests/test_lookup.sh
#
# Starts a fake ThreatQ and the connector on a throwaway network, then checks
# the two ways in — POST /lookup for the backend, the lookup_indicator tool for
# an agent — plus the cases that matter more than the happy path: an indicator
# with no record, and a caller with no token.
set -uo pipefail

NET=threatq-test-$$
TOKEN="test-$(openssl rand -hex 8)"
IMAGE=soc-threatq-test
PASS=0 FAIL=0

here=$(cd "$(dirname "$0")/.." && pwd)

cleanup() {
  docker rm -f fake-threatq threatq-under-test >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

check() { # name expected actual
  if [[ "$3" == *"$2"* ]]; then
    echo "  PASS  $1"; PASS=$((PASS+1))
  else
    echo "  FAIL  $1"; echo "        expected to contain: $2"; echo "        got: ${3:0:300}"
    FAIL=$((FAIL+1))
  fi
}

echo "building"
docker build -q -t "$IMAGE" "$here" >/dev/null || { echo "build failed"; exit 1; }
docker network create "$NET" >/dev/null

echo "starting the stand-in platform"
docker run -d --name fake-threatq --network "$NET" --network-alias threatq \
  -v "$here/tests/fake_threatq.py:/app/tests/fake_threatq.py" \
  --entrypoint uvicorn "$IMAGE" tests.fake_threatq:app --host 0.0.0.0 --port 8500 >/dev/null

echo "starting the connector"
docker run -d --name threatq-under-test --network "$NET" --network-alias soc-mcp-threatq \
  -e THREATQ_MCP_AUTH_TOKEN="$TOKEN" \
  -e THREATQ_BASE_URL=http://threatq:8500 \
  -e THREATQ_AUTH_MODE=oauth \
  -e THREATQ_CLIENT_ID=test -e THREATQ_EMAIL=test@example.com -e THREATQ_PASSWORD=test \
  -e THREATQ_VERIFY_SSL=false \
  "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  sleep 1
  docker run --rm --network "$NET" curlimages/curl -s -o /dev/null \
    http://soc-mcp-threatq:8300/health && break
done

run() { docker run --rm --network "$NET" curlimages/curl -s "$@"; }

echo
echo "health"
check "reports the platform reachable" '"threatq":true' \
  "$(run http://soc-mcp-threatq:8300/health)"

echo
echo "POST /lookup — the backend's path"
body='{"indicators":[{"type":"ip","value":"45.83.122.9"},{"type":"ip","value":"203.0.113.9"}]}'
out=$(run -X POST http://soc-mcp-threatq:8300/lookup \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body")
check "known indicator is found"        '"found":true'  "$out"
# ThreatQ scores 0-10 via generated_score, and the connector unwraps the
# score object into a number.
check "its score comes through"         '"score":9.0'   "$out"
check "its attributes come through"     '"category":"c2"' "$out"
check "its adversary comes through"     'APT29'          "$out"
check "unknown indicator is not found"  '"found":false' "$out"
check "both were checked"               '"checked":2'   "$out"

echo
echo "auth"
check "no token is rejected" "401" \
  "$(run -o /dev/null -w '%{http_code}' -X POST http://soc-mcp-threatq:8300/lookup \
      -H 'Content-Type: application/json' -d "$body")"
check "/health needs no token" '"status":"ok"' \
  "$(run http://soc-mcp-threatq:8300/health)"

echo
echo "bad requests"
check "empty array is refused" "non-empty" \
  "$(run -X POST http://soc-mcp-threatq:8300/lookup -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' -d '{"indicators":[]}')"

echo
echo "related objects need with= — the mistake this stand-in exists to catch"
noWith=$(run -X POST "http://threatq:8500/api/indicators/search" \
  -H 'Authorization: Bearer static-probe-token' -H 'Content-Type: application/json' \
  -d '{"criteria":{"value":"45.83.122.9"}}')
if [[ "$noWith" == *'"score"'* ]]; then
  echo "  FAIL  a request without with= must not return score"; FAIL=$((FAIL+1))
else
  echo "  PASS  without with=, score is absent (as on a real ThreatQ)"; PASS=$((PASS+1))
fi
check "the connector does ask for it" '"score":9.0' "$out"

echo
echo "the tool — an agent's path"
rpc() {
  run -X POST http://soc-mcp-threatq:8300/mcp \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d "$1"
}
tools=$(rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
check "publishes lookup_indicator"  '"lookup_indicator"' "$tools"
check "publishes nothing else"      '"tools":[{'         "$tools"

call=$(rpc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"value":"185.220.101.7","indicator_type":"ip"}}}')
check "tool finds a known indicator" 'Tor Project' "$call"

miss=$(rpc '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"value":"203.0.113.9","indicator_type":"ip"}}}')
check "a miss says unknown, not clean" 'unknown, not safe' "$miss"

bad=$(rpc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"value":"x","indicator_type":"nonsense"}}}')
check "rejects an unknown type" 'indicator_type must be one of' "$bad"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
