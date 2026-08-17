#!/usr/bin/env bash
#
# test_ratelimit.sh — proves the token-bucket rate limiter on /login and
# confirms /register has an INDEPENDENT bucket (not one shared per-IP).
#
# NOTE: limiter state lives in memory for the life of the server process and
# is keyed by client IP. If /login has already been hammered earlier in this
# same server run (e.g. by re-running this script without restarting the
# server), the bucket may already be partially consumed, which can make the
# "burst requests still succeed" assertion fail even though the limiter
# itself is working correctly. For a clean result, restart the server before
# running this script — run_all.sh does that automatically.
#
# Requires the server already running.

set -uo pipefail
cd "$(dirname "$0")"
source ./lib.sh

require_server

EMAIL=$(unique_email)
BURST="${BURST:-5}"

echo "target : $HOST"
echo "burst  : $BURST (must match the server's configured login burst)"
echo

curl -s -o /dev/null -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

last_code=000
for _ in $(seq 1 "$BURST"); do
  last_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
done
assert_status "burst request #$BURST still allowed" 200 "$last_code"

over_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
assert_status "request past the burst is throttled" 429 "$over_code"

reg_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$(unique_email)\",\"password\":\"$PASSWORD\"}")
assert_status "/register unaffected by exhausted /login bucket" 201 "$reg_code"

print_summary
exit $?
