#!/usr/bin/env bash
#
# test_login.sh — exercises POST /login: correct credentials, wrong password,
# a nonexistent user, and missing-field validation. Also checks that a wrong
# password and a nonexistent user return the IDENTICAL status code — the
# status-code half of the anti-enumeration guarantee. The timing half of
# that same guarantee is covered separately in timing_leak_test.sh, since it
# needs many samples and a ratio check rather than a single comparison.
#
# Requires the server already running. Registers its own fresh test user.

set -uo pipefail
cd "$(dirname "$0")"
source ./lib.sh

require_server

EMAIL=$(unique_email)

echo "target : $HOST/login"
echo "email  : $EMAIL"
echo

curl -s -o /dev/null -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
assert_status "correct password" 200 "$code"

wrong_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"wrong-password\"}")
assert_status "wrong password rejected" 401 "$wrong_code"

ghost_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$(unique_email)\",\"password\":\"whatever\"}")
assert_status "nonexistent user rejected" 401 "$ghost_code"

if [ "$wrong_code" = "$ghost_code" ]; then
  assert_true "wrong-password and no-such-user return identical status" 0
else
  assert_true "wrong-password and no-such-user return identical status" 1
fi

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"\"}")
assert_status "empty password rejected" 400 "$code"

print_summary
exit $?
