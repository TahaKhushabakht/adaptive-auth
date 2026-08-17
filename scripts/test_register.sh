#!/usr/bin/env bash
#
# test_register.sh — exercises POST /register: a valid signup, duplicate-email
# rejection, missing-field validation, and malformed-JSON handling.
#
# Requires the server already running (HOST env var, default
# http://localhost:8081). Self-contained: generates its own unique test
# email, so it's safe to re-run against a persistent database.
#
# Usage:
#   cd authsvc && go run .          # in one terminal
#   ./scripts/test_register.sh      # in another

set -uo pipefail
cd "$(dirname "$0")"
source ./lib.sh

require_server

EMAIL=$(unique_email)

echo "target : $HOST/register"
echo "email  : $EMAIL"
echo

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
assert_status "valid registration" 201 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
assert_status "duplicate email rejected" 409 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$(unique_email)\"}")
assert_status "missing password rejected" 400 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$PASSWORD\"}")
assert_status "missing email rejected" 400 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d 'not valid json')
assert_status "malformed JSON rejected" 400 "$code"

print_summary
exit $?
