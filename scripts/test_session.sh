#!/usr/bin/env bash
#
# test_session.sh — exercises requireAuth + GET /me: no cookie, a garbage
# cookie, and a real session obtained by actually logging in (proves the
# full register -> login -> cookie -> /me chain works end to end, not just
# each piece tested in isolation).
#
# If python3 (or python) is on PATH, also seeds an already-expired session
# directly into the database and confirms it's rejected — proving expiry is
# actually enforced, not just present in the code. That sub-check is skipped
# gracefully if no Python is available; everything else still runs.
#
# Requires the server already running. Registers and logs in its own user.

set -uo pipefail
cd "$(dirname "$0")"
source ./lib.sh

require_server

EMAIL=$(unique_email)
COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

echo "target : $HOST/me"
echo "email  : $EMAIL"
echo

curl -s -o /dev/null -X POST "$HOST/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

code=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/me")
assert_status "no cookie -> unauthorized" 401 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/me" \
  -H "Cookie: session_token=this-is-not-a-real-token")
assert_status "garbage cookie -> unauthorized" 401 "$code"

curl -s -c "$COOKIE_JAR" -o /dev/null -X POST "$HOST/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

code=$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" "$HOST/me")
assert_status "real session -> authorized" 200 "$code"

body=$(curl -s -b "$COOKIE_JAR" "$HOST/me")
case "$body" in
  "you are: "*) assert_true "response body has expected shape" 0 ;;
  *)            assert_true "response body has expected shape" 1 ;;
esac

PYTHON=$(command -v python3 || command -v python || true)
if [ -n "$PYTHON" ]; then
  EXPIRED_TOKEN=$("$PYTHON" - "$EMAIL" <<'PYEOF'
import hashlib
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

email = sys.argv[1]
token = secrets.token_urlsafe(32)
token_hash = hashlib.sha256(token.encode()).hexdigest()
expired_at = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

conn = sqlite3.connect("../authsvc/adaptive_auth.db")
row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
if row is None:
    sys.exit(1)
conn.execute(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
    (token_hash, row[0], expired_at),
)
conn.commit()
print(token)
PYEOF
  )
  if [ -n "$EXPIRED_TOKEN" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' "$HOST/me" -H "Cookie: session_token=$EXPIRED_TOKEN")
    assert_status "expired session rejected" 401 "$code"
  else
    echo "  SKIP  expired session check (could not seed the database row)"
  fi
else
  echo "  SKIP  expired session check (no python/python3 on PATH)"
fi

print_summary
exit $?
