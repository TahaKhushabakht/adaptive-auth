#!/usr/bin/env bash
#
# run_all.sh — the one command to run before a commit.
#
# Builds authsvc once, then gives EACH test script its own freshly-started
# server instance. That isolation matters: rate-limit buckets live in memory
# for the life of the server process, so running multiple scripts back to
# back against one shared instance lets an earlier script's requests
# silently consume tokens a later script assumed it had. Restarting between
# scripts makes every suite start from an identical, empty-bucket state.
#
# Requires nothing already listening on $HOST — if you're running the server
# yourself via `go run .` in another terminal, stop it first, since this
# script needs full control over the server's lifecycle to guarantee clean
# state between suites.
#
# Usage: ./scripts/run_all.sh

set -uo pipefail
cd "$(dirname "$0")"
source ./lib.sh

SCRIPTS_DIR="$(pwd)"
AUTHSVC_DIR="$(cd ../authsvc && pwd)"

if curl -s -o /dev/null --max-time 2 "$HOST/healthz"; then
  echo "error: something is already listening at $HOST" >&2
  echo "  this suite needs to control the server's start/stop to guarantee" >&2
  echo "  clean rate-limiter state between test suites -- stop whatever's" >&2
  echo "  running there (e.g. Ctrl+C your 'go run .' terminal) and retry." >&2
  exit 1
fi

SERVER_PID=""

start_server() {
  # No subshell here on purpose: launching inside ( ... ) & would make $!
  # the subshell's PID, not the actual server binary's, which breaks a
  # clean kill later. cd/cd back in the real shell instead.
  cd "$AUTHSVC_DIR"
  ./authsvc_test.exe &
  SERVER_PID=$!
  cd "$SCRIPTS_DIR"

  for _ in $(seq 1 20); do
    if curl -s -o /dev/null --max-time 1 "$HOST/healthz"; then
      return 0
    fi
    sleep 0.5
  done
  echo "server never came up" >&2
  return 1
}

stop_server() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  SERVER_PID=""
  sleep 0.5  # let the OS release the port before the next start
}

final_cleanup() {
  stop_server
  rm -f "$AUTHSVC_DIR/authsvc_test.exe"
}
trap final_cleanup EXIT

echo "building authsvc..."
( cd "$AUTHSVC_DIR" && go build -o authsvc_test.exe . )
if [ ! -f "$AUTHSVC_DIR/authsvc_test.exe" ]; then
  echo "build failed" >&2
  exit 1
fi

OVERALL=0
for script in test_register.sh test_login.sh test_session.sh test_ratelimit.sh timing_leak_test.sh; do
  echo
  echo "############################################"
  echo "# $script  (fresh server instance)"
  echo "############################################"
  if start_server; then
    ./"$script" || OVERALL=1
  else
    OVERALL=1
  fi
  stop_server
done

echo
echo "============================================="
if [ "$OVERALL" -eq 0 ]; then
  echo "ALL TEST SUITES PASSED"
else
  echo "SOME TEST SUITES FAILED"
fi
exit $OVERALL
