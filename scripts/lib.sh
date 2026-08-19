#!/usr/bin/env bash
#
# lib.sh — shared helpers for the authsvc test scripts.
# Sourced by the other scripts in this directory; not meant to be run directly.

HOST="${HOST:-http://localhost:8081}"
PASSWORD="${PASSWORD:-hunter22}"

PASS_COUNT=0
FAIL_COUNT=0

# unique_email — generates a fresh, never-before-used email address so tests
# are safe to re-run against a persistent database without colliding on the
# UNIQUE constraint from a previous run.
unique_email() {
  echo "test-$(date +%s%N 2>/dev/null || date +%s)-$RANDOM@example.com"
}

# assert_status <description> <expected_code> <actual_code>
assert_status() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    printf "  PASS  %-55s got %s\n" "$desc" "$actual"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "  FAIL  %-55s expected %s, got %s\n" "$desc" "$expected" "$actual"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# assert_true <description> <"0" for pass, anything else for fail>
assert_true() {
  local desc="$1" ok="$2"
  if [ "$ok" = "0" ]; then
    printf "  PASS  %s\n" "$desc"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "  FAIL  %s\n" "$desc"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

require_server() {
  if ! curl -s -o /dev/null --max-time 3 "$HOST/healthz"; then
    echo "error: no server responding at $HOST" >&2
    echo "  start it with:  cd authsvc && go run ." >&2
    exit 1
  fi
}

print_summary() {
  echo
  echo "-------------------------------------------"
  echo "passed: $PASS_COUNT   failed: $FAIL_COUNT"
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "RESULT: FAIL"
    return 1
  fi
  echo "RESULT: PASS"
  return 0
}
