#!/usr/bin/env bash
#
# timing_leak_test.sh — measure user-enumeration timing leak on POST /login
#
# Sends the same wrong password to (a) an account that exists and (b) one that
# doesn't. Both should return 401. If the response TIMES differ materially, the
# endpoint is a user-enumeration oracle: an attacker can discover which email
# addresses have accounts without ever authenticating, then feed only the
# confirmed-real ones into a credential-stuffing run.
#
# Mitigation: on the "no such user" path, verify the submitted password against a
# throwaway dummy hash and discard the result, so both paths burn equivalent CPU
# in argon2.
#
# IMPORTANT interaction with the /login rate limiter: this test needs many rapid
# /login requests, but /login is intentionally rate-limited (burst=5 by default).
# Once the bucket empties, further requests get 429 instead of reaching the real
# handler -- and a 429 returns almost instantly, which would silently corrupt a
# naive timing average into a false "leak". This script watches for that: any
# non-401 response during sampling is flagged as CONTAMINATED and excluded from
# the timing math, and the run is marked INCONCLUSIVE rather than reporting a
# possibly-bogus verdict. Default N is kept low enough to normally avoid this
# entirely against a freshly-started server.
#
# Usage:
#   ./scripts/timing_leak_test.sh
#   N=20 REAL_EMAIL=someone@example.com ./scripts/timing_leak_test.sh
#
# Env overrides: HOST, REAL_EMAIL, GHOST_EMAIL, PASSWORD, N

set -uo pipefail

HOST="${HOST:-http://localhost:8081}"
REAL_EMAIL="${REAL_EMAIL:-taha@example.com}"
GHOST_EMAIL="${GHOST_EMAIL:-ghost-does-not-exist@example.com}"
PASSWORD="${PASSWORD:-deliberately-wrong-password}"
# Default kept small on purpose: with a 1-call warmup + N interleaved pairs,
# total /login calls = 1 + 2N. Staying at or below the rate limiter's burst
# (5 by default) keeps every sample clean without needing a fresh server.
N="${N:-2}"

# Ratio above which we call it a leak. The argon2 cost (~50ms) dwarfs everything
# else on the request path, so a real leak shows up as multiples, not percentages.
THRESHOLD=1.5

# sample <email> -- prints "STATUS TIME_MS" for one login attempt.
sample() {
  local email="$1"
  local out
  out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' \
    -X POST "$HOST/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$PASSWORD\"}")
  awk -v out="$out" 'BEGIN {
    split(out, parts, " ")
    printf "%s %.3f", parts[1], parts[2] * 1000
  }'
}

mean() { awk '{ t += $1; n++ } END { if (n) printf "%.2f", t / n; else print "0" }'; }

if ! curl -s -o /dev/null --max-time 3 "$HOST/healthz"; then
  echo "error: no server responding at $HOST" >&2
  echo "  start it with:  cd authsvc && go run ." >&2
  exit 1
fi

echo "target        : $HOST/login"
echo "real account  : $REAL_EMAIL"
echo "ghost account : $GHOST_EMAIL"
echo "samples       : $N each (plus 1 warmup call)"
echo

# Warm up: first request pays one-off costs (connection setup, page faults,
# lazily-opened DB pool) that would skew the first real sample. Just one call,
# not one per side -- it's shared connection/process warmup, not a per-email
# cost, and every /login call spends from the same rate-limit budget.
sample "$REAL_EMAIL" > /dev/null

real_times=""
ghost_times=""
contaminated=0
for _ in $(seq "$N"); do
  # Interleaved rather than batched, so any drift in machine load hits both
  # samples equally instead of biasing whichever ran second.
  real_out=$(sample "$REAL_EMAIL")
  ghost_out=$(sample "$GHOST_EMAIL")

  real_status=${real_out%% *}
  ghost_status=${ghost_out%% *}

  if [ "$real_status" != "401" ] || [ "$ghost_status" != "401" ]; then
    contaminated=$((contaminated + 1))
    printf 'x'
    continue
  fi

  real_times="$real_times${real_out#* }"$'\n'
  ghost_times="$ghost_times${ghost_out#* }"$'\n'
  printf '.'
done
printf '\n\n'

if [ "$contaminated" -gt 0 ]; then
  echo "WARNING: $contaminated of $N sample pairs got a non-401 response (likely the"
  echo "  /login rate limiter kicking in mid-run, or the account state was unexpected)"
  echo "  and were excluded from the timing average below."
  echo
fi

clean_n=$(printf '%s' "$real_times" | grep -c .)
if [ "$clean_n" -lt 2 ]; then
  echo "INCONCLUSIVE: only $clean_n clean sample(s) survived -- too few to trust."
  echo "  This usually means the /login bucket was already partly spent before this"
  echo "  run started (e.g. re-running this script without restarting the server)."
  echo "  Restart the server (resets the rate limiter) and re-run."
  exit 1
fi

real_avg=$(printf '%s' "$real_times"  | mean)
ghost_avg=$(printf '%s' "$ghost_times" | mean)

printf 'real account , wrong password : %8s ms  (n=%d)\n' "$real_avg" "$clean_n"
printf 'ghost account, wrong password : %8s ms  (n=%d)\n' "$ghost_avg" "$clean_n"

awk -v r="$real_avg" -v g="$ghost_avg" -v thr="$THRESHOLD" 'BEGIN {
  if (g <= 0) { print "\ninconclusive: ghost timing was zero"; exit 2 }
  ratio = r / g
  if (ratio < 1) ratio = g / r
  printf "difference                    : %8.2f ms  (%.1fx)\n\n", (r > g ? r - g : g - r), ratio
  if (ratio >= thr) {
    printf "LEAK: response time reveals whether an account exists (%.1fx apart).\n", ratio
    exit 1
  }
  printf "OK: timings within %.1fx — no usable enumeration signal.\n", thr
  exit 0
}'
exit $?
