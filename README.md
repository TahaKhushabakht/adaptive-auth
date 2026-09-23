# adaptive-auth

A risk-based adaptive authentication service in Go. Every login attempt is scored against
device, location, and velocity signals, and the service decides whether to **allow** it,
demand a **step-up** second factor, or **block** it outright — the open-source shape of what
Okta sells as Adaptive MFA.

Built to be defensible rather than large: every security decision below was a deliberate
choice, and every fix was verified with a test that measured the thing it claimed to fix.

---

## Status

| Component | State |
|---|---|
| Registration, login, sessions, logout | Working |
| Signal collection (IP, device, geo, velocity) | Working |
| Rate limiting (per-route token buckets) | Working |
| Risk scoring rules + tests | Written, not yet wired into the login path |
| Shadow-mode scoring to decision recording | Next |
| TOTP enrollment + step-up challenge flow | Planned |
| ML scorer (Python service) | Planned |

The scoring rules are pure, unit-tested functions today; wiring them into `/login` happens
in shadow mode first — scoring and recording decisions without acting on them — before
enforcement is switched on.

## Endpoints

```
GET  /healthz          liveness
POST /register         create account          (rate limited)
POST /login            authenticate            (rate limited)
GET  /me               current user            (requires session)
POST /logout           end session             (requires session)
```

## Stack

Go 1.26 · stdlib `net/http` (no framework) · SQLite via `modernc.org/sqlite` (pure Go, no
cgo) · `database/sql` with parameterized queries (no ORM) · MaxMind GeoLite2 for offline
IP geolocation.

---

## Security design

Each of these is a tradeoff someone could reasonably ask about, so the reasoning matters as
much as the choice.

**Passwords — argon2id** (`m=65536`, `t=3`, `p=2`, 32-byte key, 16-byte per-user salt from
`crypto/rand`). argon2id is *memory-hard*; bcrypt and PBKDF2 are only CPU-hard, so an
attacker with GPUs parallelizes them cheaply. Forcing 64 MiB per hash attempt makes
mass-parallel cracking expensive, because memory doesn't scale down the way cores do.
Stored in PHC string format (`$argon2id$v=19$m=...$salt$hash`) so the cost parameters travel
with each hash and can be tuned later without invalidating existing ones.

**Sessions — opaque random tokens, not JWTs.** A JWT can't be revoked without a server-side
blocklist, which defeats the point of it being stateless. This service's entire premise is
killing a session the moment it looks compromised, so session state lives in the database.
Tokens are 32 bytes from `crypto/rand`, stored **hashed** (SHA-256) so a database dump
doesn't hand over live sessions.

**Why SHA-256 for tokens but argon2id for passwords.** Deliberately opposite choices.
argon2's slowness defends *low-entropy human-chosen* secrets against guessing. A 32-byte
random token has 256 bits of entropy and cannot be brute-forced — slow hashing buys nothing
and would be crippling, since session validation runs on every authenticated request.

**Timing equalization.** When an email doesn't exist, the service still runs a full argon2
verification against a dummy hash before returning the same generic 401. Without it,
response time alone reveals which accounts exist (see below).

**Other:** parameterized SQL throughout · UUID primary keys (sequential IDs leak user counts
and enable enumeration) · `HttpOnly` + `Secure` + `SameSite=Lax` cookies · request body size
caps · per-route rate limits with independent budgets (login `0.1/s` burst 5; register
`1/s` burst 5, so an attacker can't exhaust a victim's login budget via `/register`).

---

## Risk signals

Collected on every attempt into a `login_events` table — **failures as well as successes**,
since the interesting signal is in the failures (a burst against one account, a spray across
many accounts from one IP).

| Signal | Weight | Fires when |
|---|---|---|
| New device | 30 | `device_id` cookie unseen in this user's successful logins |
| New country | 25 | Country unseen in this user's history |
| Impossible travel | 50 | Implied speed from last login exceeds 900 km/h (haversine) |
| User velocity | 25 | ≥3 failed attempts for this user in 15 min |
| IP velocity | 25 | ≥8 failed attempts from this IP in 15 min |
| Unknown geo | 10 | Location unresolvable for a user who normally has one |

Thresholds: **<40 allow · 40–69 challenge · ≥70 block.** All weights and thresholds are
named constants in [`authsvc/risk.go`](authsvc/risk.go).

Every rule **abstains rather than guesses** when it lacks a baseline — a brand-new user's
first login doesn't score as "new device," and geo rules return zero when coordinates are
unresolvable. IP geolocation is genuinely coarse (anycast DNS, VPNs, and carrier NAT all
resolve poorly or not at all), so it's treated as probabilistic, not authoritative.

---

## Bugs found and fixed during self-review

The more interesting half of this project. Each was found, measured, fixed, and covered by a
regression test.

**Authentication bypass.** `verifyPassword` returns `(bool, error)`; the first version
discarded the bool and checked only the error. A wrong password returns `(false, nil)` — no
error — so the check never fired and **every password was accepted**. The compiler can't
catch this: every type is valid, the code just asks the wrong question. Caught by testing
the negative case rather than confirming the happy path.

**User-enumeration timing side channel — 35x signal, now 1.0x.** Even with identical 401
responses, real accounts took ~46 ms (argon2) while nonexistent ones returned in ~1 ms.
Measurable in a single request, no statistics needed — enough to sort real accounts out of a
10M-address list before ever guessing a password. Fixed by verifying against a dummy hash on
the unknown-user path. Now 46.12 ms vs 46.24 ms — a 0.12 ms delta, below network jitter.
[`scripts/timing_leak_test.sh`](scripts/timing_leak_test.sh) is the standing regression test.

**SQLite concurrency — 0/100 concurrent writes succeeded, now 100/100.** Under default
journal mode with no busy timeout, 100 concurrent writes **all** failed with `SQLITE_BUSY`.
Not an edge case; catastrophic under any real concurrency. Fixed with WAL mode plus a 5 s
busy timeout (and `foreign_keys=on`, which turned out never to have been enabled — the
`FOREIGN KEY` clauses had been decorative).

**Email never normalized.** `casetest@example.com` and `CASETEST@example.com` created two
separate accounts, and logging in with different casing than registration failed despite a
correct password. Beyond the UX bug, it fragments one person's history across two accounts —
which would have quietly degraded every "new device for this user" signal the risk engine
depends on.

**No request body limit.** A 10 MB password was accepted and fully argon2-hashed.

Others worth a mention: a schema change that silently did nothing because
`CREATE TABLE IF NOT EXISTS` is not a migration mechanism; a parameter added to a function
and never actually used, which compiled and passed `go vet` clean because Go doesn't flag
unused *parameters*; and event recording landing in the wrong branch, mislabeling
"real account, corrupted hash" as "nonexistent email" — two very different signals collapsed
into one bucket.

---

## Running it

Requires Go 1.26+ and a MaxMind GeoLite2-City database.

```bash
# 1. GeoIP database (free MaxMind account required)
#    Download GeoLite2-City in .mmdb format, then:
mkdir -p authsvc/geoip
mv GeoLite2-City.mmdb authsvc/geoip/

# 2. Run
cd authsvc
go run .          # listens on :8081
```

```bash
curl -i -X POST http://localhost:8081/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"correcthorse"}'

curl -i -c cookies.txt -X POST http://localhost:8081/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"correcthorse"}'

curl -i -b cookies.txt http://localhost:8081/me
```

The SQLite database and schema are created automatically on first run.

## Tests

```bash
cd authsvc && go test ./...     # unit tests (scoring rules, haversine)
./scripts/run_all.sh            # 18 integration checks + the timing regression
```

`run_all.sh` gives each suite its own freshly-started server, because rate-limiter state is
in-memory and process-scoped — sharing one instance lets an earlier suite silently spend a
later one's request budget.

## Known limitations

Deliberate, and worth naming: no schema migrations (`CREATE TABLE IF NOT EXISTS` only) · TOTP
secrets will be stored unencrypted at rest · no graceful shutdown · no email verification ·
no HTTPS or CSRF protection in this dev setup · `clientIP` reads the TCP peer, so it would
need `X-Forwarded-For` handling behind a proxy (naively trusting that header is its own
vulnerability) · SQLite rather than Postgres · no retention policy on stored location
history.
