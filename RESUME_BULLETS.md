# Recruiter-facing claims (each backed by a test in this repo)

**One-line description:** Node.js/Express auth service with rotating JWT refresh tokens, RBAC and TOTP 2FA, tested against real MongoDB and Redis.

## Resume bullets
* Replaced a read-then-write refresh-token rotation with an atomic MongoDB conditional update, so exactly one of 24 concurrent refresh requests succeeds; verified against a real `mongod`, including requests split across two separate Node processes.
* Closed a privilege-escalation bug where public signup accepted `role: "admin"`: role is now fixed server-side, unknown/privileged fields are rejected, and regression tests cover each mass-assignment field.
* Replaced mocked database tests with 66 integration tests on real MongoDB and Redis (run in GitHub Actions service containers), and validated them by disabling 11 protections one at a time and confirming the tests failed each time.

## LinkedIn bullets
* Implemented `sessionVersion`-based global logout that invalidates access and refresh tokens immediately and is race-safe against concurrent refresh (tested with 30 logout-vs-refresh races).
* Added single-use TOTP codes (conditional-update replay protection), per-user Redis throttling that fails closed, and password re-authentication to disable 2FA.
* Built a Redis Lua-based atomic login throttle plus MongoDB account lockout, with documented fail-open/fail-closed behaviour and tests against a real Redis.

## 30-second pitch
"AuthForge is a small auth service I hardened after auditing it myself. I found that signup could create admins and that my 'concurrent refresh' test only ran against mocks. I fixed signup, made refresh rotation a single atomic MongoDB update, moved global logout to a session version, and rewrote the tests to run against real MongoDB and Redis, including a test that races 24 refreshes across two processes. Then I disabled each protection to check the tests really catch it. The README lists what it doesn't protect against."

## Claims NOT to use
"Secure/production-grade authentication", "prevents token theft", "handles X requests/sec", any user/production-usage numbers, the old README's "20 tests" count, and the old claim that concurrency was proven by tests that used in-memory model doubles.
