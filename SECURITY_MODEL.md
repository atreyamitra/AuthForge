# Security model

Scope: a portfolio-scale auth service. This document states what is defended, how that is tested, and what is **not** defended. It makes no claim of production readiness or external review; there has been no third-party penetration test.

## Assets
Account credentials (bcrypt hashes), TOTP seeds, refresh tokens (sessions), role assignments, JWT signing secrets.

## Attackers considered
1. Unauthenticated internet client (signup abuse, credential stuffing, token forgery).
2. Authenticated low-privilege user (privilege escalation).
3. Holder of a stolen/old access or refresh token.
4. Concurrent clients racing state transitions.

## Implemented defenses -> evidence

| Property | Implementation | Test |
|---|---|---|
| Public signup cannot create an admin or set any privileged field | `role` removed from the signup schema; unknown keys rejected (400); role fixed server-side to `user` | `registration.security.test.js` |
| Admins only via operator path or existing admin | `scripts/create-admin.js`; `PATCH /admin/users/:id/role` behind `authorize('admin')` + validated enum | `registration.security`, `auth-flow` (RBAC matrix) |
| Exactly one of N concurrent refreshes succeeds | `findOneAndUpdate({revoked:false,...},{revoked:true})` in MongoDB | `refresh.concurrency`: 24 concurrent in one process; 5 repeated rounds; 24 across two separate Node processes on one MongoDB |
| Consumed refresh token cannot be reused | same conditional update | `refresh.concurrency` |
| Global logout kills access and refresh tokens at once; race-safe | `sessionVersion` in MongoDB, successor inherits consumed token's `sv` | `refresh.concurrency` (incl. 30 logout-all-vs-refresh races) |
| Logout revokes the session | family-wide revoke; cookie path covers `/logout` | `refresh.concurrency` |
| JWT hardening | HS256 pinned on sign+verify; expiry; token `type` checked; secrets required, >=32 chars, distinct; no defaults | `auth-flow` (alg=none, HS512, wrong secret, expired, wrong type; startup config) |
| Role from DB, not claims | `authenticate` loads user per request | `auth-flow` (tampered claim, demotion, deactivation) |
| Password handling | bcrypt cost 12; >72 bytes rejected (no silent truncation); unknown-email login does a dummy bcrypt compare | `auth-flow` |
| Login brute force | Redis Lua atomic counter (email+ip) with TTL self-heal; Mongo atomic `$inc` account lockout | `bruteforce`, `auth-flow` |
| TOTP brute force | per-user Redis throttle, fail closed | `twofactor` |
| TOTP replay | `twoFactorLastStep` conditional update | `twofactor` (sequential + 10 concurrent) |
| 2FA downgrade | setup refused when enrolled; disable needs password + code | `twofactor` |
| Unique accounts under concurrency | unique index on `email`, E11000 -> 409 | `registration.security` (20 concurrent signups -> 1 account) |
| Error hygiene | generic 500, no stack/internal messages, malformed JSON 400, 413 oversize | `auth-flow` |

All of the above run against a real MongoDB and Redis (the suite fails if either is unreachable). The Redis-outage behaviours are tested by forcing the Redis `eval` call to reject (`jest.spyOn`), not by stopping a real Redis.

## Mutation checks actually performed
See the table in the README ("Adversarial checks").

## Known limitations (deliberate or unaddressed)
* **No refresh-token reuse detection beyond rejection.** Replaying a consumed token returns 401 but does not revoke the descendant session. Family-wide revocation on reuse was not added because concurrent legitimate duplicates (double-click, lost response) would then kill valid sessions.
* **Logout vs. rotation race.** If a `/logout` for the old token lands between a refresh consuming it and inserting its successor, the successor survives. `/logout-all` has no such gap.
* **Lost response on rotation** forces re-login; there is no grace window.
* **Access tokens** are stateless-signed but checked against MongoDB each request, so revocation is immediate; the cost is a DB read per request.
* **User enumeration:** signup returns 409 for existing emails and a locked account returns 423. Login 401 is identical for wrong password/unknown email.
* **Lockout DoS:** anyone who knows an email can lock that account for 15 minutes (10 bad passwords), by design of per-account lockout.
* **Redis login limiter fails open**; during a Redis outage only the Mongo lockout limits guessing. `X-Forwarded-For` is not trusted (`trust proxy` is unset); behind a reverse proxy all clients would share the proxy's IP and `trust proxy` must be configured deliberately.
* **Refresh cookie** is `HttpOnly; SameSite=Strict; Path=/api/auth`, `Secure` only when `NODE_ENV=production` (local HTTP development needs it off). SameSite=Strict mitigates CSRF on `/refresh`; there is no CSRF token. A browser app on a different site from the API would need a different design.
* TOTP secrets are stored in plaintext in MongoDB (not encrypted at rest). No recovery codes. Symmetric HS256 secrets; no key rotation. No email verification, password reset, or password change flow. No `iss`/`aud` claims (single service).
* The coarse global API limiter is in-memory per process.
* The two-process concurrency test proves MongoDB atomicity across processes on one standalone `mongod`; it does not cover replica sets / failover.

## Out of scope
DDoS, TLS termination, host/container hardening, supply-chain compromise of dependencies (only `npm audit` in CI), side channels beyond the bcrypt timing equalisation, social engineering.
