# AuthForge

A small Node.js/Express authentication service (JWT access + rotating refresh tokens, RBAC, TOTP 2FA, Redis-backed throttling) whose security-relevant behaviour is tested against a real MongoDB and a real Redis.

## What is technically interesting
* **Atomic refresh-token rotation in MongoDB**: one conditional `findOneAndUpdate` decides the winner; tested with 24 concurrent requests, including across two separate Node processes sharing one MongoDB.
* **Server-side fixed signup role**: public registration can only create `user`; extra fields (including `role`) are rejected.
* **`sessionVersion` global logout** that invalidates access *and* refresh tokens immediately and is race-safe against concurrent refresh.
* **Single-use TOTP codes** (replay-protected with a conditional update) with a per-user Redis throttle.
* A suite with no database mocks, plus a record of mutation checks showing the tests catch removal of each protection.

## Security properties (each backed by a test)
See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full table, attackers and limitations, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for flows and failure semantics.

| Property | Implementation | Test |
|---|---|---|
| Public signup cannot create admin / set privileged fields | no `role` in schema, unknown keys -> 400, role fixed to `user` | `tests/registration.security.test.js` |
| Exactly one concurrent refresh wins | conditional `findOneAndUpdate` on `{revoked:false}` | `tests/refresh.concurrency.test.js` (24 concurrent; 2 processes) |
| Consumed refresh tokens cannot be reused; ordinary logout revokes its session state, while `/logout-all` uses `sessionVersion` for immediate global invalidation | `revoked` flag + `family`; `sessionVersion` | `refresh.concurrency` |
| Global logout invalidates access + refresh tokens, race-safe | `sessionVersion` in MongoDB; successor inherits consumed token's `sv` | `refresh.concurrency` (30 logout-vs-refresh races) |
| JWT: HS256 pinned, expiry, token type, secrets required (>=32 chars, distinct) | `src/utils/tokens.js`, `src/config/env.js` | `tests/auth-flow.test.js` |
| Role from database each request | `authenticate` loads the user | `auth-flow` (tampered claim, demotion) |
| Passwords: bcrypt cost 12; >72 bytes rejected, not truncated | `schemas.js` | `auth-flow` |
| Login throttling: Redis atomic counter + Mongo account lockout | Lua INCR/PEXPIRE; `$inc` | `tests/bruteforce.test.js`, `auth-flow` |
| TOTP single-use, throttled, re-auth to disable | `twoFactorLastStep`, Redis limiter, password on disable | `tests/twofactor.test.js` |
| One account per email under concurrency | unique index | `registration.security` (20 concurrent signups) |

## Failure behaviour
* Redis down: login limiter **fails open** (Mongo lockout still applies); 2FA code limiter **fails closed** (503); authorization doesn't use Redis. (Tested by forcing Redis calls to reject, not by stopping Redis.)
* Rotation succeeds but the response is lost: the client must log in again; no server retry.

## Testing
```
npm ci --legacy-peer-deps
# needs MongoDB and Redis reachable (defaults: mongodb://127.0.0.1:27017/authforge_test, redis://127.0.0.1:6379)
npm test
```
The suite **fails** if either service is unreachable; it refuses to run against a database whose URI doesn't contain `test`, and flushes the Redis DB between tests, so point it at a disposable instance. 5 suites, 66 tests (registration/mass-assignment, refresh + concurrency + global logout, auth flow/RBAC/JWT/password/errors/config, brute force, TOTP). CI (`.github/workflows/ci.yml`) runs them against `mongo:7` and `redis:7` service containers, plus `npm audit` and a Docker Compose smoke test.

### Adversarial checks performed
Each protection was disabled one at a time and the relevant suite re-run (then reverted). Every mutation made tests fail:

| Mutation | Result |
|---|---|
| signup accepts `role` from body | 2 tests failed |
| refresh changed to read-then-write | 3 failed |
| `sessionVersion` check removed | 3 failed |
| used refresh tokens accepted (`revoked:false` filter removed) | 5 failed |
| `authorize` disabled | 4 failed |
| login limiter never blocks | 4 failed |
| failed-login counter not incremented | 2 failed |
| weak-secret check removed | 1 failed |
| TOTP replay check removed | 2 failed |
| JWT algorithm allow-list widened | 1 failed |
| 2FA login throttle removed | 2 failed |

These were manual one-off runs, not an automated mutation-testing tool.

## Quick start
```
cp .env.example .env     # then set JWT_ACCESS_SECRET and JWT_REFRESH_SECRET (>=32 chars, different)
docker compose up --build
# create the first admin (operator action, not an HTTP endpoint):
docker compose exec -e ADMIN_EMAIL=you@example.com -e ADMIN_PASSWORD='...' auth-service node scripts/create-admin.js
```
Without Docker: run MongoDB and Redis locally, `npm start`. Compose runs with `NODE_ENV=production`, so the refresh cookie is `Secure` and browsers won't send it over plain HTTP; use a TLS proxy or `NODE_ENV=development` for local HTTP. Mongo/Redis ports are not published to the host by Compose.

## API
OpenAPI at `/api/docs` (source: `openapi.yaml`). Endpoints: `POST /api/auth/{register,login,refresh,logout,logout-all}`, `GET /api/auth/me`, `POST /api/auth/2fa/{setup,verify,disable,login-verify}`, `GET /api/dashboard`, `GET /api/admin/users`, `PATCH /api/admin/users/:id/role`.

## Limitations
No reuse-triggered session revocation, small logout-vs-rotation gap, plaintext TOTP secrets, no recovery codes, password reset or email verification, in-memory global API limiter, tested on a standalone `mongod` only, no external security review. Full list: [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Repository map
```
src/controllers  auth + 2FA handlers      src/middleware  authenticate, authorize, Redis limiters, validate
src/models       User, RefreshToken       src/utils       tokens, totp, schemas, audit
scripts/create-admin.js                   tests/          real-MongoDB/Redis suites
docs/ARCHITECTURE.md  SECURITY_MODEL.md  INTERVIEW_NOTES.md  RESUME_BULLETS.md
```
