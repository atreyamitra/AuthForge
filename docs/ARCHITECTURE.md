# AuthForge architecture

Node.js/Express service. **MongoDB is authoritative** for users, sessions (refresh tokens), `sessionVersion`, roles and TOTP state. **Redis** is used only for abuse throttling (login and 2FA attempt counters). Nothing authorization-related depends on Redis being up.

## Tokens: what each proves

| Token | Lifetime | Signed with | Proves | Persisted? | Revocable? |
|---|---|---|---|---|---|
| Access JWT (`type=access`, `sub`, `role`, `sv`) | 15m | `JWT_ACCESS_SECRET`, HS256 only | "this server issued it for user `sub` under session version `sv`" | no | yes, by bumping `sessionVersion` (checked per request against MongoDB) |
| Refresh JWT (`type=refresh`, `jti`, `fam`, `sv`) | 7d | `JWT_REFRESH_SECRET`, HS256 only | same, plus the `jti` must exist unrevoked in MongoDB | yes (`RefreshToken` doc) | yes |
| 2FA pending JWT (`type=2fa_pending`) | 5m | access secret | password was correct; redeemable only at `/2fa/login-verify` | no | no (expires) |

Trust boundaries: the client is untrusted (body, headers, cookies, claims); the app trusts only signature-verified JWTs and what it reads from MongoDB. `role` in the JWT is **informational**: `authenticate` loads the user from MongoDB on every request and authorization uses the database role (so demotion/deactivation applies to already-issued tokens immediately; cost: one DB read per request).

## Login
```
client -> POST /login {email,password}
  loginRateLimiter (Redis Lua INCR+PEXPIRE, key email:ip, fail-OPEN)
  -> Joi validation (unknown keys rejected, password <= 72 bytes)
  -> findOne(email); unknown email still pays a bcrypt compare (timing)
  -> locked? 423   (MongoDB lockUntil)
  -> bcrypt compare; bad => atomic $inc failedLoginAttempts, lock at threshold
  -> good: reset counters; if 2FA enabled => return 2fa_pending token (no cookie/access token)
  -> else: new family id, access(sv) + refresh(sv) issued, RefreshToken doc inserted, cookie set
```

## Refresh (rotation)
```
refresh JWT -> verify (HS256, exp, type)
  -> RefreshToken.findOneAndUpdate({tokenId, revoked:false, expiresAt>now}, {revoked:true})   <- ONE atomic MongoDB op
        returns the document to exactly one caller; all concurrent others get null -> 401
  -> load user; reject if inactive or user.sessionVersion != token.sessionVersion
  -> issue successor with SAME family and the CONSUMED token's sessionVersion
```
Why the successor inherits the old `sessionVersion`: a global logout racing with a refresh cannot hand the winner a "fresh" version. If the logout's increment lands after the user read, the successor carries the old `sv` and is dead on arrival; if before, the refresh is rejected.

## Logout / global logout
* `POST /logout`: revokes every token in the presented token's family (the session). Idempotent, always 204, clears cookie.
* `POST /logout-all` (needs access token): `$inc sessionVersion` on the user, then revoke all their refresh tokens. Access tokens die **immediately** (not at the 15m expiry) because `authenticate` compares `sv` with MongoDB.

## 2FA (TOTP)
Setup (generates a secret, stored unconfirmed; refused if already enabled) -> verify (flips `twoFactorEnabled`) -> login-verify (pending token + code). Each accepted code advances `twoFactorLastStep` with a conditional update (`lastStep < step`), so a code (and older ones) is single-use even under concurrency. All code checks are throttled per user in Redis and **fail closed** (503) if Redis is down. Disable needs password + fresh code.

## RBAC
`authenticate` (token + DB user + `sv`) then `authorize(...roles)` on the DB role. Matrix (tested):

| Endpoint | none | user | admin |
|---|---|---|---|
| GET /api/dashboard | 401 | 200 | 200 |
| GET /api/auth/me | 401 | 200 | 200 |
| GET /api/admin/users | 401 | 403 | 200 |
| PATCH /api/admin/users/:id/role | 401 | 403 | 200 |

Public signup always creates `user`. The first admin is created by an operator with DB access: `npm run create-admin`.

## Failure semantics
| Event | Behaviour |
|---|---|
| MongoDB down | auth endpoints return 500 (no unauthenticated fallback); nothing is cached |
| Redis down | login limiter fails **open** (Mongo per-account lockout still applies); 2FA checks fail **closed** (503); authorization unaffected |
| Rotation succeeded but response lost | client's old token is consumed; client must log in again. Not retried server-side (retrying a security write is unsafe) |
| Crash between consuming a token and inserting the successor | session ends; user logs in again |
