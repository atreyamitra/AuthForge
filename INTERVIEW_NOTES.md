# Interview notes

**Why short-lived access + refresh tokens?** Access tokens are sent on every request so they are exposed often; keeping them 15m limits what a leak is worth. The refresh token is sent only to `/api/auth`, is HttpOnly, and is server-tracked so it can be revoked.

**Why rotate refresh tokens?** A refresh token that never changes is a long-lived bearer secret. With single-use rotation a stolen token that was already used is useless, and the legitimate client's next refresh makes the theft visible as a 401.

**What race occurs during concurrent refresh?** Naive code does read token -> check unrevoked -> issue new -> mark old revoked. Two requests can both pass the check and both mint a successor, forking the session.

**How does MongoDB prevent it?** One `findOneAndUpdate` with filter `{tokenId, revoked:false, expiresAt>now}` and update `revoked:true`. Document-level atomicity means only one caller's update matches; the rest get `null` and answer 401. Proven by a test firing 24 concurrent refreshes, including across two separate Node processes on one MongoDB, asserting exactly one 200 and exactly one live successor.

**What does sessionVersion do?** A per-user counter embedded in every token as `sv`. Global logout increments it; any token whose `sv` differs from the database value is rejected, so access and refresh tokens die at once.

**What happens after global logout?** All previously issued access tokens return 401 on their next request (they are checked against MongoDB), refresh tokens fail, and a fresh login works.

**What if the access token was already issued?** Same answer: it is revoked immediately, because each request compares its `sv` with the user document. The price is a DB read per request. A pure-stateless design would honor it until expiry.

**How do you prevent admin self-registration?** The signup schema has no `role`; Joi rejects unknown keys with 400; the controller hard-codes `user`. The first admin is created by an operator script with DB access; later promotion needs an existing admin.

**Why Redis for brute-force protection?** Counters need to be shared across app instances, expire on their own, and be incremented atomically and cheaply. A small Lua script does INCR + expiry in one step (and heals a counter that lost its TTL).

**What if Redis goes down?** Login limiter fails open (the MongoDB per-account lockout still applies) so an outage is not a login outage; the 2FA code limiter fails closed (503) because a 6-digit code is brute-forceable without it. Authorization does not use Redis.

**Why bcrypt? Limitations?** Adaptive, salted, widely reviewed; cost 12 here. It only uses the first 72 bytes, so longer passwords are rejected instead of silently truncated. It is not memory-hard (argon2id is better against GPUs).

**How does TOTP work? Can codes be replayed?** HMAC of the current 30-second step with a shared secret, 6 digits; +-1 step tolerated for clock drift. Replay is prevented: each accepted step is recorded with a conditional update, so the same or an older code is rejected, including under concurrency.

**Limits of the project?** See SECURITY_MODEL.md: no reuse-triggered family revocation, small logout-vs-rotation gap, plaintext TOTP secret, no password reset/email verification, in-memory global limiter, tested only on standalone MongoDB, no external pen test.

**How would you harden for production?** Encrypt TOTP secrets, add recovery codes, reuse detection with a grace window, asymmetric signing with key rotation, replica set with majority write concern, `trust proxy` configuration, secrets manager, metrics/alerting on audit events, argon2id, email verification/reset flows.

**Why check the user in MongoDB on every request?** Role changes and deactivation apply instantly; the token's `role` claim is not trusted for authorization.

**Why does the refresh successor inherit the old sessionVersion?** So a global logout racing with a refresh cannot yield a valid successor: the successor is born stale if the logout wins.
