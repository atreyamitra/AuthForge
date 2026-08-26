# AuthForge — Auth & Access Control Microservice

A standalone authentication/authorization microservice: the kind of thing that
sits in front of other apps and handles who-can-do-what. Built to demonstrate
production auth patterns, not a toy login form.

## Features

- **JWT auth** — short-lived access tokens + long-lived refresh tokens
- **Refresh token rotation** — every refresh issues a new pair and revokes the
  old one; revoked/reused tokens are rejected via a Mongo-backed token record
- **TOTP-based 2FA** — enroll via QR code (Google Authenticator/Authy/1Password
  compatible), enforced at login as a second step, with a disable flow that
  itself requires a valid code
- **RBAC** — `guest` / `user` / `admin` roles enforced via middleware
  (`authorize('admin')`) on protected routes
- **Brute-force protection** — Redis-backed login rate limiter, keyed on
  email + IP, independent of the general API rate limiter
- **Account lockout** — 10 consecutive failed logins locks the account for 15
  minutes
- **Global logout** — `/logout-all` revokes every outstanding refresh token
  and invalidates all previously-issued access tokens for that user via a
  Redis marker, even ones that haven't expired yet
- **Structured audit logging** — every security-relevant event (login
  success/fail, lockouts, 2FA enable/disable, role changes) emits a
  structured, greppable log record via pino, ready to ship to a log
  aggregator
- **API documentation** — OpenAPI 3.0 spec served at `/api/docs` via Swagger UI
- **CI pipeline** — GitHub Actions runs the Jest suite plus a full-stack smoke
  test against *real* MongoDB and Redis service containers on every push
- **Security headers & hardening** — helmet, strict CORS, small JSON body
  limit, httpOnly/secure/sameSite refresh cookie
- **Input validation** — Joi schemas on every mutating route
- **Containerized** — Dockerfile + docker-compose (service + MongoDB + Redis)

## Stack

Node.js, Express, MongoDB (Mongoose), Redis (ioredis), JWT, bcrypt, TOTP
(speakeasy), pino, Docker, GitHub Actions.

## Getting started

### With Docker (recommended)

```bash
cp .env.example .env   # fill in real JWT secrets
docker compose up --build
```

The service comes up on `http://localhost:5000`, alongside its own MongoDB
and Redis containers.

### Locally, without Docker

Requires a running MongoDB and Redis instance (update `.env` accordingly).

```bash
npm install
cp .env.example .env
npm run dev
```

## API

| Method | Route                     | Auth           | Description                          |
|--------|----------------------------|----------------|---------------------------------------|
| POST   | `/api/auth/register`       | —              | Create an account                     |
| POST   | `/api/auth/login`          | —              | Log in, get access token or 2FA challenge |
| POST   | `/api/auth/2fa/setup`      | access token   | Begin 2FA enrollment, returns QR code |
| POST   | `/api/auth/2fa/verify`     | access token   | Confirm enrollment with a TOTP code   |
| POST   | `/api/auth/2fa/login-verify`| —             | Complete login for a 2FA account      |
| POST   | `/api/auth/2fa/disable`    | access token   | Disable 2FA (requires a valid code)   |
| POST   | `/api/auth/refresh`        | refresh cookie | Rotate refresh token, get new access token |
| POST   | `/api/auth/logout`         | —              | Revoke current refresh token          |
| POST   | `/api/auth/logout-all`     | access token   | Revoke all sessions for this user     |
| GET    | `/api/auth/me`             | access token   | Current user profile                  |
| GET    | `/api/dashboard`           | access token   | Example authenticated route           |
| GET    | `/api/admin/users`         | admin only     | List all users                        |
| PATCH  | `/api/admin/users/:id/role`| admin only     | Change a user's role                  |

Full interactive docs: run the service and visit `/api/docs`.

## Tests

```bash
npm test               # Jest suite — bcrypt, JWT, RBAC, 2FA, Redis rate limiting
npm run test:integration  # full-stack smoke test against REAL MongoDB + Redis
```

`npm test` covers registration, login, RBAC enforcement, refresh rotation,
the full TOTP 2FA lifecycle (enroll → challenge → verify → disable), the
Redis-backed login rate limiter, and global logout — 19 tests, all exercising
real bcrypt hashing, real JWT signing/verification, real TOTP codes, and a
real Redis instance.

**Note on the test double for MongoDB:** the persistence layer for `User` and
`RefreshToken` is swapped for an in-memory double during `npm test` (see
`src/models/__mocks__/`), matching the exact Mongoose method surface the app
uses. This was a pragmatic call made in a network-restricted sandbox that
couldn't download a `mongodb-memory-server` binary. The gap is closed in CI:
`.github/workflows/ci.yml` runs `npm run test:integration`, a separate script
that boots the real (unmocked) app against actual MongoDB and Redis service
containers and drives the whole flow — register, login, RBAC, and the full
2FA cycle — over real HTTP.

## Project structure

```
src/
  config/       env loading, Mongo connection, Redis client
  controllers/  route handlers (business logic)
  middleware/   auth, RBAC, rate limiting, validation, error handling
  models/       Mongoose schemas (User, RefreshToken)
  routes/       Express route definitions
  utils/        JWT helpers, Joi schemas
tests/          Jest + Supertest integration tests
```
