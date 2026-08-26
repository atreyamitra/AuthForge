const request = require('supertest');
const createApp = require('../src/app');

// The sandbox this suite was authored in can't reach fastdl.mongodb.org to
// pull a real mongod binary for mongodb-memory-server, so we substitute the
// manual in-memory model doubles in src/models/__mocks__/. Everything else
// (bcrypt hashing, JWT signing/verification, RBAC checks, Redis-backed rate
// limiting against a real redis-server) runs for real. Against the Dockerized
// stack (docker-compose.yml) or any machine with internet access to
// mongodb.org, these mocks are irrelevant — src/models/User.js and
// RefreshToken.js talk to a real MongoDB unmodified.
jest.mock('../src/models/User');
jest.mock('../src/models/RefreshToken');

const User = require('../src/models/User');
const RefreshToken = require('../src/models/RefreshToken');

const app = createApp();

afterEach(() => {
  User.__reset();
  RefreshToken.__reset();
});

const validUser = {
  email: 'jane@example.com',
  password: 'StrongPass123',
};

describe('POST /api/auth/register', () => {
  it('registers a new user and returns an access token + user object', async () => {
    const res = await request(app).post('/api/auth/register').send(validUser);
    expect(res.status).toBe(201);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.user.email).toBe(validUser.email);
    expect(res.body.user.passwordHash).toBeUndefined();
    expect(res.body.user.role).toBe('user');
    // refresh token should be set as httpOnly cookie, not in body
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toMatch(/refreshToken=/);
  });

  it('rejects duplicate email registration', async () => {
    await request(app).post('/api/auth/register').send(validUser);
    const res = await request(app).post('/api/auth/register').send(validUser);
    expect(res.status).toBe(409);
  });

  it('rejects weak passwords', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'weak@example.com', password: 'weak' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Validation failed');
  });
});

describe('POST /api/auth/login', () => {
  beforeEach(async () => {
    await request(app).post('/api/auth/register').send(validUser);
  });

  it('logs in with correct credentials', async () => {
    const res = await request(app).post('/api/auth/login').send(validUser);
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
  });

  it('rejects incorrect password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: validUser.email, password: 'WrongPass123' });
    expect(res.status).toBe(401);
  });

  it('rate-limits repeated failed login attempts', async () => {
    const maxAttempts = Number(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS);
    let lastRes;
    for (let i = 0; i < maxAttempts + 1; i++) {
      lastRes = await request(app)
        .post('/api/auth/login')
        .send({ email: validUser.email, password: 'WrongPass123' });
    }
    expect(lastRes.status).toBe(429);
    expect(lastRes.body.error).toMatch(/Too many login attempts/);
  });
});

describe('GET /api/auth/me (authenticate middleware)', () => {
  it('rejects requests with no token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('returns the current user with a valid access token', async () => {
    const registerRes = await request(app).post('/api/auth/register').send(validUser);
    const token = registerRes.body.accessToken;

    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(validUser.email);
  });

  it('rejects a malformed/invalid token', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer not.a.valid.token');
    expect(res.status).toBe(401);
  });
});

describe('RBAC: /api/admin/users', () => {
  it('blocks a regular user (403)', async () => {
    const registerRes = await request(app).post('/api/auth/register').send(validUser);
    const token = registerRes.body.accessToken;

    const res = await request(app).get('/api/admin/users').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/insufficient role/);
  });

  it('allows an admin user (200)', async () => {
    const adminRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'admin@example.com', password: 'AdminPass123', role: 'admin' });
    const token = adminRes.body.accessToken;

    const res = await request(app).get('/api/admin/users').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users)).toBe(true);
  });
});

describe('POST /api/auth/refresh (rotation)', () => {
  it('issues a new access token using the refresh cookie, and rotates it', async () => {
    const agent = request.agent(app); // persists cookies across requests
    await agent.post('/api/auth/register').send(validUser);

    const refreshRes = await agent.post('/api/auth/refresh').send();
    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.accessToken).toBeDefined();

    // old cookie should now be rotated; a second immediate refresh
    // reusing the *original* cookie value would fail, but since our
    // agent auto-updates cookies, this call succeeds with the new one.
    const secondRefresh = await agent.post('/api/auth/refresh').send();
    expect(secondRefresh.status).toBe(200);
  });

  it('rejects refresh with no cookie/body token', async () => {
    const res = await request(app).post('/api/auth/refresh').send();
    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth/logout-all', () => {
  it('invalidates all outstanding access tokens for the user', async () => {
    const agent = request.agent(app);
    const registerRes = await agent.post('/api/auth/register').send(validUser);
    const oldToken = registerRes.body.accessToken;

    // sanity check: token works before logout-all
    const before = await agent.get('/api/auth/me').set('Authorization', `Bearer ${oldToken}`);
    expect(before.status).toBe(200);

    await new Promise((r) => setTimeout(r, 1100)); // ensure invalidation timestamp > token iat (1s JWT resolution)
    const logoutRes = await agent
      .post('/api/auth/logout-all')
      .set('Authorization', `Bearer ${oldToken}`);
    expect(logoutRes.status).toBe(204);

    const after = await agent.get('/api/auth/me').set('Authorization', `Bearer ${oldToken}`);
    expect(after.status).toBe(401);
  });
});

describe('Two-factor authentication (TOTP)', () => {
  const speakeasy = require('speakeasy');

  async function registerAndGetToken(email = 'twofa@example.com') {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email, password: 'StrongPass123' });
    return res.body.accessToken;
  }

  it('sets up 2FA and returns a QR code + manual entry key', async () => {
    const token = await registerAndGetToken();
    const res = await request(app).post('/api/auth/2fa/setup').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.qrCode).toMatch(/^data:image\/png;base64,/);
    expect(res.body.manualEntryKey).toBeDefined();
  });

  it('rejects setup confirmation with a wrong code', async () => {
    const token = await registerAndGetToken();
    await request(app).post('/api/auth/2fa/setup').set('Authorization', `Bearer ${token}`);

    const res = await request(app)
      .post('/api/auth/2fa/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ code: '000000' });
    expect(res.status).toBe(400);
  });

  it('completes the full 2FA enroll -> login-challenge -> verify cycle', async () => {
    const token = await registerAndGetToken();

    const setupRes = await request(app)
      .post('/api/auth/2fa/setup')
      .set('Authorization', `Bearer ${token}`);
    const secret = setupRes.body.manualEntryKey;

    const validCode = speakeasy.totp({ secret, encoding: 'base32' });
    const verifyRes = await request(app)
      .post('/api/auth/2fa/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ code: validCode });
    expect(verifyRes.status).toBe(200);

    // Password login should now return a 2FA challenge, not a full token.
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'twofa@example.com', password: 'StrongPass123' });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body.requiresTwoFactor).toBe(true);
    expect(loginRes.body.accessToken).toBeUndefined();

    // Redeem the challenge with a fresh TOTP code.
    const secondCode = speakeasy.totp({ secret, encoding: 'base32' });
    const finishRes = await request(app).post('/api/auth/2fa/login-verify').send({
      twoFactorToken: loginRes.body.twoFactorToken,
      code: secondCode,
    });
    expect(finishRes.status).toBe(200);
    expect(finishRes.body.accessToken).toBeDefined();
  });

  it('rejects a login-verify with an invalid code', async () => {
    const token = await registerAndGetToken();
    const setupRes = await request(app)
      .post('/api/auth/2fa/setup')
      .set('Authorization', `Bearer ${token}`);
    const secret = setupRes.body.manualEntryKey;
    const validCode = speakeasy.totp({ secret, encoding: 'base32' });
    await request(app)
      .post('/api/auth/2fa/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ code: validCode });

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'twofa@example.com', password: 'StrongPass123' });

    const res = await request(app).post('/api/auth/2fa/login-verify').send({
      twoFactorToken: loginRes.body.twoFactorToken,
      code: '000000',
    });
    expect(res.status).toBe(401);
  });

  it('disables 2FA with a valid code', async () => {
    const token = await registerAndGetToken();
    const setupRes = await request(app)
      .post('/api/auth/2fa/setup')
      .set('Authorization', `Bearer ${token}`);
    const secret = setupRes.body.manualEntryKey;
    const code = speakeasy.totp({ secret, encoding: 'base32' });
    await request(app)
      .post('/api/auth/2fa/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ code });

    const disableCode = speakeasy.totp({ secret, encoding: 'base32' });
    const res = await request(app)
      .post('/api/auth/2fa/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ code: disableCode });
    expect(res.status).toBe(200);

    // Login should now go straight through without a 2FA challenge.
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'twofa@example.com', password: 'StrongPass123' });
    expect(loginRes.body.requiresTwoFactor).toBeUndefined();
    expect(loginRes.body.accessToken).toBeDefined();
  });
});
