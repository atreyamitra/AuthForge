const jwt = require('jsonwebtoken');
const { app, request, creds, register, registerAdmin, bearer } = require('./helpers');
const User = require('../src/models/User');
const { MAX_PASSWORD_BYTES } = require('../src/utils/schemas');

const A = process.env.JWT_ACCESS_SECRET;

describe('login + password handling', () => {
  beforeEach(() => register());

  it('logs in; stored hash is bcrypt cost 12 and never returned', async () => {
    const res = await request(app).post('/api/auth/login').send(creds());
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|\$2[aby]\$/);
    const u = await User.findOne({ email: 'jane@example.com' }).select('+passwordHash');
    expect(u.passwordHash).toMatch(/^\$2[aby]\$12\$/);
  });

  it('wrong password and unknown email return the same 401 body', async () => {
    const a = await request(app).post('/api/auth/login').send({ ...creds(), password: 'WrongPass123' });
    const b = await request(app).post('/api/auth/login').send({ email: 'nobody@example.com', password: 'WrongPass123' });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body).toEqual(b.body);
  });

  it('login is case-insensitive on email', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'JANE@EXAMPLE.COM', password: 'StrongPass123' });
    expect(res.status).toBe(200);
  });

  it('boundary: 72-byte password accepted, 73-byte rejected (no silent bcrypt truncation)', async () => {
    const ok = 'Aa1' + 'x'.repeat(MAX_PASSWORD_BYTES - 3);
    expect(Buffer.byteLength(ok)).toBe(72);
    const r1 = await request(app).post('/api/auth/register').send({ email: 'long@example.com', password: ok });
    expect(r1.status).toBe(201);
    const tooLong = ok + 'y';
    const r2 = await request(app).post('/api/auth/register').send({ email: 'long2@example.com', password: tooLong });
    expect(r2.status).toBe(400);
    // a 73-byte guess whose first 72 bytes are correct must NOT log in
    const r3 = await request(app).post('/api/auth/login').send({ email: 'long@example.com', password: tooLong });
    expect(r3.status).toBe(400);
  });

  it('multi-byte passwords are measured in bytes, not characters', async () => {
    const pw = 'Aa1' + '€'.repeat(24); // 3 + 72 bytes
    const res = await request(app).post('/api/auth/register').send({ email: 'mb@example.com', password: pw });
    expect(res.status).toBe(400);
  });

  it('enforces the password policy (min length / classes)', async () => {
    for (const password of ['short1A', 'alllowercase1', 'ALLUPPERCASE1', 'NoDigitsHere']) {
      const res = await request(app).post('/api/auth/register').send({ email: 'p@example.com', password });
      expect(res.status).toBe(400);
    }
  });

  it('locks the account in MongoDB after ACCOUNT_LOCK_THRESHOLD bad passwords, even from "many IPs"', async () => {
    const { getRedisClient } = require('../src/config/redis');
    for (let i = 0; i < 10; i += 1) {
      await getRedisClient().flushdb(); // simulate attempts that the per-IP Redis limiter never sees together
      const r = await request(app).post('/api/auth/login').send({ ...creds(), password: 'WrongPass123' });
      expect(r.status).toBe(401);
    }
    await getRedisClient().flushdb();
    const locked = await request(app).post('/api/auth/login').send(creds()); // correct password, still locked
    expect(locked.status).toBe(423);
  });

  it('concurrent bad guesses are all counted (atomic $inc)', async () => {
    const { getRedisClient } = require('../src/config/redis');
    await getRedisClient().flushdb();
    await Promise.all(Array.from({ length: 4 }, () =>
      request(app).post('/api/auth/login').send({ ...creds(), password: 'WrongPass123' })));
    expect((await User.findOne({ email: 'jane@example.com' })).failedLoginAttempts).toBe(4);
  });
});

describe('access-token validation', () => {
  it('rejects missing / malformed / expired / wrong-secret / alg=none / wrong-type tokens', async () => {
    const { user } = await register();
    const claims = { sub: user._id, role: 'user', type: 'access', sv: 0 };
    const none = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
    const cases = {
      none,
      noHeader: undefined,
      garbage: 'Bearer abc',
      expired: jwt.sign({ ...claims, exp: Math.floor(Date.now() / 1000) - 10 }, A, { algorithm: 'HS256' }),
      wrongSecret: jwt.sign(claims, 'x'.repeat(40), { algorithm: 'HS256' }),
      hs512: jwt.sign(claims, A, { algorithm: 'HS512' }),
      refreshType: jwt.sign({ ...claims, type: 'refresh' }, A, { algorithm: 'HS256' }),
      twoFaPending: jwt.sign({ sub: user._id, type: '2fa_pending' }, A, { algorithm: 'HS256' }),
    };
    for (const [name, token] of Object.entries(cases)) {
      const req = request(app).get('/api/auth/me');
      if (name === 'garbage') req.set('Authorization', token);
      else if (token) req.set(bearer(token));
      const res = await req;
      expect([name, res.status]).toEqual([name, 401]);
    }
  });

  it('a valid token with a tampered role claim gains nothing (role comes from the database)', async () => {
    const { user } = await register();
    const forged = jwt.sign({ sub: user._id, role: 'admin', type: 'access', sv: 0 }, A, { algorithm: 'HS256' });
    // signature is valid (attacker would need the secret; here we model the claim being wrong)
    const res = await request(app).get('/api/admin/users').set(bearer(forged));
    expect(res.status).toBe(403);
  });
});

describe('RBAC matrix', () => {
  const endpoints = [
    ['get', '/api/dashboard', { none: 401, user: 200, admin: 200 }],
    ['get', '/api/auth/me', { none: 401, user: 200, admin: 200 }],
    ['get', '/api/admin/users', { none: 401, user: 403, admin: 200 }],
  ];
  it.each(endpoints)('%s %s', async (method, url, expected) => {
    const user = await register('u');
    const admin = await registerAdmin('a');
    expect((await request(app)[method](url)).status).toBe(expected.none);
    expect((await request(app)[method](url).set(bearer(user.accessToken))).status).toBe(expected.user);
    expect((await request(app)[method](url).set(bearer(admin.accessToken))).status).toBe(expected.admin);
  });

  it('PATCH /api/admin/users/:id/role: user 403, admin 200, bad role 400, bad id 400', async () => {
    const user = await register('u');
    const admin = await registerAdmin('a');
    const url = `/api/admin/users/${user.user._id}/role`;
    expect((await request(app).patch(url).send({ role: 'user' })).status).toBe(401);
    expect((await request(app).patch(url).set(bearer(user.accessToken)).send({ role: 'admin' })).status).toBe(403);
    expect((await request(app).patch(url).set(bearer(admin.accessToken)).send({ role: 'root' })).status).toBe(400);
    expect((await request(app).patch('/api/admin/users/not-an-id/role').set(bearer(admin.accessToken)).send({ role: 'user' })).status).toBe(400);
    expect((await request(app).patch(url).set(bearer(admin.accessToken)).send({ role: 'admin' })).status).toBe(200);
  });

  it('authorization is database-checked: demotion/deactivation applies to already-issued tokens', async () => {
    const admin = await registerAdmin('a');
    expect((await request(app).get('/api/admin/users').set(bearer(admin.accessToken))).status).toBe(200);
    await User.updateOne({ _id: admin.user._id }, { role: 'user' });
    expect((await request(app).get('/api/admin/users').set(bearer(admin.accessToken))).status).toBe(403);
    await User.updateOne({ _id: admin.user._id }, { isActive: false });
    expect((await request(app).get('/api/admin/users').set(bearer(admin.accessToken))).status).toBe(401);
  });

  it('admin listing never exposes secrets or hashes', async () => {
    const admin = await registerAdmin('a');
    const res = await request(app).get('/api/admin/users').set(bearer(admin.accessToken));
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|twoFactorSecret|\$2[aby]\$/);
  });
});

describe('error handling', () => {
  it('malformed JSON -> 400 without parser internals; oversized -> 413', async () => {
    const bad = await request(app).post('/api/auth/login').set('Content-Type', 'application/json').send('{"email":');
    expect(bad.status).toBe(400);
    expect(bad.body).toEqual({ error: 'Malformed JSON body' });
    const big = await request(app).post('/api/auth/login').send({ email: 'a@example.com', password: 'x'.repeat(20000) });
    expect(big.status).toBe(413);
  });

  it('unknown route 404; no stack traces in any error body', async () => {
    const res = await request(app).get('/api/nope');
    expect(res.status).toBe(404);
    expect(JSON.stringify(res.body)).not.toMatch(/at .*\.js|node_modules/);
  });
});

describe('startup configuration', () => {
  const run = (envOver) => {
    const { spawnSync } = require('child_process');
    return spawnSync(process.execPath, ['-e', "require('./src/config/env')"], {
      cwd: require('path').join(__dirname, '..'),
      env: { PATH: process.env.PATH, ...envOver },
      encoding: 'utf8',
    });
  };
  const good = { JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40) };
  it('refuses to start with missing, short or identical JWT secrets (no default secret)', () => {
    expect(run({}).status).not.toBe(0);
    expect(run({ ...good, JWT_ACCESS_SECRET: 'short' }).status).not.toBe(0);
    expect(run({ ...good, JWT_REFRESH_SECRET: good.JWT_ACCESS_SECRET }).status).not.toBe(0);
    expect(run(good).status).toBe(0);
  });
});
