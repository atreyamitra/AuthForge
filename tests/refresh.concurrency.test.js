const path = require('path');
const { spawn } = require('child_process');
const { app, request, creds, register, refreshWith, bearer, cookieValue } = require('./helpers');
const RefreshToken = require('../src/models/RefreshToken');
const User = require('../src/models/User');
const { signRefreshToken } = require('../src/utils/tokens');

const N = 24;

describe('refresh-token rotation against real MongoDB', () => {
  it('rotates: new pair works, old refresh token is dead', async () => {
    const { refreshToken } = await register();
    const r1 = await refreshWith(refreshToken);
    expect(r1.status).toBe(200);
    const next = cookieValue(r1);
    expect(next).toBeTruthy();
    expect(next).not.toBe(refreshToken);
    expect((await request(app).get('/api/auth/me').set(bearer(r1.body.accessToken))).status).toBe(200);
    expect((await refreshWith(refreshToken)).status).toBe(401); // replay of consumed token
    expect((await refreshWith(next)).status).toBe(200); // chain continues
  });

  it('rejects missing, garbage, wrong-type and unknown-jti refresh tokens', async () => {
    expect((await request(app).post('/api/auth/refresh')).status).toBe(401);
    expect((await refreshWith('garbage')).status).toBe(401);
    const { accessToken, user } = await register();
    expect((await refreshWith(accessToken)).status).toBe(401); // access token is not a refresh token
    const forged = signRefreshToken(user, { family: 'f', sessionVersion: 0 }).token; // valid signature, never stored
    expect((await refreshWith(forged)).status).toBe(401);
  });

  it(`${N} concurrent refreshes of one token in one process: exactly one wins`, async () => {
    const { refreshToken, user } = await register();
    const results = await Promise.all(Array.from({ length: N }, () => refreshWith(refreshToken)));
    const winners = results.filter((r) => r.status === 200);
    expect(winners).toHaveLength(1);
    expect(results.filter((r) => r.status === 401)).toHaveLength(N - 1);
    await assertSingleSuccessor(user._id, refreshToken, winners[0]);
  });

  it('repeats the race 5 times with fresh sessions', async () => {
    for (let i = 0; i < 5; i += 1) {
      const { refreshToken } = await register(`rep${i}`);
      const results = await Promise.all(Array.from({ length: N }, () => refreshWith(refreshToken)));
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    }
  });

  it(`${N} concurrent refreshes spread over TWO separate app processes sharing one MongoDB: exactly one wins`, async () => {
    const { refreshToken, user } = await register();
    const servers = await Promise.all([startChild(), startChild()]);
    try {
      let release;
      const barrier = new Promise((r) => { release = r; });
      const calls = Array.from({ length: N }, (_, i) =>
        barrier.then(() =>
          fetch(`http://127.0.0.1:${servers[i % 2].port}/api/auth/refresh`, {
            method: 'POST',
            headers: { Cookie: `refreshToken=${refreshToken}` },
          }).then(async (r) => ({ status: r.status, cookie: r.headers.get('set-cookie') }))
        )
      );
      await new Promise((r) => setTimeout(r, 200));
      release();
      const results = await Promise.all(calls);
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(results.filter((r) => r.status === 401)).toHaveLength(N - 1);
      const docs = await RefreshToken.find({ user: user._id });
      expect(docs).toHaveLength(2);
      expect(docs.filter((d) => !d.revoked)).toHaveLength(1);
    } finally {
      servers.forEach((s) => s.child.kill());
    }
  }, 60000);

  it('logout revokes the whole session family (successor tokens too)', async () => {
    const { refreshToken } = await register();
    const r1 = await refreshWith(refreshToken);
    const successor = cookieValue(r1);
    const out = await request(app).post('/api/auth/logout').set('Cookie', `refreshToken=${successor}`);
    expect(out.status).toBe(204);
    expect((await refreshWith(successor)).status).toBe(401);
  });

  it('refresh cookie is scoped so the browser sends it to /logout as well as /refresh', async () => {
    const { res } = await register();
    const c = res.headers['set-cookie'][0];
    expect(c).toMatch(/Path=\/api\/auth(;|$)/);
    expect(c).toMatch(/HttpOnly/);
    expect(c).toMatch(/SameSite=Strict/);
  });

  it('an expired stored token cannot be rotated even with a valid signature', async () => {
    const { refreshToken, user } = await register();
    await RefreshToken.updateMany({ user: user._id }, { expiresAt: new Date(Date.now() - 1000) });
    expect((await refreshWith(refreshToken)).status).toBe(401);
  });

  it('an inactive user cannot refresh', async () => {
    const { refreshToken, user } = await register();
    await User.updateOne({ _id: user._id }, { isActive: false });
    expect((await refreshWith(refreshToken)).status).toBe(401);
  });
});

describe('global logout / sessionVersion', () => {
  it('kills outstanding access tokens immediately and refresh tokens from before', async () => {
    const { accessToken, refreshToken } = await register();
    expect((await request(app).get('/api/auth/me').set(bearer(accessToken))).status).toBe(200);
    expect((await request(app).post('/api/auth/logout-all').set(bearer(accessToken))).status).toBe(204);
    expect((await request(app).get('/api/auth/me').set(bearer(accessToken))).status).toBe(401);
    expect((await refreshWith(refreshToken)).status).toBe(401);
    // new login after global logout works
    const login = await request(app).post('/api/auth/login').send(creds());
    expect(login.status).toBe(200);
    expect((await request(app).get('/api/auth/me').set(bearer(login.body.accessToken))).status).toBe(200);
  });

  it('a forged token with a future sessionVersion claim is rejected (sv is not client-controlled)', async () => {
    const jwt = require('jsonwebtoken');
    const { user } = await register();
    const forged = jwt.sign({ sub: user._id, role: 'user', type: 'access', sv: 5 }, process.env.JWT_ACCESS_SECRET, { algorithm: 'HS256' });
    expect((await request(app).get('/api/auth/me').set(bearer(forged))).status).toBe(401);
  });

  it('logout-all racing with refresh never leaves a usable session behind (30 rounds)', async () => {
    for (let i = 0; i < 30; i += 1) {
      const { accessToken, refreshToken } = await register(`race${i}`);
      const [refreshRes, logoutRes] = await Promise.all([
        refreshWith(refreshToken),
        request(app).post('/api/auth/logout-all').set(bearer(accessToken)),
      ]);
      expect(logoutRes.status).toBe(204);
      if (refreshRes.status === 200) {
        // Refresh won the race: its output must be dead on arrival.
        const me = await request(app).get('/api/auth/me').set(bearer(refreshRes.body.accessToken));
        expect(me.status).toBe(401);
        expect((await refreshWith(cookieValue(refreshRes))).status).toBe(401);
      }
    }
  });
});

async function assertSingleSuccessor(userId, oldToken, winner) {
  const docs = await RefreshToken.find({ user: userId });
  expect(docs).toHaveLength(2); // original (consumed) + exactly one successor
  expect(docs.filter((d) => !d.revoked)).toHaveLength(1);
  expect(docs[0].family).toBe(docs[1].family);
  const successor = cookieValue(winner);
  expect((await refreshWith(oldToken)).status).toBe(401);
  expect((await refreshWith(successor)).status).toBe(200);
}

function startChild() {
  return new Promise((resolve, reject) => {
    const port = 20000 + Math.floor(Math.random() * 20000);
    const child = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], {
      env: { ...process.env, PORT: String(port), NODE_ENV: 'test' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const timer = setTimeout(() => { child.kill(); reject(new Error('child app did not start')); }, 20000);
    child.stdout.on('data', (d) => {
      if (String(d).includes('listening on port')) { clearTimeout(timer); resolve({ child, port }); }
    });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`child exited ${code}`)); });
  });
}
