/**
 * End-to-end smoke test against REAL MongoDB + Redis (not the in-memory
 * doubles used by `npm test`). Intended for CI (see .github/workflows/ci.yml)
 * where service containers give us the real infra that a fully sandboxed
 * dev environment sometimes can't reach.
 *
 * Usage: MONGO_URI=... REDIS_URL=... node scripts/integration-smoke.js
 */
const assert = require('assert');
const speakeasy = require('speakeasy');
const { connectDB, disconnectDB } = require('../src/config/db');
const { closeRedisClient } = require('../src/config/redis');
const createApp = require('../src/app');
const User = require('../src/models/User');
const RefreshToken = require('../src/models/RefreshToken');

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}

async function main() {
  await connectDB();
  const app = createApp();
  const server = app.listen(0); // random free port
  const port = server.address().port;
  const base = `http://localhost:${port}`;

  try {
    console.log('== health ==');
    const health = await fetchJson(`${base}/health`);
    assert.strictEqual(health.status, 200);

    console.log('== register ==');
    const email = `ci-smoke-${Date.now()}@example.com`;
    const reg = await fetchJson(`${base}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'SmokeTest123' }),
    });
    assert.strictEqual(reg.status, 201, `register failed: ${JSON.stringify(reg.body)}`);
    assert.ok(reg.body.accessToken, 'no access token returned');

    console.log('== me ==');
    const me = await fetchJson(`${base}/api/auth/me`, {
      headers: { Authorization: `Bearer ${reg.body.accessToken}` },
    });
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.body.user.email, email);

    console.log('== RBAC: non-admin blocked ==');
    const forbidden = await fetchJson(`${base}/api/admin/users`, {
      headers: { Authorization: `Bearer ${reg.body.accessToken}` },
    });
    assert.strictEqual(forbidden.status, 403);

    console.log('== RBAC: admin allowed ==');
    const adminEmail = `ci-admin-${Date.now()}@example.com`;
    // Administrators are provisioned through a trusted DB operation, never signup.
    await User.create({ email: adminEmail, passwordHash: await User.hashPassword('SmokeTest123'), role: 'admin' });
    const adminReg = await fetchJson(`${base}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: adminEmail, password: 'SmokeTest123' }),
    });
    assert.strictEqual(adminReg.status, 200);
    const adminList = await fetchJson(`${base}/api/admin/users`, {
      headers: { Authorization: `Bearer ${adminReg.body.accessToken}` },
    });
    assert.strictEqual(adminList.status, 200);
    assert.ok(Array.isArray(adminList.body.users));

    console.log('== 2FA: setup + verify + login-verify ==');
    const setup = await fetchJson(`${base}/api/auth/2fa/setup`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${reg.body.accessToken}` },
    });
    assert.strictEqual(setup.status, 200);
    const code1 = speakeasy.totp({ secret: setup.body.manualEntryKey, encoding: 'base32' });
    const verify = await fetchJson(`${base}/api/auth/2fa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${reg.body.accessToken}` },
      body: JSON.stringify({ code: code1 }),
    });
    assert.strictEqual(verify.status, 200, `2fa verify failed: ${JSON.stringify(verify.body)}`);

    const loginAttempt = await fetchJson(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'SmokeTest123' }),
    });
    assert.strictEqual(loginAttempt.body.requiresTwoFactor, true);

    const code2 = speakeasy.totp({ secret: setup.body.manualEntryKey, encoding: 'base32' });
    const finish = await fetchJson(`${base}/api/auth/2fa/login-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ twoFactorToken: loginAttempt.body.twoFactorToken, code: code2 }),
    });
    assert.strictEqual(finish.status, 200, `2fa login-verify failed: ${JSON.stringify(finish.body)}`);
    assert.ok(finish.body.accessToken);

    console.log('== security regressions against real persistence ==');
    const post = (path, body, headers = {}) => fetchJson(`${base}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    const escalation = await post('/api/auth/register', {
      email: `ci-escalation-${Date.now()}@example.com`, password: 'SmokeTest123', role: 'admin',
    });
    assert.strictEqual(escalation.status, 400, 'public admin signup must fail');
    const raceEmail = `ci-race-${Date.now()}@example.com`;
    const race = await post('/api/auth/register', { email: raceEmail, password: 'SmokeTest123' });
    assert.strictEqual(race.status, 201);
    const tokenFrom = response => decodeURIComponent(response.headers.getSetCookie().find(cookie => cookie.startsWith('refreshToken=') && !cookie.startsWith('refreshToken=;')).split(';')[0].split('=')[1]);
    const originalRefresh = tokenFrom(race);
    const rotated = await Promise.all(Array.from({ length: 20 }, () =>
      post('/api/auth/refresh', { refreshToken: originalRefresh })));
    assert.strictEqual(rotated.filter(r => r.status === 200).length, 1, 'one refresh winner');
    assert.strictEqual(rotated.filter(r => r.status === 401).length, 19, 'replayed refreshes rejected');
    const winner = rotated.find(r => r.status === 200);
    // Logout races a refresh: any issued old-generation replacement must be unusable.
    const [concurrentRefresh, logoutAll] = await Promise.all([
      post('/api/auth/refresh', { refreshToken: tokenFrom(winner) }),
      post('/api/auth/logout-all', {}, { Authorization: `Bearer ${race.body.accessToken}` }),
    ]);
    assert.strictEqual(logoutAll.status, 204);
    assert.ok([200, 401].includes(concurrentRefresh.status));
    if (concurrentRefresh.status === 200) {
      assert.strictEqual((await fetchJson(`${base}/api/auth/me`, {
        headers: { Authorization: `Bearer ${concurrentRefresh.body.accessToken}` },
      })).status, 401, 'racing access token must be invalidated');
      assert.strictEqual((await post('/api/auth/refresh', {
        refreshToken: tokenFrom(concurrentRefresh),
      })).status, 401, 'racing refresh token must be invalidated');
    }
    const fresh = await post('/api/auth/login', { email: raceEmail, password: 'SmokeTest123' });
    assert.strictEqual(fresh.status, 200);
    assert.strictEqual((await fetchJson(`${base}/api/auth/me`, {
      headers: { Authorization: `Bearer ${fresh.body.accessToken}` },
    })).status, 200, 'immediate login after global logout must work');
    assert.match(fresh.headers.get('set-cookie'), /Path=\/api\/auth(?:;|$)/);
    const freshToken = tokenFrom(fresh);
    assert.strictEqual((await post('/api/auth/logout', {}, {
      Cookie: `refreshToken=${encodeURIComponent(freshToken)}`,
    })).status, 204);
    assert.strictEqual((await post('/api/auth/refresh', { refreshToken: freshToken })).status, 401);
    // TTL cleanup is asynchronous: an expired database record must still be rejected.
    const expiring = await post('/api/auth/login', { email: raceEmail, password: 'SmokeTest123' });
    const expiredToken = tokenFrom(expiring);
    const expiredPayload = require('jsonwebtoken').decode(expiredToken);
    await RefreshToken.updateOne({ tokenId: expiredPayload.jti }, { expiresAt: new Date(0) });
    assert.strictEqual((await post('/api/auth/refresh', { refreshToken: expiredToken })).status, 401);

    console.log('\nALL INTEGRATION SMOKE CHECKS PASSED (real MongoDB + real Redis)');
  } finally {
    server.close();
    await disconnectDB();
    await closeRedisClient();
  }
}

main().catch((err) => {
  console.error('INTEGRATION SMOKE TEST FAILED:', err);
  process.exit(1);
});
