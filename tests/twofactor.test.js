const speakeasy = require('speakeasy');
const { app, request, creds, register, bearer, totpCode } = require('./helpers');
const { getRedisClient } = require('../src/config/redis');
const User = require('../src/models/User');

async function enroll() {
  const r = await register();
  const setup = await request(app).post('/api/auth/2fa/setup').set(bearer(r.accessToken));
  const secret = setup.body.manualEntryKey;
  const ok = await request(app).post('/api/auth/2fa/verify').set(bearer(r.accessToken)).send({ code: totpCode(secret, 0) });
  expect(ok.status).toBe(200);
  return { ...r, secret };
}
const loginChallenge = async () => (await request(app).post('/api/auth/login').send(creds())).body.twoFactorToken;
const loginVerify = (twoFactorToken, code) => request(app).post('/api/auth/2fa/login-verify').send({ twoFactorToken, code });

describe('TOTP 2FA (real MongoDB + Redis)', () => {
  it('setup returns the secret once; it is never in profile responses; stored server-side only', async () => {
    const { accessToken, user } = await register();
    const setup = await request(app).post('/api/auth/2fa/setup').set(bearer(accessToken));
    expect(setup.status).toBe(200);
    expect(setup.body.manualEntryKey).toMatch(/^[A-Z2-7]+$/);
    const me = await request(app).get('/api/auth/me').set(bearer(accessToken));
    expect(JSON.stringify(me.body)).not.toContain(setup.body.manualEntryKey);
    expect((await User.findById(user._id)).twoFactorEnabled).toBe(false); // not enabled until confirmed
  });

  it('password login of a 2FA account yields only a challenge, no access token or refresh cookie', async () => {
    await enroll();
    const res = await request(app).post('/api/auth/login').send(creds());
    expect(res.body.requiresTwoFactor).toBe(true);
    expect(res.body.accessToken).toBeUndefined();
    expect(res.headers['set-cookie']).toBeUndefined();
    // the pending token is not an access token
    expect((await request(app).get('/api/auth/me').set(bearer(res.body.twoFactorToken))).status).toBe(401);
  });

  it('completes login with a valid code; a wrong code is rejected', async () => {
    const { secret } = await enroll();
    const t = await loginChallenge();
    expect((await loginVerify(t, '000000')).status).toBe(401);
    const ok = await loginVerify(t, totpCode(secret, 1));
    expect(ok.status).toBe(200);
    expect(ok.body.accessToken).toBeDefined();
  });

  it('REPLAY: a code is single-use. Same code (and older steps) rejected after acceptance', async () => {
    const { secret } = await enroll(); // enrollment consumed the current step
    const code = totpCode(secret, 1);
    const t = await loginChallenge();
    expect((await loginVerify(t, code)).status).toBe(200);
    expect((await loginVerify(t, code)).status).toBe(401); // same code again
    expect((await loginVerify(t, totpCode(secret, 0))).status).toBe(401); // older step
  });

  it('REPLAY race: 10 concurrent submissions of one valid code -> exactly one succeeds', async () => {
    const { secret } = await enroll();
    const code = totpCode(secret, 1);
    const t = await loginChallenge();
    const rs = await Promise.all(Array.from({ length: 10 }, () => loginVerify(t, code)));
    expect(rs.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it('brute force: after maxAttempts wrong codes the user gets 429, even with a valid code', async () => {
    const { secret } = await enroll();
    await getRedisClient().flushdb(); // enrollment shares the per-user attempt budget; start clean
    const t = await loginChallenge();
    for (let i = 0; i < 5; i += 1) expect((await loginVerify(t, '000000')).status).toBe(401);
    expect((await loginVerify(t, '000000')).status).toBe(429);
    expect((await loginVerify(t, totpCode(secret, 1))).status).toBe(429);
  });

  it('2FA throttle FAILS CLOSED (503) when Redis errors', async () => {
    const { secret } = await enroll();
    const t = await loginChallenge();
    const spy = jest.spyOn(getRedisClient(), 'eval').mockRejectedValue(new Error('redis down'));
    try {
      const res = await loginVerify(t, totpCode(secret, 1));
      expect(res.status).toBe(503);
    } finally {
      spy.mockRestore();
    }
  });

  it('cannot re-run setup on an enrolled account (would swap in an attacker-known secret)', async () => {
    const { accessToken, user } = await enroll();
    const before = (await User.findById(user._id).select('+twoFactorSecret')).twoFactorSecret;
    const res = await request(app).post('/api/auth/2fa/setup').set(bearer(accessToken));
    expect(res.status).toBe(409);
    expect((await User.findById(user._id).select('+twoFactorSecret')).twoFactorSecret).toBe(before);
  });

  it('disable requires password AND a fresh code', async () => {
    const { accessToken, secret, user } = await enroll();
    const code = totpCode(secret, 1);
    const noPw = await request(app).post('/api/auth/2fa/disable').set(bearer(accessToken)).send({ code });
    expect(noPw.status).toBe(400);
    const badPw = await request(app).post('/api/auth/2fa/disable').set(bearer(accessToken)).send({ code, password: 'WrongPass123' });
    expect(badPw.status).toBe(401);
    expect((await User.findById(user._id)).twoFactorEnabled).toBe(true);
    const ok = await request(app).post('/api/auth/2fa/disable').set(bearer(accessToken)).send({ code, password: 'StrongPass123' });
    expect(ok.status).toBe(200);
    const after = await User.findById(user._id).select('+twoFactorSecret');
    expect(after.twoFactorEnabled).toBe(false);
    expect(after.twoFactorSecret).toBeNull();
  });

  it('rejects malformed codes and unknown/foreign challenge tokens', async () => {
    await enroll();
    const t = await loginChallenge();
    for (const code of ['12345', '1234567', 'abcdef', 123456]) expect((await loginVerify(t, code)).status).toBe(400);
    expect((await loginVerify('garbage', '123456')).status).toBe(401);
    const { accessToken } = await register('other');
    expect((await loginVerify(accessToken, '123456')).status).toBe(401); // access token is not a 2FA challenge
  });

  it('a code from a different secret is rejected', async () => {
    await enroll();
    const t = await loginChallenge();
    const other = speakeasy.generateSecret({ length: 20 }).base32;
    expect((await loginVerify(t, totpCode(other, 0))).status).toBe(401);
  });
});
