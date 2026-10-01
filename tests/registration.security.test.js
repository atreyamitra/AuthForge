const { app, request, creds, register } = require('./helpers');
const User = require('../src/models/User');

describe('registration cannot escalate privilege', () => {
  it('assigns the fixed default role "user" and persists it', async () => {
    const { user } = await register();
    expect(user.role).toBe('user');
    expect((await User.findById(user._id)).role).toBe('user');
  });

  it.each([
    ['role', { role: 'admin' }],
    ['isAdmin', { isAdmin: true }],
    ['permissions', { permissions: ['*'] }],
    ['sessionVersion', { sessionVersion: 99 }],
    ['isActive', { isActive: false }],
    ['twoFactorEnabled', { twoFactorEnabled: true }],
    ['twoFactorSecret', { twoFactorSecret: 'JBSWY3DPEHPK3PXP' }],
    ['passwordHash', { passwordHash: 'x' }],
    ['lockUntil', { lockUntil: '2999-01-01T00:00:00.000Z' }],
  ])('rejects (400) and creates no account when the body contains %s', async (_n, extra) => {
    const res = await request(app).post('/api/auth/register').send({ ...creds('mallory'), ...extra });
    expect(res.status).toBe(400);
    expect(await User.countDocuments()).toBe(0);
  });

  it('a raw "__proto__" key in the JSON body does not grant a role', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .set('Content-Type', 'application/json')
      .send(`{"email":"proto@example.com","password":"StrongPass123","__proto__":{"role":"admin"}}`);
    // Either rejected as an unknown key or accepted without effect; never an admin.
    expect([201, 400]).toContain(res.status);
    expect(await User.countDocuments({ role: 'admin' })).toBe(0);
  });

  it('rejects role:"admin" explicitly and never yields an admin', async () => {
    const res = await request(app).post('/api/auth/register').send({ ...creds('evil'), role: 'admin' });
    expect(res.status).toBe(400);
    expect(await User.countDocuments({ role: 'admin' })).toBe(0);
  });

  it('a user cannot self-promote through the admin role endpoint', async () => {
    const { accessToken, user } = await register();
    const res = await request(app)
      .patch(`/api/admin/users/${user._id}/role`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ role: 'admin' });
    expect(res.status).toBe(403);
    expect((await User.findById(user._id)).role).toBe('user');
  });

  it('normalises email so case variants are the same account', async () => {
    await register('jane');
    const res = await request(app).post('/api/auth/register').send({ email: 'JANE@Example.com', password: 'StrongPass123' });
    expect(res.status).toBe(409);
  });

  it('20 concurrent signups with the same email create exactly one account (unique index)', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, () => request(app).post('/api/auth/register').send(creds('race')))
    );
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409)).toHaveLength(19);
    expect(await User.countDocuments({ email: 'race@example.com' })).toBe(1);
  });

  it('rejects NoSQL-operator and non-string input', async () => {
    for (const body of [
      { email: { $ne: null }, password: 'StrongPass123' },
      { email: 'a@example.com', password: { $gt: '' } },
      { email: 'a@example.com', password: 12345678 },
    ]) {
      const res = await request(app).post('/api/auth/register').send(body);
      expect(res.status).toBe(400);
    }
  });
});
