const { app, request, creds, register } = require('./helpers');
const { getRedisClient } = require('../src/config/redis');
const createApp = require('../src/app');

describe('Redis-backed login throttle (real Redis)', () => {
  beforeEach(() => register());
  const bad = (a = app, c = creds()) => request(a).post('/api/auth/login').send({ ...c, password: 'WrongPass123' });

  it('allows maxAttempts then returns 429 with Retry-After, even for the correct password', async () => {
    for (let i = 0; i < 5; i += 1) expect((await bad()).status).toBe(401);
    const blocked = await bad();
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    expect((await request(app).post('/api/auth/login').send(creds())).status).toBe(429);
  });

  it('counter has a TTL (cannot become a permanent lock)', async () => {
    await bad();
    const redis = getRedisClient();
    const [key] = await redis.keys('login-attempts:*');
    const ttl = await redis.ttl(key);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(900);
  });

  it('heals a counter that lost its TTL', async () => {
    const redis = getRedisClient();
    await bad();
    const [key] = await redis.keys('login-attempts:*');
    await redis.persist(key);
    await bad();
    expect(await redis.ttl(key)).toBeGreaterThan(0);
  });

  it('is shared across app instances (two createApp() instances, one Redis)', async () => {
    const app2 = createApp();
    for (let i = 0; i < 3; i += 1) await bad(app);
    for (let i = 0; i < 2; i += 1) await bad(app2);
    expect((await bad(app2)).status).toBe(429);
    expect((await bad(app)).status).toBe(429);
  });

  it('50 concurrent attempts: exactly maxAttempts reach the password check (atomic counter)', async () => {
    const results = await Promise.all(Array.from({ length: 50 }, () => bad()));
    expect(results.filter((r) => r.status === 401)).toHaveLength(5);
    expect(results.filter((r) => r.status === 429)).toHaveLength(45);
  });

  it('successful login resets the counter', async () => {
    for (let i = 0; i < 3; i += 1) await bad();
    expect((await request(app).post('/api/auth/login').send(creds())).status).toBe(200);
    for (let i = 0; i < 5; i += 1) expect((await bad()).status).toBe(401);
  });

  it('keys are per (email, ip): another email is unaffected; X-Forwarded-For is not trusted', async () => {
    await register('other');
    for (let i = 0; i < 6; i += 1) await bad();
    expect((await bad(app, creds('other'))).status).toBe(401);
    const spoof = await request(app).post('/api/auth/login').set('X-Forwarded-For', '9.9.9.9').send({ ...creds(), password: 'WrongPass123' });
    expect(spoof.status).toBe(429);
  });

  it('login limiter FAILS OPEN when Redis errors (Mongo account lock is the backstop)', async () => {
    const spy = jest.spyOn(getRedisClient(), 'eval').mockRejectedValue(new Error('redis down'));
    try {
      expect((await request(app).post('/api/auth/login').send(creds())).status).toBe(200);
    } finally {
      spy.mockRestore();
    }
  });
});
