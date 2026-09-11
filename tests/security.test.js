const request = require('supertest');
jest.mock('../src/models/User');
jest.mock('../src/models/RefreshToken');
const User = require('../src/models/User');
const RefreshToken = require('../src/models/RefreshToken');
const createApp = require('../src/app');
const auth = require('../src/controllers/authController');
const app = createApp();
const credentials = { email: 'security@example.com', password: 'StrongPass123' };
const cookieToken = res => decodeURIComponent(res.headers['set-cookie'][0].split(';')[0].split('=')[1]);
afterEach(() => { User.__reset(); RefreshToken.__reset(); jest.restoreAllMocks(); });

test('public registration cannot create an administrator', async () => {
  const res = await request(app).post('/api/auth/register').send({ ...credentials, role: 'admin' });
  expect(res.status).toBe(400);
  expect(await User.findOne({ email: credentials.email })).toBeNull();
});

test('controller forces an ordinary role even without request validation', async () => {
  const res = { cookie: jest.fn(), clearCookie: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn() };
  const next = jest.fn();
  await auth.register({ body: { ...credentials, role: 'admin' }, headers: {}, ip: '127.0.0.1' }, res, next);
  expect(next).not.toHaveBeenCalled();
  expect((await User.findOne({ email: credentials.email })).role).toBe('user');
});

test('concurrent use of the same refresh token issues exactly one replacement', async () => {
  const reg = await request(app).post('/api/auth/register').send(credentials);
  const token = cookieToken(reg);
  const responses = Array.from({ length: 10 }, () => ({
    cookie: jest.fn(), clearCookie: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn(),
  }));
  const errors = [];
  await Promise.all(responses.map(res => auth.refresh({
    body: { refreshToken: token }, headers: {}, ip: '127.0.0.1',
  }, res, error => errors.push(error))));
  expect(errors).toEqual([]);
  expect(responses.filter(res => res.cookie.mock.calls.length)).toHaveLength(1);
  expect(responses.filter(res => res.status.mock.calls.some(([status]) => status === 401))).toHaveLength(9);
});

test('browser cookie logout revokes the refresh token on the server', async () => {
  const agent = request.agent(app);
  const reg = await agent.post('/api/auth/register').send(credentials);
  const token = cookieToken(reg);
  expect((await agent.post('/api/auth/logout')).status).toBe(204);
  const replay = await request(app).post('/api/auth/refresh').send({ refreshToken: token });
  expect(replay.status).toBe(401);
});

test('logout-all invalidates old sessions but allows immediate same-second login', async () => {
  const clock = jest.spyOn(Date, 'now').mockReturnValue(1800000000500);
  const reg = await request(app).post('/api/auth/register').send(credentials);
  const oldRefresh = cookieToken(reg);
  expect((await request(app).post('/api/auth/logout-all').set('Authorization', `Bearer ${reg.body.accessToken}`)).status).toBe(204);
  const login = await request(app).post('/api/auth/login').send(credentials);
  expect(login.status).toBe(200);
  expect((await request(app).get('/api/auth/me').set('Authorization', `Bearer ${reg.body.accessToken}`)).status).toBe(401);
  expect((await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login.body.accessToken}`)).status).toBe(200);
  expect((await request(app).post('/api/auth/refresh').send({ refreshToken: oldRefresh })).status).toBe(401);
  clock.mockRestore();
});


test('login removes the old narrow cookie without removing the new auth cookie', async () => {
  const agent = request.agent(app);
  await agent.post('/api/auth/register').send(credentials);
  const login = await agent.post('/api/auth/login').send(credentials);
  const cookies = login.headers['set-cookie'];
  expect(cookies.some(cookie => /Path=\/api\/auth;/.test(cookie) && !/Expires=Thu, 01 Jan 1970/.test(cookie))).toBe(true);
  expect(cookies.some(cookie => /Path=\/api\/auth\/refresh;/.test(cookie) && /Expires=Thu, 01 Jan 1970/.test(cookie))).toBe(true);
  expect((await agent.post('/api/auth/refresh').send()).status).toBe(200);
});

test('logout reports a database failure instead of falsely confirming revocation', async () => {
  const reg = await request(app).post('/api/auth/register').send(credentials);
  const token = cookieToken(reg);
  const update = jest.spyOn(RefreshToken, 'updateOne').mockRejectedValueOnce(new Error('test database unavailable'));
  expect((await request(app).post('/api/auth/logout').send({ refreshToken: token })).status).toBe(500);
  update.mockRestore();
  expect((await request(app).post('/api/auth/logout').send({ refreshToken: token })).status).toBe(204);
  expect((await request(app).post('/api/auth/refresh').send({ refreshToken: token })).status).toBe(401);
});
