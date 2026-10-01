const request = require('supertest');
const speakeasy = require('speakeasy');
const User = require('../../src/models/User');
const createApp = require('../../src/app');

const app = createApp();

const creds = (n = 'jane') => ({ email: `${n}@example.com`, password: 'StrongPass123' });

function cookieValue(res, name = 'refreshToken') {
  const raw = (res.headers['set-cookie'] || []).find((c) => c.startsWith(`${name}=`));
  return raw ? raw.split(';')[0].slice(name.length + 1) : null;
}

async function register(n = 'jane') {
  const res = await request(app).post('/api/auth/register').send(creds(n));
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { res, accessToken: res.body.accessToken, refreshToken: cookieValue(res), user: res.body.user };
}

/** Registers a normal user, then promotes via the database (the operator path). */
async function registerAdmin(n = 'boss') {
  const r = await register(n);
  await User.updateOne({ _id: r.user._id }, { role: 'admin', $inc: { sessionVersion: 1 } });
  const login = await request(app).post('/api/auth/login').send(creds(n));
  return { ...r, accessToken: login.body.accessToken, refreshToken: cookieValue(login) };
}

const refreshWith = (token) => request(app).post('/api/auth/refresh').set('Cookie', `refreshToken=${token}`);
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

/** Code for the TOTP step `offsetSteps` away from now (verifier accepts +-1). */
const totpCode = (secret, offsetSteps = 0) =>
  speakeasy.totp({ secret, encoding: 'base32', time: Math.floor(Date.now() / 1000) + offsetSteps * 30 });

module.exports = { app, request, creds, cookieValue, register, registerAdmin, refreshWith, bearer, totpCode };
