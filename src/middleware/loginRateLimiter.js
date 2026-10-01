const redisLimiter = require('./redisLimiter');
const env = require('../config/env');

/**
 * Per-(email, ip) login throttle in Redis (shared by all app instances).
 * FAILS OPEN on Redis errors: the MongoDB per-account lockout in the login
 * controller remains as a backstop, and failing closed would make a Redis
 * outage a full login outage.
 * req.ip is the socket address unless `trust proxy` is configured; this app
 * does not set it, so X-Forwarded-For is NOT trusted.
 */
module.exports = function loginRateLimiter() {
  return redisLimiter({
    prefix: 'login-attempts',
    keyFn: (req) => `${String(req.body?.email || 'unknown').toLowerCase()}:${req.ip}`,
    max: env.rateLimit.maxAttempts,
    windowMs: env.rateLimit.windowMs,
    failOpen: true,
    message: 'Too many login attempts. Please try again later.',
  });
};
