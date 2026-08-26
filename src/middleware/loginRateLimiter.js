const { getRedisClient } = require('../config/redis');
const env = require('../config/env');

/**
 * Redis-backed brute-force protection, keyed on email + IP.
 * Using Redis (rather than in-memory express-rate-limit) means the
 * counters survive process restarts and work correctly across multiple
 * instances of the service behind a load balancer.
 */
function loginRateLimiter() {
  const windowSeconds = Math.ceil(env.rateLimit.windowMs / 1000);
  const maxAttempts = env.rateLimit.maxAttempts;

  return async function rateLimitMiddleware(req, res, next) {
    try {
      const email = (req.body?.email || 'unknown').toLowerCase();
      const key = `login-attempts:${email}:${req.ip}`;
      const redis = getRedisClient();

      const attempts = await redis.incr(key);
      if (attempts === 1) {
        await redis.expire(key, windowSeconds);
      }

      if (attempts > maxAttempts) {
        const ttl = await redis.ttl(key);
        res.set('Retry-After', String(ttl > 0 ? ttl : windowSeconds));
        return res.status(429).json({
          error: 'Too many login attempts. Please try again later.',
          retryAfterSeconds: ttl > 0 ? ttl : windowSeconds,
        });
      }

      // Attach a helper so the controller can clear the counter on success.
      req.clearLoginAttempts = () => redis.del(key);
      next();
    } catch (err) {
      // Fail open on infra errors rather than locking everyone out of login.
      console.error('[rateLimiter] redis error, failing open:', err.message);
      next();
    }
  };
}

module.exports = loginRateLimiter;
