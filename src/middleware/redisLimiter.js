const { getRedisClient } = require('../config/redis');
const { logger } = require('../utils/audit');

// INCR + (re)arm expiry in one atomic server-side step. The PTTL check also
// heals a counter that somehow lost its TTL, so it can never lock a key forever.
const CONSUME_LUA = `
local c = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if c == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {c, ttl}
`;

/**
 * Fixed-window counter limiter backed by Redis.
 *  - keyFn(req) -> string key suffix
 *  - failOpen:   on Redis error, let the request through (true) or answer 503 (false)
 * On success, req.resetRateLimit() deletes the counter.
 */
function redisLimiter({ prefix, keyFn, max, windowMs, failOpen, message }) {
  return async function limiter(req, res, next) {
    let redis;
    let key;
    try {
      key = `${prefix}:${keyFn(req)}`;
      redis = getRedisClient();
      const [count, ttlMs] = await redis.eval(CONSUME_LUA, 1, key, String(windowMs));
      req.resetRateLimit = () => redis.del(key);
      if (count > max) {
        const retryAfter = Math.max(1, Math.ceil(ttlMs / 1000));
        res.set('Retry-After', String(retryAfter));
        return res.status(429).json({ error: message, retryAfterSeconds: retryAfter });
      }
      return next();
    } catch (err) {
      logger.error({ err: err.message, limiter: prefix }, 'rate limiter backend error');
      if (failOpen) {
        req.resetRateLimit = async () => {};
        return next();
      }
      return res.status(503).json({ error: 'Service temporarily unavailable' });
    }
  };
}

module.exports = redisLimiter;
