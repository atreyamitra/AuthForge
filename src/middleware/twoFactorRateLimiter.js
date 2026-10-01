const redisLimiter = require('./redisLimiter');
const env = require('../config/env');
const { verifyTwoFactorPendingToken } = require('../utils/tokens');

/**
 * Per-user throttle on every endpoint that checks a TOTP code. A 6-digit code
 * is brute-forceable without it. FAILS CLOSED (503) on Redis errors, since
 * there is no other backstop on this path.
 * Key = user id (from the authenticated user, or the pending-2FA token's
 * subject); falls back to IP if neither is available.
 */
module.exports = function twoFactorRateLimiter() {
  return redisLimiter({
    prefix: '2fa-attempts',
    keyFn: (req) => {
      if (req.user) return `u:${req.user._id}`;
      try {
        return `u:${verifyTwoFactorPendingToken(req.body?.twoFactorToken).sub}`;
      } catch {
        return `ip:${req.ip}`;
      }
    },
    max: env.twoFactorRateLimit.maxAttempts,
    windowMs: env.twoFactorRateLimit.windowMs,
    failOpen: false,
    message: 'Too many two-factor attempts. Please try again later.',
  });
};
