const rateLimit = require('express-rate-limit');

// Coarse-grained limiter applied to the whole API to blunt scripted abuse;
// the login route additionally gets the stricter Redis-backed limiter.
const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
});

module.exports = apiRateLimiter;
