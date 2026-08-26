process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET = 'test_access_secret';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret';
process.env.JWT_ACCESS_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS = '5';
process.env.LOGIN_RATE_LIMIT_WINDOW_MS = '900000';
process.env.REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';

const { closeRedisClient, getRedisClient } = require('../src/config/redis');

afterAll(async () => {
  await closeRedisClient();
});

// Flush any leftover rate-limit / invalidation keys from previous runs so
// tests don't bleed into each other via shared Redis state.
beforeEach(async () => {
  const redis = getRedisClient();
  await redis.flushdb();
});

