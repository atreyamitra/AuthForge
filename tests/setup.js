// Tests run against REAL MongoDB and REAL Redis. If either is unreachable the
// suite fails (no skipping, no in-memory doubles).
process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET = 'test_access_secret_0123456789_abcdefghijklmnop';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_9876543210_ponmlkjihgfedcba';
process.env.JWT_ACCESS_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS = '5';
process.env.LOGIN_RATE_LIMIT_WINDOW_MS = '900000';
process.env.TWO_FACTOR_RATE_LIMIT_MAX_ATTEMPTS = '5';
process.env.ACCOUNT_LOCK_THRESHOLD = '10';
process.env.API_RATE_LIMIT_MAX = '1000000'; // coarse per-process limiter would throttle burst tests; it is not under test
process.env.MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authforge_test';
process.env.REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';

const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const { closeRedisClient, getRedisClient } = require('../src/config/redis');
const User = require('../src/models/User');
const RefreshToken = require('../src/models/RefreshToken');

beforeAll(async () => {
  if (!/test/.test(process.env.MONGO_URI)) {
    throw new Error('Refusing to run tests against a database whose URI does not contain "test"');
  }
  await connectDB();
  // Unique indexes are part of what is under test; make sure they exist.
  await Promise.all([User.init(), RefreshToken.init()]);
});

afterAll(async () => {
  await disconnectDB();
  await closeRedisClient();
});

beforeEach(async () => {
  await getRedisClient().flushdb();
  await Promise.all(Object.values(mongoose.connection.collections).map((c) => c.deleteMany({})));
});
