require('dotenv').config();

const MIN_SECRET_LENGTH = 32;

const required = (name) => {
  const val = process.env[name];
  if (!val) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return val;
};

const secret = (name) => {
  const val = required(name);
  if (val.length < MIN_SECRET_LENGTH) {
    throw new Error(`${name} must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  return val;
};

const accessSecret = secret('JWT_ACCESS_SECRET');
const refreshSecret = secret('JWT_REFRESH_SECRET');
if (accessSecret === refreshSecret) {
  throw new Error('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ');
}

module.exports = {
  port: Number(process.env.PORT) || 5000,
  nodeEnv: process.env.NODE_ENV || 'development',

  mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/authforge',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',

  jwt: {
    accessSecret,
    refreshSecret,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },

  // Redis-backed per-(email, ip) login throttle.
  rateLimit: {
    windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    maxAttempts: Number(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS) || 5,
  },

  // Redis-backed per-user throttle on TOTP code checks (fails closed).
  twoFactorRateLimit: {
    windowMs: Number(process.env.TWO_FACTOR_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    maxAttempts: Number(process.env.TWO_FACTOR_RATE_LIMIT_MAX_ATTEMPTS) || 5,
  },

  // MongoDB-backed per-account lockout (independent of source IP).
  accountLock: {
    threshold: Number(process.env.ACCOUNT_LOCK_THRESHOLD) || 10,
    durationMs: Number(process.env.ACCOUNT_LOCK_DURATION_MS) || 15 * 60 * 1000,
  },

  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
};
