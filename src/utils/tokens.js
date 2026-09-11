const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const env = require('../config/env');

function signAccessToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, type: 'access', tokenVersion: user.tokenVersion },
    env.jwt.accessSecret,
    { expiresIn: env.jwt.accessExpiresIn }
  );
}

/**
 * Short-lived, single-purpose token issued after a correct password check
 * for a 2FA-enabled account. It proves "password was correct" without
 * granting any actual access — it can only be redeemed at
 * POST /api/auth/2fa/login-verify, and only within 5 minutes.
 */
function signTwoFactorPendingToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), type: '2fa_pending', tokenVersion: user.tokenVersion },
    env.jwt.accessSecret,
    { expiresIn: '5m' }
  );
}

function verifyTwoFactorPendingToken(token) {
  const payload = jwt.verify(token, env.jwt.accessSecret);
  if (payload.type !== '2fa_pending') {
    throw new Error('Wrong token type');
  }
  return payload;
}

function signRefreshToken(user) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user._id.toString(), type: 'refresh', jti, tokenVersion: user.tokenVersion },
    env.jwt.refreshSecret,
    { expiresIn: env.jwt.refreshExpiresIn }
  );
  return { token, jti };
}

function verifyAccessToken(token) {
  return jwt.verify(token, env.jwt.accessSecret);
}

function verifyRefreshToken(token) {
  const payload = jwt.verify(token, env.jwt.refreshSecret);
  if (payload.type !== 'refresh' || typeof payload.jti !== 'string' ||
      !Number.isSafeInteger(payload.tokenVersion) || payload.tokenVersion < 0) {
    throw new Error('Invalid refresh token claims');
  }
  return payload;
}

/** Converts a JWT expiresIn-style string (e.g. "7d", "15m") to seconds. */
function expiresInToSeconds(str) {
  const match = /^(\d+)([smhd])$/.exec(str);
  if (!match) return 900; // fallback: 15 minutes
  const value = Number(match[1]);
  const unit = match[2];
  const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
  return value * multipliers[unit];
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  signTwoFactorPendingToken,
  verifyTwoFactorPendingToken,
  expiresInToSeconds,
};
