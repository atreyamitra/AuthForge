const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const env = require('../config/env');

const ALG = 'HS256';
const VERIFY_OPTS = { algorithms: [ALG] };

/** `sv` = sessionVersion the token belongs to; compared against the user's current value. */
function signAccessToken(user, sessionVersion = user.sessionVersion) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, type: 'access', sv: sessionVersion },
    env.jwt.accessSecret,
    { algorithm: ALG, expiresIn: env.jwt.accessExpiresIn }
  );
}

/**
 * Short-lived, single-purpose token issued after a correct password check
 * for a 2FA-enabled account. It proves "password was correct" without
 * granting any actual access; it is only redeemable at /2fa/login-verify.
 */
function signTwoFactorPendingToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), type: '2fa_pending' },
    env.jwt.accessSecret,
    { algorithm: ALG, expiresIn: '5m' }
  );
}

function verifyTwoFactorPendingToken(token) {
  const payload = jwt.verify(token, env.jwt.accessSecret, VERIFY_OPTS);
  if (payload.type !== '2fa_pending') {
    throw new Error('Wrong token type');
  }
  return payload;
}

function signRefreshToken(user, { family, sessionVersion }) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user._id.toString(), type: 'refresh', jti, fam: family, sv: sessionVersion },
    env.jwt.refreshSecret,
    { algorithm: ALG, expiresIn: env.jwt.refreshExpiresIn }
  );
  return { token, jti };
}

function verifyAccessToken(token) {
  return jwt.verify(token, env.jwt.accessSecret, VERIFY_OPTS);
}

function verifyRefreshToken(token) {
  const payload = jwt.verify(token, env.jwt.refreshSecret, VERIFY_OPTS);
  if (payload.type !== 'refresh') {
    throw new Error('Wrong token type');
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
