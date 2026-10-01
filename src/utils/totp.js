const speakeasy = require('speakeasy');
const User = require('../models/User');

const STEP_SECONDS = 30;

/**
 * Checks a TOTP code (+-1 step of clock drift) and, if valid, atomically
 * records its time step so the same code (or any older one) can never be
 * accepted again. The conditional update is what makes replay protection
 * hold across concurrent requests/instances. Returns true only for the
 * single caller that advanced twoFactorLastStep.
 */
async function verifyAndConsumeTotp(userId, secret, code) {
  const delta = speakeasy.totp.verifyDelta({ secret, encoding: 'base32', token: code, window: 1 });
  if (!delta) return false;
  const step = Math.floor(Date.now() / 1000 / STEP_SECONDS) + delta.delta;
  const updated = await User.findOneAndUpdate(
    { _id: userId, twoFactorLastStep: { $lt: step } },
    { twoFactorLastStep: step }
  );
  return Boolean(updated);
}

module.exports = { verifyAndConsumeTotp };
