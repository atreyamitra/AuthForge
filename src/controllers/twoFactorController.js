const speakeasy = require('speakeasy');
const { verifyAndConsumeTotp } = require('../utils/totp');
const qrcode = require('qrcode');
const User = require('../models/User');
const { auditLog } = require('../utils/audit');
const {
  signAccessToken,
  signTwoFactorPendingToken,
  verifyTwoFactorPendingToken,
} = require('../utils/tokens');

/**
 * Step 1 of enabling 2FA: generate a TOTP secret, store it *unconfirmed*
 * (twoFactorEnabled stays false until the user proves they can produce a
 * valid code), and return a QR code the user scans with an authenticator
 * app (Google Authenticator, Authy, 1Password, etc).
 */
async function setupTwoFactor(req, res, next) {
  try {
    // Replacing the secret of an already-enrolled account would let a stolen
    // access token swap in an attacker-known seed; disable first (needs password + code).
    if (req.user.twoFactorEnabled) {
      return res.status(409).json({ error: '2FA is already enabled; disable it first' });
    }
    const secret = speakeasy.generateSecret({
      name: `AuthForge (${req.user.email})`,
      length: 20,
    });

    await User.findByIdAndUpdate(req.user._id, { twoFactorSecret: secret.base32 });

    const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    auditLog('2fa_setup_initiated', { userId: req.user._id.toString() });

    res.json({
      message: 'Scan this QR code with your authenticator app, then confirm with /2fa/verify',
      otpauthUrl: secret.otpauth_url,
      qrCode: qrDataUrl, // base64 data: URL, render directly in an <img> tag
      manualEntryKey: secret.base32, // fallback if the user can't scan
    });
  } catch (err) {
    next(err);
  }
}

/** Step 2: user submits a code from their app to confirm setup and flip twoFactorEnabled on. */
async function verifyTwoFactorSetup(req, res, next) {
  try {
    const { code } = req.body;
    const user = await User.findById(req.user._id).select('+twoFactorSecret');

    if (!user?.twoFactorSecret) {
      return res.status(400).json({ error: 'No pending 2FA setup found. Call /2fa/setup first.' });
    }

    const valid = await verifyAndConsumeTotp(user._id, user.twoFactorSecret, code);

    if (!valid) {
      auditLog('2fa_setup_failed', { userId: req.user._id.toString() });
      return res.status(400).json({ error: 'Invalid code' });
    }

    await User.findByIdAndUpdate(req.user._id, { twoFactorEnabled: true });
    auditLog('2fa_enabled', { userId: req.user._id.toString() });

    res.json({ message: '2FA is now enabled on your account' });
  } catch (err) {
    next(err);
  }
}

async function disableTwoFactor(req, res, next) {
  try {
    const { code, password } = req.body;
    const user = await User.findById(req.user._id).select('+twoFactorSecret +passwordHash');

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled on this account' });
    }

    // Re-authentication: a stolen access token alone must not be able to turn 2FA off.
    if (!(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const valid = await verifyAndConsumeTotp(user._id, user.twoFactorSecret, code);

    if (!valid) {
      return res.status(400).json({ error: 'Invalid code' });
    }

    await User.findByIdAndUpdate(req.user._id, { twoFactorEnabled: false, twoFactorSecret: null });
    auditLog('2fa_disabled', { userId: req.user._id.toString() });

    res.json({ message: '2FA has been disabled' });
  } catch (err) {
    next(err);
  }
}

/**
 * Called from the login controller instead of issuing tokens directly,
 * when the account has 2FA enabled. Returns a short-lived pending token
 * instead of real access — the client then calls /2fa/login-verify.
 */
function issueTwoFactorChallenge(user) {
  return {
    requiresTwoFactor: true,
    twoFactorToken: signTwoFactorPendingToken(user),
  };
}

/** Step 2 of login for 2FA accounts: redeem the pending token + a TOTP code for real tokens. */
async function verifyTwoFactorLogin(req, res, next) {
  try {
    const { twoFactorToken, code } = req.body;
    if (!twoFactorToken || !code) {
      return res.status(400).json({ error: 'twoFactorToken and code are required' });
    }

    let payload;
    try {
      payload = verifyTwoFactorPendingToken(twoFactorToken);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired 2FA challenge, please log in again' });
    }

    const user = await User.findById(payload.sub).select('+twoFactorSecret');
    if (!user || !user.twoFactorEnabled) {
      return res.status(401).json({ error: 'Invalid 2FA state for this account' });
    }

    const valid = await verifyAndConsumeTotp(user._id, user.twoFactorSecret, code);

    if (!valid) {
      auditLog('2fa_login_failed', { userId: user._id.toString() });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }

    // Delegate to the same token-issuance path the password login uses.
    const { issueTokenPair } = require('./authController')._internal;
    const accessToken = await issueTokenPair(user, req, res);
    if (req.resetRateLimit) await req.resetRateLimit().catch(() => {});

    auditLog('2fa_login_success', { userId: user._id.toString() });
    return res.json({ user, accessToken });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  setupTwoFactor,
  verifyTwoFactorSetup,
  disableTwoFactor,
  issueTwoFactorChallenge,
  verifyTwoFactorLogin,
};
