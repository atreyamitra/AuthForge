const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { auditLog } = require('../utils/audit');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  expiresInToSeconds,
} = require('../utils/tokens');
const env = require('../config/env');

const REFRESH_COOKIE_NAME = 'refreshToken';
// Must cover both /refresh and /logout, otherwise browsers never send the cookie to /logout.
const REFRESH_COOKIE_PATH = '/api/auth';
const DEFAULT_ROLE = 'user';

function refreshCookieOptions() {
  return {
    httpOnly: true,
    secure: env.nodeEnv === 'production',
    sameSite: 'strict',
    maxAge: expiresInToSeconds(env.jwt.refreshExpiresIn) * 1000,
    path: REFRESH_COOKIE_PATH,
  };
}

async function issueTokenPair(user, req, res, { family = crypto.randomUUID(), sessionVersion = user.sessionVersion } = {}) {
  const accessToken = signAccessToken(user, sessionVersion);
  const { token: refreshToken, jti } = signRefreshToken(user, { family, sessionVersion });

  await RefreshToken.create({
    user: user._id,
    tokenId: jti,
    family,
    sessionVersion,
    userAgent: req.headers['user-agent'] || '',
    ip: req.ip,
    expiresAt: new Date(Date.now() + expiresInToSeconds(env.jwt.refreshExpiresIn) * 1000),
  });

  res.cookie(REFRESH_COOKIE_NAME, refreshToken, refreshCookieOptions());
  return accessToken;
}

async function register(req, res, next) {
  try {
    const { email, password } = req.body; // schema rejects any other key

    if (await User.exists({ email })) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await User.hashPassword(password);
    // Role is NOT client-controlled: public signup always yields DEFAULT_ROLE.
    // A concurrent duplicate is caught by the unique index (E11000 -> 409).
    const user = await User.create({ email, passwordHash, role: DEFAULT_ROLE });

    const accessToken = await issueTokenPair(user, req, res);
    auditLog('user_registered', { userId: user._id.toString(), role: user.role });
    return res.status(201).json({ user, accessToken });
  } catch (err) {
    next(err);
  }
}

// Valid bcrypt hash of a random string; compared against when the email is
// unknown so "no such user" costs the same as "wrong password" (timing).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomUUID(), 12);

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+passwordHash +twoFactorSecret');
    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH);
      auditLog('login_failed', { reason: 'no_such_user' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.isLocked()) {
      auditLog('login_blocked_locked', { userId: user._id.toString() });
      return res.status(423).json({ error: 'Account temporarily locked due to failed attempts' });
    }

    const valid = await user.comparePassword(password);
    if (!valid) {
      // Atomic $inc: concurrent bad guesses cannot overwrite each other's count.
      const updated = await User.findByIdAndUpdate(user._id, { $inc: { failedLoginAttempts: 1 } }, { new: true });
      if (updated && updated.failedLoginAttempts >= env.accountLock.threshold) {
        await User.updateOne({ _id: user._id }, { lockUntil: new Date(Date.now() + env.accountLock.durationMs) });
        auditLog('account_locked', { userId: user._id.toString() });
      }
      auditLog('login_failed', { userId: user._id.toString(), reason: 'bad_password' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await User.updateOne(
      { _id: user._id },
      { failedLoginAttempts: 0, lockUntil: null, lastLoginAt: new Date() }
    );

    if (req.resetRateLimit) await req.resetRateLimit().catch(() => {});

    if (user.twoFactorEnabled) {
      const { issueTwoFactorChallenge } = require('./twoFactorController');
      auditLog('login_password_ok_2fa_pending', { userId: user._id.toString() });
      return res.json(issueTwoFactorChallenge(user));
    }

    const accessToken = await issueTokenPair(user, req, res);
    auditLog('login_success', { userId: user._id.toString() });
    return res.json({ user, accessToken });
  } catch (err) {
    next(err);
  }
}

/**
 * Rotation. The security-critical step is ONE atomic conditional update in
 * MongoDB: flip revoked false->true for this jti only if it is still
 * unrevoked and unexpired. findOneAndUpdate returns the pre-image only to the
 * single caller whose update matched; every concurrent caller gets null.
 * The successor inherits the consumed token's family + sessionVersion (NOT the
 * user's current one), so a global logout racing with this refresh yields a
 * successor that is already stale.
 */
async function refresh(req, res, next) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;
    if (!token) {
      return res.status(401).json({ error: 'No refresh token provided' });
    }

    let payload;
    try {
      payload = verifyRefreshToken(token);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const consumed = await RefreshToken.findOneAndUpdate(
      { tokenId: payload.jti, revoked: false, expiresAt: { $gt: new Date() } },
      { $set: { revoked: true } }
    );
    if (!consumed) {
      auditLog('refresh_rejected', { reason: 'revoked_or_reused' });
      return res.status(401).json({ error: 'Refresh token has been revoked' });
    }

    const user = await User.findById(consumed.user);
    if (!user || !user.isActive || user.sessionVersion !== consumed.sessionVersion) {
      return res.status(401).json({ error: 'Session is no longer valid' });
    }

    const accessToken = await issueTokenPair(user, req, res, {
      family: consumed.family,
      sessionVersion: consumed.sessionVersion,
    });
    return res.json({ user, accessToken });
  } catch (err) {
    next(err);
  }
}

/** Revokes the presented token's whole family (the session) in MongoDB. */
async function logout(req, res, next) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;
    if (token) {
      try {
        const payload = verifyRefreshToken(token);
        await RefreshToken.updateMany({ family: payload.fam, user: payload.sub }, { revoked: true });
      } catch (err) {
        if (err.name !== 'JsonWebTokenError' && err.name !== 'TokenExpiredError') throw err;
        // token already invalid/expired — nothing to revoke
      }
    }
    res.clearCookie(REFRESH_COOKIE_NAME, { path: REFRESH_COOKIE_PATH });
    return res.status(204).send();
  } catch (err) {
    next(err);
  }
}

/**
 * Global logout. MongoDB is authoritative: bumping sessionVersion makes every
 * outstanding access AND refresh token (all carry the old `sv`) fail the
 * check in authenticate()/refresh(). Revoking stored refresh tokens is
 * belt-and-braces. Access tokens die immediately, not at their 15m expiry.
 */
async function logoutAll(req, res, next) {
  try {
    await User.updateOne({ _id: req.user._id }, { $inc: { sessionVersion: 1 } });
    await RefreshToken.updateMany({ user: req.user._id, revoked: false }, { revoked: true });
    res.clearCookie(REFRESH_COOKIE_NAME, { path: REFRESH_COOKIE_PATH });
    auditLog('logout_all', { userId: req.user._id.toString() });
    return res.status(204).send();
  } catch (err) {
    next(err);
  }
}

async function me(req, res) {
  return res.json({ user: req.user });
}

module.exports = { register, login, refresh, logout, logoutAll, me };
module.exports._internal = { issueTokenPair };
