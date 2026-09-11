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

function refreshCookieOptions() {
  return {
    httpOnly: true,
    secure: env.nodeEnv === 'production',
    sameSite: 'strict',
    maxAge: expiresInToSeconds(env.jwt.refreshExpiresIn) * 1000,
    path: '/api/auth',
  };
}

async function issueTokenPair(user, req, res) {
  const accessToken = signAccessToken(user);
  const { token: refreshToken, jti } = signRefreshToken(user);

  await RefreshToken.create({
    user: user._id,
    tokenId: jti,
    tokenVersion: user.tokenVersion,
    userAgent: req.headers['user-agent'] || '',
    ip: req.ip,
    expiresAt: new Date(Date.now() + expiresInToSeconds(env.jwt.refreshExpiresIn) * 1000),
  });

  res.cookie(REFRESH_COOKIE_NAME, refreshToken, refreshCookieOptions());
  // Remove the legacy narrower cookie so it cannot shadow the new cookie.
  res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth/refresh' });
  return accessToken;
}

async function register(req, res, next) {
  try {
    const { email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await User.hashPassword(password);
    const user = await User.create({ email, passwordHash, role: 'user' });

    const accessToken = await issueTokenPair(user, req, res);
    auditLog('user_registered', { userId: user._id.toString(), role: user.role });
    return res.status(201).json({ user, accessToken });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+passwordHash +twoFactorSecret');
    if (!user || !user.isActive) {
      auditLog('login_failed', { email, reason: 'no_such_user' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (user.isLocked()) {
      auditLog('login_blocked_locked', { userId: user._id.toString() });
      return res.status(423).json({ error: 'Account temporarily locked due to failed attempts' });
    }

    const valid = await user.comparePassword(password);
    if (!valid) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 10) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 min lock
        auditLog('account_locked', { userId: user._id.toString() });
      }
      await user.save();
      auditLog('login_failed', { userId: user._id.toString(), reason: 'bad_password' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    user.lastLoginAt = new Date();
    await user.save();

    if (req.clearLoginAttempts) await req.clearLoginAttempts();

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

    const user = await User.findById(payload.sub);
    if (!user || !user.isActive || payload.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({ error: 'Session invalidated or user inactive' });
    }

    // Compare-and-set: only one caller can consume an unexpired token.
    // A read followed by save permits two concurrent refreshes to succeed.
    const stored = await RefreshToken.findOneAndUpdate(
      { tokenId: payload.jti, user: user._id, revoked: false,
        tokenVersion: payload.tokenVersion, expiresAt: { $gt: new Date() } },
      { $set: { revoked: true } },
      { new: true }
    );
    if (!stored) {
      return res.status(401).json({ error: 'Refresh token has been revoked or expired' });
    }
    // Keep this user snapshot: if logout-all races issuance, the replacement
    // retains the old version and is rejected by authentication and refresh.

    const accessToken = await issueTokenPair(user, req, res);
    return res.json({ user, accessToken });
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;
    if (token) {
      let payload;
      try {
        payload = verifyRefreshToken(token);
      } catch {
        // An invalid or expired token needs no server-side revocation.
      }
      if (payload) {
        // Storage failures must reach the error handler; do not report logout
        // success while the refresh token is still usable.
        await RefreshToken.updateOne({ tokenId: payload.jti }, { revoked: true });
      }
    }
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth/refresh' });
    return res.status(204).send();
  } catch (err) {
    next(err);
  }
}

/** Revokes all refresh tokens + invalidates outstanding access tokens for the current user. */
async function logoutAll(req, res, next) {
  try {
    // A database generation avoids JWT's one-second timestamp ambiguity and
    // invalidates tokens issued by in-flight refreshes with an older snapshot.
    const user = await User.findByIdAndUpdate(
      req.user._id, { $inc: { tokenVersion: 1 } }, { new: true }
    );
    await RefreshToken.updateMany(
      { user: req.user._id, revoked: false, tokenVersion: { $lt: user.tokenVersion } },
      { $set: { revoked: true } }
    );
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth/refresh' });
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
