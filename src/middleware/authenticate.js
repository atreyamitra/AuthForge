const { verifyAccessToken } = require('../utils/tokens');
const { getRedisClient } = require('../config/redis');
const User = require('../models/User');

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');

    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    let payload;
    try {
      payload = verifyAccessToken(token);
    } catch (err) {
      const reason = err.name === 'TokenExpiredError' ? 'Access token expired' : 'Invalid access token';
      return res.status(401).json({ error: reason });
    }

    if (payload.type !== 'access') {
      return res.status(401).json({ error: 'Wrong token type' });
    }

    // Global logout / force-logout check: if the user's tokens were
    // invalidated (e.g. password change, admin action), a marker is set
    // in Redis with a timestamp; any access token issued before that is rejected.
    const redis = getRedisClient();
    const invalidatedAt = await redis.get(`user-tokens-invalidated:${payload.sub}`);
    if (invalidatedAt && payload.iat * 1000 < Number(invalidatedAt)) {
      return res.status(401).json({ error: 'Token has been invalidated, please log in again' });
    }

    const user = await User.findById(payload.sub);
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    req.user = user;
    req.tokenPayload = payload;
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = authenticate;
