const { verifyAccessToken } = require('../utils/tokens');
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

    const user = await User.findById(payload.sub);
    if (!user || !user.isActive || !Number.isSafeInteger(payload.tokenVersion) ||
        payload.tokenVersion !== user.tokenVersion) {
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
