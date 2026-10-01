const { logger } = require('../utils/audit');

function notFound(req, res) {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed JSON body' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large' });
  }
  logger.error({ err: { name: err.name, message: err.message, stack: err.stack } }, 'unhandled error');

  if (err.code === 11000) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: 'Validation failed' });
  }
  if (err.name === 'CastError') {
    return res.status(400).json({ error: 'Invalid identifier' });
  }

  // Never echo internal error messages to clients.
  res.status(500).json({ error: 'Internal server error' });
}

module.exports = { notFound, errorHandler };
