const pino = require('pino');
const env = require('../config/env');

const logger = pino({
  level: env.nodeEnv === 'test' ? 'silent' : 'info',
  base: undefined, // omit pid/hostname noise
  timestamp: pino.stdTimeFunctions.isoTime,
});

/**
 * Emits a structured, greppable audit record for every security-relevant
 * event: logins (success/fail), lockouts, role changes, 2FA changes,
 * token revocation. In production this stream is meant to be shipped to a
 * log aggregator (Datadog/ELK/CloudWatch) rather than read off stdout.
 */
function auditLog(event, details = {}) {
  logger.info({ audit: true, event, ...details });
}

module.exports = { logger, auditLog };
