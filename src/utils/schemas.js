const Joi = require('joi');

// bcrypt only uses the first 72 BYTES of its input. Rather than silently
// truncating (two different long passwords would be equivalent), we reject
// anything longer. Applied to login as well so a >72-byte guess can never
// match by truncation.
const MAX_PASSWORD_BYTES = 72;
const passwordBytes = (value, helpers) =>
  Buffer.byteLength(value, 'utf8') > MAX_PASSWORD_BYTES ? helpers.error('password.tooLong') : value;

const email = Joi.string().trim().lowercase().email().max(254);

const loginPassword = Joi.string().custom(passwordBytes).required().messages({
  'password.tooLong': `Password must be at most ${MAX_PASSWORD_BYTES} bytes`,
});

// Note: no `role` key. Joi rejects unknown keys (validate() does not strip
// them), so a body containing role/isAdmin/sessionVersion/... is a 400.
const registerSchema = Joi.object({
  email: email.required(),
  password: Joi.string()
    .min(8)
    .custom(passwordBytes)
    .pattern(/[A-Z]/, 'uppercase letter')
    .pattern(/[a-z]/, 'lowercase letter')
    .pattern(/[0-9]/, 'number')
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters',
      'string.pattern.name': 'Password must contain at least one {#name}',
      'password.tooLong': `Password must be at most ${MAX_PASSWORD_BYTES} bytes`,
    }),
});

const loginSchema = Joi.object({
  email: email.required(),
  password: loginPassword,
});

const refreshSchema = Joi.object({
  refreshToken: Joi.string().optional(), // may also arrive via httpOnly cookie
});

const totpCode = Joi.string().length(6).pattern(/^\d+$/).required();

const twoFactorCodeSchema = Joi.object({ code: totpCode });

const twoFactorDisableSchema = Joi.object({ code: totpCode, password: loginPassword });

const twoFactorLoginVerifySchema = Joi.object({
  twoFactorToken: Joi.string().required(),
  code: totpCode,
});

const roleChangeSchema = Joi.object({
  role: Joi.string().valid('guest', 'user', 'admin').required(),
});

module.exports = {
  MAX_PASSWORD_BYTES,
  registerSchema,
  loginSchema,
  refreshSchema,
  twoFactorCodeSchema,
  twoFactorDisableSchema,
  twoFactorLoginVerifySchema,
  roleChangeSchema,
};
