const Joi = require('joi');

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .pattern(/[A-Z]/, 'uppercase letter')
    .pattern(/[a-z]/, 'lowercase letter')
    .pattern(/[0-9]/, 'number')
    .required()
    .messages({
      'string.min': 'Password must be at least 8 characters',
      'string.pattern.name': 'Password must contain at least one {#name}',
    }),
  role: Joi.string().valid('user').default('user'),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const refreshSchema = Joi.object({
  refreshToken: Joi.string().optional(), // may also arrive via httpOnly cookie
});

const twoFactorCodeSchema = Joi.object({
  code: Joi.string().length(6).pattern(/^\d+$/).required(),
});

const twoFactorLoginVerifySchema = Joi.object({
  twoFactorToken: Joi.string().required(),
  code: Joi.string().length(6).pattern(/^\d+$/).required(),
});

module.exports = {
  registerSchema,
  loginSchema,
  refreshSchema,
  twoFactorCodeSchema,
  twoFactorLoginVerifySchema,
};
