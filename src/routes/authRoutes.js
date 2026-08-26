const express = require('express');
const authController = require('../controllers/authController');
const twoFactorController = require('../controllers/twoFactorController');
const authenticate = require('../middleware/authenticate');
const validate = require('../middleware/validate');
const loginRateLimiter = require('../middleware/loginRateLimiter');
const {
  registerSchema,
  loginSchema,
  refreshSchema,
  twoFactorCodeSchema,
  twoFactorLoginVerifySchema,
} = require('../utils/schemas');

const router = express.Router();

router.post('/register', validate(registerSchema), authController.register);
router.post('/login', loginRateLimiter(), validate(loginSchema), authController.login);
router.post('/refresh', validate(refreshSchema), authController.refresh);
router.post('/logout', authController.logout);
router.post('/logout-all', authenticate, authController.logoutAll);
router.get('/me', authenticate, authController.me);

// Two-factor authentication (TOTP)
router.post('/2fa/setup', authenticate, twoFactorController.setupTwoFactor);
router.post(
  '/2fa/verify',
  authenticate,
  validate(twoFactorCodeSchema),
  twoFactorController.verifyTwoFactorSetup
);
router.post(
  '/2fa/disable',
  authenticate,
  validate(twoFactorCodeSchema),
  twoFactorController.disableTwoFactor
);
router.post(
  '/2fa/login-verify',
  validate(twoFactorLoginVerifySchema),
  twoFactorController.verifyTwoFactorLogin
);

module.exports = router;
