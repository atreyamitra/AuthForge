const express = require('express');
const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');
const User = require('../models/User');
const { auditLog } = require('../utils/audit');

const router = express.Router();

// Any authenticated user
router.get('/dashboard', authenticate, (req, res) => {
  res.json({ message: `Welcome, ${req.user.email}`, role: req.user.role });
});

// Admin-only: list all users
router.get('/admin/users', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const users = await User.find().limit(100);
    res.json({ users });
  } catch (err) {
    next(err);
  }
});

// Admin-only: change a user's role
router.patch('/admin/users/:id/role', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const { role } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    auditLog('role_changed', {
      targetUserId: req.params.id,
      newRole: role,
      changedBy: req.user._id.toString(),
    });
    res.json({ user });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
