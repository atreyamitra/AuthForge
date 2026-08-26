/**
 * Role-based access control middleware.
 * Usage: router.get('/admin', authenticate, authorize('admin'), handler)
 *        router.get('/dash',  authenticate, authorize('admin', 'user'), handler)
 */
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden: insufficient role',
        required: allowedRoles,
        actual: req.user.role,
      });
    }
    next();
  };
}

module.exports = authorize;
