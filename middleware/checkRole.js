const { ApiError } = require("./errorHandler");

// Usage: checkRole(['SuperAdmin']) or checkRole(['Manager', 'SuperAdmin'])
// Must run AFTER authenticateToken (needs req.user to be set).
function checkRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return next(new ApiError(401, "NO_TOKEN", "Authentication required before role check"));
    }
    if (!allowedRoles.includes(req.user.role)) {
      return next(
        new ApiError(
          403,
          "FORBIDDEN_ROLE",
          `Role '${req.user.role}' is not authorized for this action. Required: ${allowedRoles.join(" or ")}`
        )
      );
    }
    next();
  };
}

module.exports = { checkRole };
