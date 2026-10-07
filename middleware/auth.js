const jwt = require("jsonwebtoken");
const { ApiError } = require("./errorHandler");

// Reads "Authorization: Bearer <token>" and verifies the short-lived access token.
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // "Bearer <token>"

  if (!token) {
    return next(new ApiError(401, "NO_TOKEN", "Access token is required"));
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return next(new ApiError(401, "TOKEN_EXPIRED", "Access token has expired, please refresh"));
      }
      return next(new ApiError(403, "INVALID_TOKEN", "Access token is invalid"));
    }
    req.user = decoded; // { id, role, email }
    next();
  });
}

module.exports = { authenticateToken };
