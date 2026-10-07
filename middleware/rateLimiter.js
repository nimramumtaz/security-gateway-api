const rateLimit = require("express-rate-limit");

// IP-based rate limiting on login: max 5 attempts per 15 minutes.
// This works ALONGSIDE the per-account lockout in data/users.js --
// together they satisfy "Account Lockout OR Rate Limiting" with extra robustness
// (rate limit blocks by IP, lockout blocks by account -- covers both attack styles).
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error_code: "TOO_MANY_ATTEMPTS",
    message: "Too many login attempts from this IP. Please try again after 15 minutes.",
    timestamp: new Date().toISOString(),
  },
});

module.exports = { loginRateLimiter };
