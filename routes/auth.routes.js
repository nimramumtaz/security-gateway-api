const express = require("express");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const router = express.Router();

const usersDb = require("../data/users");
const { ApiError } = require("../middleware/errorHandler");
const { loginRateLimiter } = require("../middleware/rateLimiter");
const tokens = require("../utils/tokens");

const isProd = process.env.NODE_ENV === "production";

// Cookie options for the refresh token -- httpOnly + Secure + SameSite=Strict
// This is the core defense against XSS stealing the refresh token: JS on the
// page can NEVER read this cookie (httpOnly), and it's only sent over HTTPS
// in production (secure), and never sent cross-site (SameSite=Strict).
const refreshCookieOptions = {
  httpOnly: true,
  secure: isProd, // must be true in production (HTTPS only)
  sameSite: "strict",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: "/api/v1/auth",
};

function issueTokens(res, user) {
  const accessToken = tokens.generateAccessToken(user);
  const refreshToken = tokens.generateRefreshToken(user);
  res.cookie("refreshToken", refreshToken, refreshCookieOptions);
  return accessToken;
}

// ------------------------------------------------------------------
// POST /api/v1/auth/register
// ------------------------------------------------------------------
router.post("/register", (req, res, next) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password) {
      throw new ApiError(400, "VALIDATION_ERROR", "Email and password are required");
    }
    if (password.length < 8) {
      throw new ApiError(400, "WEAK_PASSWORD", "Password must be at least 8 characters");
    }
    if (usersDb.findByEmail(email)) {
      throw new ApiError(409, "EMAIL_EXISTS", "An account with this email already exists");
    }

    // Only allow self-registration as Employee -- SuperAdmin/Manager
    // should be provisioned internally, never via public signup.
    const assignedRole = ["Employee"].includes(role) ? role : "Employee";

    const user = usersDb.addUser({ email, password, role: assignedRole, provider: "local" });

    const accessToken = issueTokens(res, user);
    res.status(201).json({
      message: "Registration successful",
      accessToken,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

// ------------------------------------------------------------------
// POST /api/v1/auth/login  (rate-limited + account lockout)
// ------------------------------------------------------------------
router.post("/login", loginRateLimiter, (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      throw new ApiError(400, "VALIDATION_ERROR", "Email and password are required");
    }

    // Account-level lockout check (separate from IP rate-limit above)
    if (usersDb.isLocked(email)) {
      const lockInfo = usersDb.getLockInfo(email);
      throw new ApiError(
        423,
        "ACCOUNT_LOCKED",
        `Account locked due to too many failed attempts. Try again in ${lockInfo.remainingSeconds}s`
      );
    }

    const user = usersDb.findByEmail(email);
    if (!user || !user.password) {
      // Either user doesn't exist, or it's an OAuth-only account with no password
      if (user) usersDb.recordFailedAttempt(email);
      throw new ApiError(401, "INVALID_CREDENTIALS", "Invalid email or password");
    }

    const match = bcrypt.compareSync(password, user.password);
    if (!match) {
      const record = usersDb.recordFailedAttempt(email);
      throw new ApiError(
        401,
        "INVALID_CREDENTIALS",
        `Invalid email or password (attempt ${record.attempts}/${usersDb.MAX_ATTEMPTS})`
      );
    }

    usersDb.clearFailedAttempts(email);
    const accessToken = issueTokens(res, user);

    res.status(200).json({
      message: "Login successful",
      accessToken,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

// ------------------------------------------------------------------
// POST /api/v1/auth/refresh  -- Refresh Token Rotation
// ------------------------------------------------------------------
router.post("/refresh", (req, res, next) => {
  try {
    const incomingToken = req.cookies.refreshToken;
    if (!incomingToken) {
      throw new ApiError(401, "NO_REFRESH_TOKEN", "Refresh token cookie is missing");
    }

    let payload;
    try {
      payload = tokens.verifyRefreshToken(incomingToken);
    } catch (e) {
      throw new ApiError(403, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
    }

    // Reuse detection: if this jti was already rotated/revoked, reject it.
    if (!tokens.isRefreshTokenValid(payload.jti)) {
      throw new ApiError(403, "REFRESH_TOKEN_REUSED", "Refresh token has already been used or revoked");
    }

    const user = usersDb.findById(payload.id);
    if (!user) {
      throw new ApiError(401, "USER_NOT_FOUND", "User for this token no longer exists");
    }

    // ROTATE: invalidate the old one, issue a brand new access+refresh pair
    tokens.invalidateRefreshToken(payload.jti);
    const accessToken = issueTokens(res, user);

    res.status(200).json({ message: "Token refreshed", accessToken });
  } catch (err) {
    next(err);
  }
});

// ------------------------------------------------------------------
// POST /api/v1/auth/logout  -- revoke refresh token
// ------------------------------------------------------------------
router.post("/logout", (req, res, next) => {
  try {
    const incomingToken = req.cookies.refreshToken;
    if (incomingToken) {
      try {
        const payload = tokens.verifyRefreshToken(incomingToken);
        tokens.invalidateRefreshToken(payload.jti);
      } catch (e) {
        // token already invalid/expired -- nothing to revoke, that's fine
      }
    }
    res.clearCookie("refreshToken", { path: "/api/v1/auth" });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    next(err);
  }
});

// ------------------------------------------------------------------
// GOOGLE OAuth 2.0
// ------------------------------------------------------------------
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"], session: false })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/api/v1/auth/google/failure" }),
  (req, res) => {
    // req.user was set by the passport Google strategy (config/passport.js)
    const accessToken = issueTokens(res, req.user);
    // In a real frontend you'd redirect with the token or a short-lived code.
    // For this assignment/demo we return JSON directly.
    res.status(200).json({
      message: "Google OAuth login successful",
      accessToken,
      user: { id: req.user.id, email: req.user.email, role: req.user.role },
    });
  }
);

router.get("/google/failure", (req, res) => {
  res.status(401).json({
    error_code: "OAUTH_FAILED",
    message: "Google authentication failed",
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
