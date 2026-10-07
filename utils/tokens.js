const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Server-side store of valid refresh token IDs (jti).
// Map<jti, { userId, valid: boolean }>
// This is what allows us to ROTATE (invalidate old, issue new) and
// REVOKE (on logout) refresh tokens -- a plain stateless JWT can't do this.
const refreshTokenStore = new Map();

function generateAccessToken(user) {
  return jwt.sign({ id: user.id, role: user.role, email: user.email }, ACCESS_SECRET, {
    expiresIn: "15m",
  });
}

function generateRefreshToken(user) {
  const jti = uuidv4();
  const token = jwt.sign({ id: user.id, jti }, REFRESH_SECRET, { expiresIn: "7d" });
  refreshTokenStore.set(jti, { userId: user.id, valid: true });
  return token;
}

function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET); // throws if invalid/expired
}

function isRefreshTokenValid(jti) {
  const record = refreshTokenStore.get(jti);
  return !!record && record.valid;
}

// Rotation: old token is invalidated the moment it's used to get a new one.
// If someone tries to reuse an old (already-rotated) refresh token, it will
// fail here -- this detects token theft/replay.
function invalidateRefreshToken(jti) {
  refreshTokenStore.delete(jti);
}

function revokeAllForUser(userId) {
  for (const [jti, record] of refreshTokenStore.entries()) {
    if (record.userId === userId) refreshTokenStore.delete(jti);
  }
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  isRefreshTokenValid,
  invalidateRefreshToken,
  revokeAllForUser,
};
