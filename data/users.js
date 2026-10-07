const bcrypt = require("bcryptjs");

// In-memory "database" of users.
// Passwords are NEVER stored in plain text — always bcrypt-hashed.
let users = [];
let nextId = 1;

// Failed-login tracking for account lockout (per email)
// Map<email, { attempts: number, lockedUntil: timestamp|null }>
const loginAttempts = new Map();

function addUser({ email, password, role, provider = "local", googleId = null }) {
  const hashedPassword = password ? bcrypt.hashSync(password, 10) : null;
  const user = {
    id: nextId++,
    email,
    password: hashedPassword, // null for pure OAuth users
    role,
    provider, // 'local' or 'google'
    googleId,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  return user;
}

function findByEmail(email) {
  return users.find((u) => u.email.toLowerCase() === email.toLowerCase());
}

function findById(id) {
  return users.find((u) => u.id === Number(id));
}

function findByGoogleId(googleId) {
  return users.find((u) => u.googleId === googleId);
}

function removeById(id) {
  const index = users.findIndex((u) => u.id === Number(id));
  if (index === -1) return null;
  const removed = users[index];
  users.splice(index, 1);
  return removed;
}

function getAll() {
  return users;
}

// ---- Account lockout helpers (5 failed attempts -> 15 min lock) ----
const MAX_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes

function isLocked(email) {
  const record = loginAttempts.get(email.toLowerCase());
  if (!record || !record.lockedUntil) return false;
  if (Date.now() > record.lockedUntil) {
    // Lock expired -> reset
    loginAttempts.delete(email.toLowerCase());
    return false;
  }
  return true;
}

function recordFailedAttempt(email) {
  const key = email.toLowerCase();
  const record = loginAttempts.get(key) || { attempts: 0, lockedUntil: null };
  record.attempts += 1;
  if (record.attempts >= MAX_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCK_DURATION_MS;
  }
  loginAttempts.set(key, record);
  return record;
}

function clearFailedAttempts(email) {
  loginAttempts.delete(email.toLowerCase());
}

function getLockInfo(email) {
  const record = loginAttempts.get(email.toLowerCase());
  if (!record || !record.lockedUntil) return null;
  const remainingMs = record.lockedUntil - Date.now();
  return { remainingSeconds: Math.max(0, Math.ceil(remainingMs / 1000)) };
}

// ---- Seed three required roles for viva/demo ----
// NOTE: These are demo credentials for the assignment viva ONLY.
// In real production, never hardcode seed passwords like this.
addUser({ email: "superadmin@gateway.com", password: "SuperAdmin@123", role: "SuperAdmin" });
addUser({ email: "manager@gateway.com", password: "Manager@123", role: "Manager" });
addUser({ email: "employee@gateway.com", password: "Employee@123", role: "Employee" });

module.exports = {
  addUser,
  findByEmail,
  findById,
  findByGoogleId,
  removeById,
  getAll,
  isLocked,
  recordFailedAttempt,
  clearFailedAttempts,
  getLockInfo,
  MAX_ATTEMPTS,
};
