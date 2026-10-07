const xss = require("xss");

// Recursively sanitize every string field in an object (body, query, params)
// to strip out <script> tags and other XSS payloads. Also guards against
// basic NoSQL injection by rejecting keys starting with "$" or containing ".".
function sanitizeValue(value) {
  if (typeof value === "string") {
    return xss(value.trim());
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value && typeof value === "object") {
    const clean = {};
    for (const key of Object.keys(value)) {
      // Block NoSQL injection operators like { "$gt": "" }
      if (key.startsWith("$") || key.includes(".")) continue;
      clean[key] = sanitizeValue(value[key]);
    }
    return clean;
  }
  return value;
}

function sanitizeRequest(req, res, next) {
  if (req.body) req.body = sanitizeValue(req.body);
  if (req.query) req.query = sanitizeValue(req.query);
  if (req.params) req.params = sanitizeValue(req.params);
  next();
}

module.exports = { sanitizeRequest };
