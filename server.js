require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const passport = require("./config/passport");

const { sanitizeRequest } = require("./middleware/sanitize");
const { notFoundHandler, errorHandler } = require("./middleware/errorHandler");

const authRoutes = require("./routes/auth.routes");
const employeeRoutes = require("./routes/employee.routes");
const payrollRoutes = require("./routes/payroll.routes");
const usersRoutes = require("./routes/users.routes");

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------------------------------------------------------
// OWASP Security Hardening
// ------------------------------------------------------------------
app.use(helmet()); // sets secure HTTP headers (CSP, X-Frame-Options, etc.)

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN || "http://localhost:3000",
    credentials: true, // required so the refresh-token cookie can be sent
  })
);

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());
app.use(sanitizeRequest); // strip XSS / NoSQL-injection payloads from every request

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------
app.get("/", (req, res) => {
  res.status(200).json({
    message: "Enterprise Multi-Tenant Security Gateway is running",
    endpoints: {
      register: "POST /api/v1/auth/register",
      login: "POST /api/v1/auth/login",
      refresh: "POST /api/v1/auth/refresh",
      logout: "POST /api/v1/auth/logout",
      googleLogin: "GET /api/v1/auth/google",
      profile: "GET /api/v1/employee/profile",
      payrollApprove: "POST /api/v1/payroll/approve",
      deleteUser: "DELETE /api/v1/users/:id",
    },
  });
});

app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/employee", employeeRoutes);
app.use("/api/v1/payroll", payrollRoutes);
app.use("/api/v1/users", usersRoutes);

// 404 + centralized error handler -- must be registered LAST
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`🔐 Security Gateway running at http://localhost:${PORT}`);
});
