const express = require("express");
const router = express.Router();
const { authenticateToken } = require("../middleware/auth");
const { checkRole } = require("../middleware/checkRole");

// POST /api/v1/payroll/approve -- Manager and SuperAdmin only
router.post("/approve", authenticateToken, checkRole(["Manager", "SuperAdmin"]), (req, res) => {
  res.status(200).json({
    message: `Payroll approved by ${req.user.role} (${req.user.email})`,
    approvedAt: new Date().toISOString(),
  });
});

module.exports = router;
