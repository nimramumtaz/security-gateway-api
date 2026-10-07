const express = require("express");
const router = express.Router();
const { authenticateToken } = require("../middleware/auth");

// GET /api/v1/employee/profile -- any authenticated role can access
router.get("/profile", authenticateToken, (req, res) => {
  res.status(200).json({
    message: "Profile fetched successfully",
    user: req.user, // { id, role, email } from the access token
  });
});

module.exports = router;
