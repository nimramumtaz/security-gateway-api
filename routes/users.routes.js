const express = require("express");
const router = express.Router();
const { authenticateToken } = require("../middleware/auth");
const { checkRole } = require("../middleware/checkRole");
const usersDb = require("../data/users");
const { ApiError } = require("../middleware/errorHandler");

// GET /api/v1/users -- SuperAdmin only (handy for viva demo / listing)
router.get("/", authenticateToken, checkRole(["SuperAdmin"]), (req, res) => {
  const safeUsers = usersDb.getAll().map((u) => ({
    id: u.id,
    email: u.email,
    role: u.role,
    provider: u.provider,
  }));
  res.status(200).json({ total: safeUsers.length, data: safeUsers });
});

// DELETE /api/v1/users/:id -- SuperAdmin only
router.delete("/:id", authenticateToken, checkRole(["SuperAdmin"]), (req, res, next) => {
  try {
    const removed = usersDb.removeById(req.params.id);
    if (!removed) {
      throw new ApiError(404, "USER_NOT_FOUND", `User with id ${req.params.id} was not found`);
    }
    res.status(200).json({
      message: "User deleted successfully",
      user: { id: removed.id, email: removed.email, role: removed.role },
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
