const express = require("express");
const User = require("../models/User");
const { protect, authorize } = require("../middleware/auth");

const router = express.Router();

// Get all users (admin)
router.get("/", protect, authorize("admin"), async (req, res) => {
  const users = await User.find().select("-passwordHash");
  res.json({ users });
});

// Get user by id (admin or self)
router.get("/:id", protect, async (req, res) => {
  const { id } = req.params;
  if (req.user.role !== "admin" && req.user._id.toString() !== id) {
    return res.status(403).json({ error: "Forbidden" });
  }
  const user = await User.findById(id).select("-passwordHash");
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user });
});

module.exports = router;
