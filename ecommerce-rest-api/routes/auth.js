const express = require("express");
const { body, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

// Helper function to create user response
const createUserResponse = (user) => ({
  _id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  phone: user.phone || "",
  addresses: user.addresses || [],
  createdAt: user.createdAt,
  updatedAt: user.updatedAt
});

// Helper function to create auth response
const createAuthResponse = (user, token) => {
  const jwtPayload = jwt.decode(token);
  const expiresAt = new Date(jwtPayload.exp * 1000);
  
  return {
    token,
    user: createUserResponse(user),
    expiresAt
  };
};

// Register
router.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Please provide a valid email"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
    body("role").optional().isIn(["customer", "admin"]).withMessage("Role must be customer or admin"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: "Validation failed", 
        errors: errors.array() 
      });
    }
    
    try {
      const { name, email, password, phone, role } = req.body;
      const existing = await User.findOne({ email: email.toLowerCase().trim() });
      if (existing) {
        return res.status(400).json({ message: "Email already registered" });
      }

      const user = new User({ 
        name, 
        email: email.toLowerCase().trim(), 
        passwordHash: password,
        phone: phone || "",
        role: role || "customer"
      });
      await user.save();

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || "7d",
      });

      res.status(201).json(createAuthResponse(user, token));
    } catch (err) {
      console.error("Registration error:", err);
      res.status(500).json({ message: "Server error during registration" });
    }
  }
);

// Login
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Please provide a valid email"),
    body("password").notEmpty().withMessage("Password is required")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: "Validation failed", 
        errors: errors.array() 
      });
    }
    
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email: email.toLowerCase().trim() });
      
      if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
      }
      
      const match = await user.matchPassword(password);
      if (!match) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || "7d",
      });

      res.json(createAuthResponse(user, token));
    } catch (err) {
      console.error("Login error:", err);
      res.status(500).json({ message: "Server error during login" });
    }
  }
);

// Get profile
const { protect } = require("../middleware/auth");
router.get("/profile", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(createUserResponse(user));
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update profile
router.put("/profile", protect, [
  body("name").optional().notEmpty().withMessage("Name cannot be empty"),
  body("phone").optional().isLength({ min: 10 }).withMessage("Please provide a valid phone number"),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      message: "Validation failed", 
      errors: errors.array() 
    });
  }

  try {
    const updates = {};
    const { name, phone, addresses } = req.body;
    
    if (name !== undefined) updates.name = name;
    if (phone !== undefined) updates.phone = phone;
    if (addresses !== undefined) updates.addresses = addresses;

    const user = await User.findByIdAndUpdate(
      req.user.id, 
      updates, 
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(createUserResponse(user));
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ message: "Server error during profile update" });
  }
});

// Forgot password
router.post("/forgot-password", [
  body("email").isEmail().withMessage("Please provide a valid email")
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      message: "Validation failed", 
      errors: errors.array() 
    });
  }

  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    
    if (!user) {
      // Don't reveal whether user exists or not
      return res.json({ message: "If an account with that email exists, you will receive a password reset email." });
    }

    // TODO: Implement actual password reset email logic here
    // For now, just return success message
    res.json({ message: "If an account with that email exists, you will receive a password reset email." });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Reset password
router.post("/reset-password", [
  body("token").notEmpty().withMessage("Reset token is required"),
  body("newPassword").isLength({ min: 6 }).withMessage("Password must be at least 6 characters")
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      message: "Validation failed", 
      errors: errors.array() 
    });
  }

  try {
    // TODO: Implement actual password reset logic here
    res.json({ message: "Password reset functionality not yet implemented" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
