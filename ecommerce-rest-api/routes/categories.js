const express = require("express");
const Category = require("../models/Category");
const { protect, authorize } = require("../middleware/auth");
const { body, validationResult } = require("express-validator");

const router = express.Router();

// Create category (admin)
router.post(
  "/",
  protect,
  authorize("admin"),
  [body("name").notEmpty(), body("slug").notEmpty()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    const { name, slug, parentId, image } = req.body;
    const existing = await Category.findOne({ slug });
    if (existing) return res.status(400).json({ error: "Slug exists" });
    const cat = new Category({ name, slug, parentId: parentId || null, image });
    await cat.save();
    res.status(201).json({ category: cat });
  }
);

// List categories
router.get("/", async (req, res) => {
  const cats = await Category.find();
  res.json({ categories: cats });
});

module.exports = router;
