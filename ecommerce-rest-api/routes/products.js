const express = require("express");
const router = express.Router();
const Product = require("../models/Product");
const Category = require("../models/Category");
const { protect, authorize } = require("../middleware/auth");

// --------------------------------------------------
// GET /api/products → List products with filters & pagination
// --------------------------------------------------
router.get("/", async (req, res) => {
  try {
    const { category, minPrice, maxPrice, keyword, page = 1, limit = 10 } = req.query;
    const filter = {};

    // Category filter (accepts ObjectId or category name)
    if (category) {
      if (/^[0-9a-fA-F]{24}$/.test(category)) {
        filter.categoryId = category;
      } else {
        const categoryDoc = await Category.findOne({
          name: { $regex: category, $options: "i" },
        });
        if (categoryDoc) {
          filter.categoryId = categoryDoc._id;
        } else {
          return res.status(404).json({ success: false, message: "Category not found" });
        }
      }
    }

    // Price filters
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = Number(minPrice);
      if (maxPrice) filter.price.$lte = Number(maxPrice);
    }

    // Keyword filter (search in name or description)
    if (keyword) {
      filter.$or = [
        { name: { $regex: keyword, $options: "i" } },
        { description: { $regex: keyword, $options: "i" } },
      ];
    }

    // Pagination
    const skip = (Number(page) - 1) * Number(limit);
    const [products, total] = await Promise.all([
      Product.find(filter).skip(skip).limit(Number(limit)).populate("categoryId", "name"),
      Product.countDocuments(filter),
    ]);

    res.json({
      success: true,
      total,
      page: Number(page),
      pages: Math.ceil(total / Number(limit)),
      count: products.length,
      data: products,
    });
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// GET /api/products/:id → Get single product by ID
// --------------------------------------------------
router.get("/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate("categoryId", "name");
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }
    res.json({ success: true, data: product });
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// POST /api/products → Create new product (Admin only)
// --------------------------------------------------
router.post("/", protect, authorize("admin"), async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json({ success: true, data: product });
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(400).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// PUT /api/products/:id → Update existing product (Admin only)
// --------------------------------------------------
router.put("/:id", protect, authorize("admin"), async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }
    res.json({ success: true, data: product });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(400).json({ success: false, error: error.message });
  }
});

// --------------------------------------------------
// DELETE /api/products/:id → Delete product (Admin only)
// --------------------------------------------------
router.delete("/:id", protect, authorize("admin"), async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }
    res.json({ success: true, message: "Product deleted successfully" });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
