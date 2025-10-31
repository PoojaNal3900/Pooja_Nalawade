const express = require("express");
const Review = require("../models/Review");
const Product = require("../models/Product");
const { protect } = require("../middleware/auth");

const router = express.Router();

// Add review
router.post("/:productId", protect, async (req, res) => {
  const { rating, comment } = req.body;
  const { productId } = req.params;
  const prod = await Product.findById(productId);
  if (!prod) return res.status(404).json({ error: "Product not found" });
  const review = new Review({
    userId: req.user._id,
    productId,
    rating,
    comment,
  });
  await review.save();
  // update product rating
  const reviews = await Review.find({ productId });
  const avg = reviews.reduce((s, r) => s + r.rating, 0) / reviews.length;
  prod.rating = avg;
  prod.numReviews = reviews.length;
  await prod.save();
  res.status(201).json({ review });
});

// Get reviews for product
router.get("/:productId", async (req, res) => {
  const { productId } = req.params;
  const reviews = await Review.find({ productId }).populate("userId", "name");
  res.json({ reviews });
});

module.exports = router;
