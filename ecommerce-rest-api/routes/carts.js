const express = require("express");
const Cart = require("../models/Cart");
const Product = require("../models/Product");
const { protect } = require("../middleware/auth");

const router = express.Router();

// Get current user's cart
router.get("/", protect, async (req, res) => {
  let cart = await Cart.findOne({ userId: req.user._id }).populate(
    "items.productId"
  );
  if (!cart) cart = new Cart({ userId: req.user._id, items: [] });
  res.json({ cart });
});

// Add/update cart item
router.post("/items", protect, async (req, res) => {
  const { productId, quantity = 1 } = req.body;
  const product = await Product.findById(productId);
  if (!product) return res.status(404).json({ error: "Product not found" });
  let cart = await Cart.findOne({ userId: req.user._id });
  if (!cart) cart = new Cart({ userId: req.user._id, items: [] });
  const idx = cart.items.findIndex((i) => i.productId.toString() === productId);
  if (idx > -1) {
    cart.items[idx].quantity = quantity;
    cart.items[idx].price = product.price;
  } else {
    cart.items.push({ productId, quantity, price: product.price });
  }
  cart.totalAmount = cart.items.reduce(
    (s, it) => s + it.quantity * it.price,
    0
  );
  await cart.save();
  res.json({ cart });
});

// Remove item
router.delete("/items/:productId", protect, async (req, res) => {
  const { productId } = req.params;
  let cart = await Cart.findOne({ userId: req.user._id });
  if (!cart) return res.status(404).json({ error: "Cart not found" });
  cart.items = cart.items.filter((i) => i.productId.toString() !== productId);
  cart.totalAmount = cart.items.reduce(
    (s, it) => s + it.quantity * it.price,
    0
  );
  await cart.save();
  res.json({ cart });
});

module.exports = router;
