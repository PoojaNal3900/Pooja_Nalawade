const express = require("express");
const Order = require("../models/Order");
const Cart = require("../models/Cart");
const Product = require("../models/Product");
const { protect, authorize } = require("../middleware/auth");

const router = express.Router();

// Create order from cart
router.post("/", protect, async (req, res) => {
  const { shippingAddress, paymentMethod } = req.body;
  const cart = await Cart.findOne({ userId: req.user._id });
  if (!cart || cart.items.length === 0)
    return res.status(400).json({ error: "Cart empty" });
  // Build order items (denormalize product name & price)
  const items = [];
  for (const it of cart.items) {
    const prod = await Product.findById(it.productId);
    if (!prod)
      return res.status(400).json({ error: "Product not found in cart" });
    items.push({
      productId: prod._id,
      name: prod.name,
      quantity: it.quantity,
      price: prod.price,
      total: it.quantity * prod.price,
    });
  }
  const totalAmount = items.reduce((s, it) => s + it.total, 0);
  const order = new Order({
    userId: req.user._id,
    items,
    shippingAddress,
    payment: { method: paymentMethod || "Mock", status: "Pending" },
    totalAmount,
    orderStatus: "Pending",
  });
  await order.save();
  // Optionally, reduce stock
  for (const it of items) {
    await Product.findByIdAndUpdate(it.productId, {
      $inc: { stock: -it.quantity },
    });
  }
  // Clear cart
  cart.items = [];
  cart.totalAmount = 0;
  await cart.save();
  res.status(201).json({ order });
});

// Get orders for current user
router.get("/", protect, async (req, res) => {
  const orders = await Order.find({ userId: req.user._id });
  res.json({ orders });
});

// Admin: get all orders
router.get("/all", protect, authorize("admin"), async (req, res) => {
  const orders = await Order.find().populate("userId", "name email");
  res.json({ orders });
});

// Update order status (admin)
router.put("/:id/status", protect, authorize("admin"), async (req, res) => {
  const { status } = req.body;
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found" });
  order.orderStatus = status;
  await order.save();
  res.json({ order });
});

module.exports = router;
