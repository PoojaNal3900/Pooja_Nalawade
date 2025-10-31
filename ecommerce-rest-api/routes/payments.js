const express = require("express");
const { protect } = require("../middleware/auth");

const router = express.Router();

// Mock payment endpoint - in real life integrate Stripe/Razorpay SDKs
router.post("/create", protect, async (req, res) => {
  const { orderId, amount } = req.body;
  // Simulate a successful payment
  const transactionId = "TXN_" + Date.now();
  res.json({ success: true, transactionId, status: "Paid" });
});

module.exports = router;
