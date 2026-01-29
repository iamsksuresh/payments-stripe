// server.js — minimal Express server to create Stripe PaymentIntents (test mode)
// Usage:
// 1. npm install express stripe dotenv cors
// 2. create a .env with STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY
// 3. node server.js
//
// Note: This example intentionally keeps things simple for testing. Do not
// use this exact server for production without proper validation and security.

require('dotenv').config();
const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Load secret key from environment (must be your test secret key)
const stripeSecret = process.env.STRIPE_SECRET_KEY;
const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;

if (!stripeSecret) {
  console.error('Missing STRIPE_SECRET_KEY in environment. Exiting.');
  process.exit(1);
}
const stripe = Stripe(stripeSecret);

// Serve static client (index.html) from the same folder
app.use(express.static(path.join(__dirname)));

// Simple endpoint to return publishable key
app.get('/config', (req, res) => {
  res.json({ publishableKey: publishableKey || '' });
});

// Create a PaymentIntent for an amount (in cents)
app.post('/create-payment-intent', async (req, res) => {
  try {
    const { amount, currency } = req.body;
    if (!amount || typeof amount !== 'number') {
      return res.status(400).json({ error: 'Invalid or missing amount (in cents).' });
    }
    // Create PaymentIntent with automatic payment methods allowed (for demo)
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: currency || 'usd',
      // optionally automatically attach payment methods
      automatic_payment_methods: { enabled: true },
      description: 'Test payment from demo',
      metadata: { integration_check: 'accept_a_payment_demo' }
    });
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error('Error creating payment intent:', err);
    res.status(500).json({ error: err.message });
  }
});

// Listen
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT} — serving index.html`);
});