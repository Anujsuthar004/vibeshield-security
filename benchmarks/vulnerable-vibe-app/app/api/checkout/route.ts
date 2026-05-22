import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, { apiVersion: "2024-06-20" });

// no auth, no idempotency
export async function POST(request: NextRequest) {
  const body = await request.json();
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer: body.customerId,
    line_items: [{ price: body.priceId, quantity: 1 }],
    success_url: "https://example.com/success",
    cancel_url: "https://example.com/cancel"
  });
  return NextResponse.json({ url: session.url });
}

// no idempotency on charge
export async function PUT(request: NextRequest) {
  const body = await request.json();
  await stripe.paymentIntents.create({ amount: body.amount, currency: "usd" });
  return NextResponse.json({ ok: true });
}
