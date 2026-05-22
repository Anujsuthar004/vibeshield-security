import { NextRequest, NextResponse } from "next/server";

// no signature verification
export async function POST(request: NextRequest) {
  const event = await request.json();
  if (event.type === "checkout.session.completed") {
    // trust the payload because, vibes
  }
  return NextResponse.json({ received: true });
}
