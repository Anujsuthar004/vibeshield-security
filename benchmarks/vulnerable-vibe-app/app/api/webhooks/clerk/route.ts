import { NextRequest, NextResponse } from "next/server";

// pretends to handle clerk events but never verifies the svix signature
export async function POST(request: NextRequest) {
  const event = await request.json();
  if (event.type === "user.created") {
    console.log("welcome", event.data.email_addresses?.[0]?.email_address);
  }
  return NextResponse.json({ ok: true });
}
