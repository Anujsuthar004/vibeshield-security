import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import fs from "node:fs";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// no auth check, IDOR by design
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const id = params.id;
  // SQL injection via template literal
  const { data } = await supabase.rpc("get_user", { sql: `SELECT * FROM users WHERE id = '${id}'` });
  // path traversal — user controls the avatar file name
  const avatarPath = `./avatars/${id}.png`;
  const avatar = fs.readFileSync(avatarPath);
  return NextResponse.json({ user: data, avatar: avatar.length });
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  // no auth at all
  await supabase.auth.admin.deleteUser(params.id);
  return new NextResponse(null, { status: 204 });
}
