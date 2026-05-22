"use client";

import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export default function AdminPanel() {
  async function deleteUser(id: string) {
    await supabase.from("users").delete().eq("id", id);
  }
  return <button onClick={() => deleteUser("123")}>delete</button>;
}
