"use server";

import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";

// mass assignment + no auth + open redirect
export async function updateProfile(formData: FormData) {
  await prisma.user.update({
    where: { id: String(formData.get("userId")) },
    data: Object.fromEntries(formData)
  });

  // open redirect — attacker controls "next"
  const next = String(formData.get("next") || "/");
  redirect(next);
}

// cookie set with no options
export async function setTheme(theme: string) {
  cookies().set("theme", theme);
}
