"use server";

import { auth } from "@clerk/nextjs/server";
import { prisma } from "@/lib/db";

// signed in, but can archive anyone's project
export async function archiveProject(projectId: string) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");
  await prisma.project.update({ where: { id: projectId }, data: { archived: true } });
}

// correct: the owner is part of the filter (must not be flagged)
export async function renameProject(projectId: string, name: string) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");
  await prisma.project.update({ where: { id: projectId, userId }, data: { name } });
}
