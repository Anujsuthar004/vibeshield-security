import { NextResponse } from "next/server";
import { auth } from "@clerk/nextjs/server";
import { prisma } from "@/lib/db";

// signed-in is checked, ownership is not: any user can read any project
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { userId } = await auth();
  if (!userId) return new NextResponse("Unauthorized", { status: 401 });
  const { id } = await params;
  const project = await prisma.project.findUnique({ where: { id } });
  return NextResponse.json(project);
}

// correct: compares the record's owner to the caller (must not be flagged)
export async function PATCH(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { userId } = await auth();
  if (!userId) return new NextResponse("Unauthorized", { status: 401 });
  const { id } = await params;
  const project = await prisma.project.findUnique({ where: { id } });
  if (!project || project.userId !== userId) return new NextResponse("Not found", { status: 404 });
  const { name } = await request.json();
  const updated = await prisma.project.update({ where: { id }, data: { name } });
  return NextResponse.json(updated);
}
