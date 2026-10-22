const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "scripts", "cli.js");
const FIXTURE = path.join(ROOT, "benchmarks", "vulnerable-vibe-app");
const { handle } = require("../scripts/mcp");

const IDOR_ROUTE = `import { prisma } from "@/lib/db";
import { auth } from "@clerk/nextjs/server";
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { userId } = await auth();
  if (!userId) return new Response(null, { status: 401 });
  await prisma.invoice.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`;

function tempRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibeshield-git-"));
  const git = (...args) => execFileSync("git", args, { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  return { dir, git, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function write(dir, file, content) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
}

test("--staged reports only findings in staged files", () => {
  const repo = tempRepo();
  try {
    write(repo.dir, "app/api/old/[id]/route.ts", IDOR_ROUTE);
    repo.git("add", ".");
    repo.git("commit", "-qm", "existing code");
    write(repo.dir, "app/api/invoices/[id]/route.ts", IDOR_ROUTE);
    repo.git("add", "app/api/invoices");

    const res = spawnSync(process.execPath, [CLI, "--staged", "--json", "--no-deps", "--quiet", "--fail-on", "high"], { cwd: repo.dir, encoding: "utf8" });
    assert.equal(res.status, 1, res.stderr);
    const files = new Set(JSON.parse(res.stdout).findings.map((f) => f.file));
    assert.deepEqual([...files], ["app/api/invoices/[id]/route.ts"]);

    repo.git("commit", "-qm", "add invoices");
    const clean = spawnSync(process.execPath, [CLI, "--staged", "--no-deps", "--quiet", "--fail-on", "high"], { cwd: repo.dir, encoding: "utf8" });
    assert.equal(clean.status, 0, "nothing staged means nothing to block");
  } finally {
    repo.cleanup();
  }
});

test("--install-hook writes an executable pre-commit hook and won't clobber another one", () => {
  const repo = tempRepo();
  try {
    const run = () => spawnSync(process.execPath, [CLI, "--install-hook"], { cwd: repo.dir, encoding: "utf8" });
    assert.equal(run().status, 0);
    const hook = path.join(repo.dir, ".git", "hooks", "pre-commit");
    assert.match(fs.readFileSync(hook, "utf8"), /vibeshield --staged --fail-on high/);
    assert.ok(fs.statSync(hook).mode & 0o100, "hook must be executable");
    assert.equal(run().status, 0, "re-installing our own hook is fine");

    fs.writeFileSync(hook, "#!/bin/sh\nnpm run lint\n");
    const res = run();
    assert.equal(res.status, 2);
    assert.match(res.stderr, /already exists/);
    assert.equal(fs.readFileSync(hook, "utf8"), "#!/bin/sh\nnpm run lint\n");
  } finally {
    repo.cleanup();
  }
});

test("MCP server lists tools and returns fix instructions for a scan", async () => {
  const init = await handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  assert.equal(init.serverInfo.name, "vibeshield");
  assert.equal(await handle({ jsonrpc: "2.0", method: "notifications/initialized" }), undefined);

  const { tools } = await handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.deepEqual(tools.map((t) => t.name), ["vibeshield_scan", "vibeshield_scan_url"]);

  const call = await handle({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "vibeshield_scan", arguments: { path: FIXTURE, files: ["supabase/migrations/20240101000000_init.sql"], severity: "critical" } }
  });
  const text = call.content[0].text;
  assert.match(text, /Table public\.invoices is created without row level security/);
  assert.doesNotMatch(text, /app\/actions/, "files filter must drop findings elsewhere");

  const bad = await handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "vibeshield_scan_url", arguments: { url: "ftp://x" } } });
  assert.equal(bad.isError, true);
  await assert.rejects(handle({ jsonrpc: "2.0", id: 5, method: "nope" }), /Method not found/);
});
