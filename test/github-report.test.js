const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const SCAN_PATH = "benchmarks/vulnerable-vibe-app";

function runAction(failOn) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibeshield-action-"));
  const json = path.join(tmp, "result.json");
  const sarif = path.join(tmp, "out.sarif");
  const env = {
    ...process.env,
    GITHUB_WORKSPACE: ROOT,
    GITHUB_OUTPUT: path.join(tmp, "output"),
    GITHUB_STEP_SUMMARY: path.join(tmp, "summary.md")
  };
  const scan = spawnSync(process.execPath, ["scripts/cli.js", SCAN_PATH, "--json", "--quiet", "--no-deps", "-o", json], { cwd: ROOT, env, encoding: "utf8" });
  assert.equal(scan.status, 0, scan.stderr);
  const report = spawnSync(
    process.execPath,
    ["scripts/github-report.js", json, "--path", SCAN_PATH, "--fail-on", failOn, "--sarif", sarif],
    { cwd: ROOT, env, encoding: "utf8" }
  );
  const read = (file) => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "");
  const out = {
    status: report.status,
    stdout: report.stdout,
    stderr: report.stderr,
    outputs: Object.fromEntries(read(env.GITHUB_OUTPUT).trim().split("\n").filter(Boolean).map((l) => l.split("="))),
    summary: read(env.GITHUB_STEP_SUMMARY),
    sarif: read(sarif) && JSON.parse(read(sarif))
  };
  fs.rmSync(tmp, { recursive: true, force: true });
  return out;
}

test("report emits annotations with repo-relative paths", () => {
  const res = runAction("high");
  assert.equal(res.status, 0, res.stderr);
  const annotations = res.stdout.split("\n").filter((l) => l.startsWith("::"));
  assert.ok(annotations.length > 0);
  assert.ok(annotations.some((l) => l.startsWith(`::error file=${SCAN_PATH}/lib/jwt.ts,line=4,`)), annotations.join("\n"));
});

test("report sets outputs and fails only at the threshold", () => {
  const high = runAction("high");
  assert.equal(high.outputs.failed, "true");
  assert.ok(Number(high.outputs.findings) > 0);
  assert.match(high.outputs.score, /^\d+$/);
  assert.equal(runAction("none").outputs.failed, "false");
});

test("report writes a summary table and repo-relative SARIF", () => {
  const res = runAction("high");
  assert.match(res.summary, /^## VibeShield: score \d+\/100/);
  assert.match(res.summary, /\| critical \| .* \| `benchmarks\/vulnerable-vibe-app\/lib\/jwt\.ts:4` \|/);
  for (const result of res.sarif.runs[0].results) {
    for (const loc of result.locations) {
      assert.ok(loc.physicalLocation.artifactLocation.uri.startsWith(`${SCAN_PATH}/`));
    }
  }
});

test("report rejects an unknown fail-on value", () => {
  const res = runAction("severe");
  assert.equal(res.status, 2);
  assert.match(res.stdout + res.stderr, /fail-on must be one of/);
});
