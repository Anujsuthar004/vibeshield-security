const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "scripts", "cli.js");
const FIXTURE = path.join(ROOT, "benchmarks", "vulnerable-vibe-app");
const { version } = require("../package.json");

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args, "--no-deps", "--quiet"], { encoding: "utf8" });
}

test("--fail-on exits 1 when findings meet the threshold", () => {
  assert.equal(run([FIXTURE, "--fail-on", "critical"]).status, 1);
});

test("--fail-on exits 0 on a clean directory", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibeshield-clean-"));
  fs.writeFileSync(path.join(dir, "index.js"), "export const add = (a, b) => a + b;\n");
  try {
    const res = run([dir, "--fail-on", "low"]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("invalid severity is rejected", () => {
  const res = run([FIXTURE, "--fail-on", "severe"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /--fail-on must be one of/);
});

test("--sarif emits SARIF 2.1.0 with the package version", () => {
  const res = run([FIXTURE, "--sarif"]);
  assert.equal(res.status, 0, res.stderr);
  const sarif = JSON.parse(res.stdout);
  assert.equal(sarif.version, "2.1.0");
  const [runResult] = sarif.runs;
  assert.equal(runResult.tool.driver.version, version);
  assert.ok(runResult.results.length > 0);
  for (const result of runResult.results) {
    assert.ok(["error", "warning", "note"].includes(result.level));
    assert.ok(runResult.tool.driver.rules.some((rule) => rule.id === result.ruleId));
  }
});

test("large JSON output piped to another process is not truncated", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibeshield-big-"));
  try {
    for (let i = 0; i < 120; i += 1) {
      fs.writeFileSync(path.join(dir, `f${i}.js`), "export function run(input) { return eval(input); }\nlocalStorage.setItem('token', 'x');\n");
    }
    const res = run([dir, "--json"]);
    assert.ok(res.stdout.length > 64 * 1024, `expected >64 KB of output, got ${res.stdout.length}`);
    assert.ok(JSON.parse(res.stdout).findings.length >= 120);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
