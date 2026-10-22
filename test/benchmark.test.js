const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { scanDirectory } = require("../scripts/cli");
const manifest = require("../benchmarks/vulnerable-vibe-app/expected-findings.json");

const FIXTURE = path.join(__dirname, "..", "benchmarks", "vulnerable-vibe-app");
const key = (f) => `${f.rule} @ ${f.file}:${f.line}`;

test("benchmark fixture produces exactly the expected findings", async () => {
  const result = await scanDirectory(FIXTURE, { deps: false });
  const actual = new Set(result.findings.map(key));
  const expected = new Set(manifest.expected.map(key));

  const missed = [...expected].filter((k) => !actual.has(k));
  const unexpected = [...actual].filter((k) => !expected.has(k));

  assert.deepEqual(missed, [], `Recall regression, these findings are no longer reported:\n  ${missed.join("\n  ")}`);
  assert.deepEqual(
    unexpected,
    [],
    `New findings not in expected-findings.json (add them if intended):\n  ${unexpected.join("\n  ")}`
  );
});

test("benchmark findings are not suppressed and carry a fix", async () => {
  const result = await scanDirectory(FIXTURE, { deps: false });
  for (const finding of result.findings) {
    assert.equal(finding.suppressed, false, key(finding));
    assert.ok(finding.fix && finding.fix.length > 10, `${key(finding)} has no fix text`);
    assert.ok(["critical", "high", "medium", "low"].includes(finding.severity), key(finding));
  }
});

test("manifest entries point at real lines in the fixture", () => {
  const fs = require("node:fs");
  for (const entry of [...manifest.expected, ...manifest.knownMisses]) {
    const lines = fs.readFileSync(path.join(FIXTURE, entry.file), "utf8").split("\n");
    assert.ok(entry.line >= 1 && entry.line <= lines.length, `${entry.file}:${entry.line} is out of range`);
  }
});
