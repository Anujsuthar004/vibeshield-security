const test = require("node:test");
const assert = require("node:assert/strict");

const { analyzeFile } = require("../api/_lib/analyzers");
const { maskSecrets } = require("../api/_lib/findings");

// Keys are assembled at runtime so no secret-shaped literal is committed
// (GitHub push protection would block it, and our own scanner would flag it).
const body = "FAKEfakeFAKEfake00000000";
const STRIPE_LIVE = ["sk", "live", body].join("_");
const STRIPE_TEST = ["sk", "test", body].join("_");
const STRIPE_RESTRICTED = ["rk", "live", body].join("_");

function rulesFor(path, content) {
  return analyzeFile({ path, content, size: content.length }).map((f) => f.rule);
}

test("Stripe secret keys in source are reported", () => {
  for (const [secret, rule] of [
    [STRIPE_LIVE, "secrets.stripe_live"],
    [STRIPE_RESTRICTED, "secrets.stripe_live"],
    [STRIPE_TEST, "secrets.stripe_test"]
  ]) {
    const rules = rulesFor("lib/stripe.ts", `export const key = "${secret}";\n`);
    assert.ok(rules.includes(rule), `${rule} missing for ${secret.slice(0, 8)}…`);
    assert.ok(rules.includes("secrets.literal_credential"), `AST literal check missed ${secret.slice(0, 8)}…`);
  }
});

test("Stripe keys in non-JS files are reported", () => {
  assert.ok(rulesFor("config/settings.py", `STRIPE_KEY = "${STRIPE_LIVE}"\n`).includes("secrets.stripe_live"));
});

test("Stripe publishable keys are not reported", () => {
  const pk = ["pk", "live", body].join("_");
  assert.deepEqual(rulesFor("lib/stripe.ts", `export const key = "${pk}";\n`), []);
});

test("Stripe keys are masked in stored evidence", () => {
  const masked = maskSecrets(`const key = "${STRIPE_LIVE}"`);
  assert.ok(!masked.includes(body), masked);
  assert.ok(masked.includes("sk_live_[redacted]"), masked);
});
