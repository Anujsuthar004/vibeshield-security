const { buildFinding } = require("../findings");

const SECRET_PATTERNS = [
  { rule: "secrets.stripe_live", rx: /sk-live-[A-Za-z0-9_-]{12,}/, label: "Stripe live secret key" },
  { rule: "secrets.stripe_test", rx: /sk-test-[A-Za-z0-9_-]{12,}/, label: "Stripe test secret key" },
  { rule: "secrets.github_pat", rx: /ghp_[A-Za-z0-9_]{20,}/, label: "GitHub PAT" },
  { rule: "secrets.github_fine_pat", rx: /github_pat_[A-Za-z0-9_]{20,}/, label: "GitHub fine-grained PAT" },
  { rule: "secrets.aws_key", rx: /AKIA[A-Z0-9]{12,}/, label: "AWS access key id" },
  { rule: "secrets.slack_token", rx: /xox[abprs]-[A-Za-z0-9-]{12,}/, label: "Slack token" },
  { rule: "secrets.openai_key", rx: /sk-proj-[A-Za-z0-9_-]{12,}/, label: "OpenAI project key" }
];

function analyze(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (/^\s*(\/\/|#|--|\*)/.test(line)) return;
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.rx.test(line)) {
        findings.push(buildFinding({
          rule: pattern.rule,
          severity: "critical",
          title: `Committed ${pattern.label}`,
          category: "Data Exposure",
          file: file.path,
          line: index + 1,
          evidence: `${file.path}:${index + 1} ${line.trim()}`,
          fix: "Revoke and rotate the credential, remove it from git history, and load it from a secret manager.",
          ruleType: "literal_credential"
        }));
      }
    }
  });
  return findings;
}

module.exports = { analyze };
