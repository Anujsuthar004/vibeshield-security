const { buildFinding } = require("../findings");

const SECRET_PATTERNS = [
  { rule: "secrets.stripe_live", rx: /sk-live-[A-Za-z0-9_-]{12,}/, label: "Stripe live secret key" },
  { rule: "secrets.stripe_test", rx: /sk-test-[A-Za-z0-9_-]{12,}/, label: "Stripe test secret key" },
  { rule: "secrets.github_pat", rx: /ghp_[A-Za-z0-9_]{20,}/, label: "GitHub PAT" },
  { rule: "secrets.github_fine_pat", rx: /github_pat_[A-Za-z0-9_]{20,}/, label: "GitHub fine-grained PAT" },
  { rule: "secrets.aws_key", rx: /AKIA[A-Z0-9]{12,}/, label: "AWS access key id" },
  { rule: "secrets.slack_token", rx: /xox[abprs]-[A-Za-z0-9-]{12,}/, label: "Slack token" },
  { rule: "secrets.openai_key", rx: /sk-proj-[A-Za-z0-9_-]{12,}/, label: "OpenAI project key" },
  { rule: "secrets.sendgrid_key", rx: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/, label: "SendGrid API key" },
  { rule: "secrets.twilio_account", rx: /AC[a-f0-9]{32}/, label: "Twilio account SID" },
  { rule: "secrets.resend_key", rx: /re_[A-Za-z0-9_]{16,}/, label: "Resend API key" },
  { rule: "secrets.supabase_service_role", rx: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, label: "JWT (possibly Supabase service role)" }
];

const ENV_CLIENT_SECRET_RE = /^(NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)_[A-Z0-9_]*(SECRET|PRIVATE|API_?KEY|TOKEN|PASSWORD|SERVICE_ROLE)/i;

function analyze(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  const isEnvFile = /(^|\/)\.env(\.|$)|\.env\.local$|\.env\.example$|\.env\.production$/i.test(file.path);

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
    if (isEnvFile) {
      const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.+)$/);
      if (match && ENV_CLIENT_SECRET_RE.test(match[1])) {
        findings.push(buildFinding({
          rule: "secrets.env_public_secret",
          severity: "high",
          title: `Public-prefixed env var holds a secret: ${match[1]}`,
          category: "Data Exposure",
          file: file.path,
          line: index + 1,
          evidence: `${file.path}:${index + 1} ${match[1]}=<value>`,
          fix: "Public-prefixed env vars (NEXT_PUBLIC_, VITE_, PUBLIC_, REACT_APP_) end up in the client bundle. Drop the prefix for any value that should stay server-side, and rotate the credential.",
          ruleType: "regex_match",
          signal: 3
        }));
      }
    }
  });
  return findings;
}

module.exports = { analyze };
