const PATCH_TEMPLATES = {
  "auth.token_in_browser_storage": {
    summary: "Move auth tokens out of browser storage",
    body: [
      "// Replace localStorage/sessionStorage token storage with httpOnly cookies set by the server.",
      "// Example replacement (server-side):",
      "// res.setHeader('Set-Cookie', `auth=${token}; HttpOnly; Secure; SameSite=Lax; Path=/`)"
    ].join("\n")
  },
  "auth.weak_jwt_secret": {
    summary: "Replace hardcoded JWT secret with env-loaded value",
    body: [
      "// Hardcoded JWT secrets must be removed. Replace with:",
      "// const secret = process.env.JWT_SECRET;",
      "// if (!secret || secret.length < 32) throw new Error('JWT_SECRET missing or too short')"
    ].join("\n")
  },
  "injection.sql_template": {
    summary: "Switch to parameterized SQL",
    body: [
      "// Replace template-built SQL with parameter placeholders.",
      "// Example: db.query('SELECT * FROM users WHERE id = $1', [userId])"
    ].join("\n")
  },
  "injection.sql_concat": {
    summary: "Switch to parameterized SQL",
    body: [
      "// Concatenated SQL is unsafe. Replace with parameter placeholders.",
      "// db.query('SELECT * FROM users WHERE id = $1', [userId])"
    ].join("\n")
  },
  "injection.shell_command": {
    summary: "Drop shell interpolation",
    body: [
      "// Use an argument array instead of building a shell command from user input.",
      "// const { execFile } = require('node:child_process')",
      "// execFile('/usr/local/bin/safe', [sanitizedArg], callback)"
    ].join("\n")
  },
  "logic.mass_assignment": {
    summary: "Pick allowed fields explicitly",
    body: [
      "// Map allowed fields before passing to the ORM.",
      "// const allowed = ['name', 'email']",
      "// const data = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))"
    ].join("\n")
  },
  "logic.predictable_random": {
    summary: "Use cryptographic randomness",
    body: [
      "// Replace Math.random() with crypto.randomBytes for any security-sensitive value.",
      "// const token = require('node:crypto').randomBytes(24).toString('base64url')"
    ].join("\n")
  },
  "infra.open_cors": {
    summary: "Restrict CORS origins",
    body: [
      "// Avoid wildcard CORS. Configure explicit origins per environment.",
      "// app.use(cors({ origin: ['https://app.example.com'], credentials: true }))"
    ].join("\n")
  },
  "xss.dangerously_set_inner_html": {
    summary: "Render text or sanitize HTML",
    body: [
      "// Render with {value} instead of dangerouslySetInnerHTML.",
      "// If HTML is required, sanitize with DOMPurify before assignment."
    ].join("\n")
  },
  "webhooks.unverified_signature": {
    summary: "Verify webhook signatures",
    body: [
      "// Verify the provider signature against the raw request body.",
      "// Stripe example:",
      "// const event = stripe.webhooks.constructEvent(rawBody, signatureHeader, endpointSecret)"
    ].join("\n")
  },
  "secrets.client_bundle_exposure": {
    summary: "Drop public prefix for server-only secrets",
    body: [
      "// Move server-only secrets out of NEXT_PUBLIC_/VITE_/PUBLIC_ env names.",
      "// Read them on the server only and rotate the exposed credential."
    ].join("\n")
  },
  "db.rls_disabled": {
    summary: "Re-enable RLS and define policies",
    body: [
      "-- ALTER TABLE public.<table> ENABLE ROW LEVEL SECURITY;",
      "-- CREATE POLICY <name> ON public.<table> FOR SELECT USING (auth.uid() = user_id);"
    ].join("\n")
  }
};

function buildPatch(finding) {
  const template = PATCH_TEMPLATES[finding.rule];
  if (!template) {
    return {
      summary: "Manual fix required",
      body: `// VibeShield does not have an automated patch for ${finding.rule} yet.\n// Apply: ${finding.fix}`
    };
  }
  return template;
}

function findingsWithPatches(findings) {
  return findings.map((finding) => ({ ...finding, patch: buildPatch(finding) }));
}

function buildUnifiedDiff(finding) {
  const patch = buildPatch(finding);
  const path = finding.file || "vibeshield.notes";
  const header = `--- a/${path}\n+++ b/${path}`;
  const note = patch.body.split("\n").map((line) => `+${line}`).join("\n");
  const context = `@@ -${finding.line || 1},0 +${finding.line || 1},${patch.body.split("\n").length} @@`;
  return `${header}\n${context}\n${note}\n`;
}

function buildPrSummary(scanResult) {
  const active = scanResult.findings.filter((finding) => !finding.suppressed);
  const sevCounts = active.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});
  const lines = [
    "## VibeShield scan summary",
    "",
    `Scan id: \`${scanResult.id}\``,
    `Target: \`${scanResult.target}\``,
    `Score: **${scanResult.score}/100**`,
    "",
    "| Severity | Count |",
    "| --- | --- |"
  ];
  for (const severity of ["critical", "high", "medium", "low"]) {
    lines.push(`| ${severity} | ${sevCounts[severity] || 0} |`);
  }
  lines.push("");
  lines.push("### Top findings");
  for (const finding of active.slice(0, 10)) {
    lines.push(`- **${finding.severity.toUpperCase()}** ${finding.title} — \`${finding.file || "general"}${finding.line ? `:${finding.line}` : ""}\` (rule: \`${finding.rule}\`)`);
  }
  lines.push("");
  lines.push("Findings can be suppressed via `.vibeshield.ignore` or the suppressions API.");
  return lines.join("\n");
}

module.exports = {
  buildPatch,
  buildPrSummary,
  buildUnifiedDiff,
  findingsWithPatches
};
