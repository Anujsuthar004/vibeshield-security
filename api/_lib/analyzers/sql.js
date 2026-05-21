const { buildFinding } = require("../findings");

function analyze(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  lines.forEach((rawLine, index) => {
    const line = rawLine;
    if (!line.trim() || line.trim().startsWith("--")) return;
    const lineNumber = index + 1;

    if (/alter\s+table[^;]+disable\s+row\s+level\s+security/i.test(line) || /\brls\s*=\s*false\b/i.test(line)) {
      findings.push(buildFinding({
        rule: "db.rls_disabled",
        severity: "critical",
        title: "Row Level Security disabled",
        category: "Database & Storage",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Enable RLS on exposed tables and add role-specific policies for SELECT, INSERT, UPDATE, DELETE.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/grant\s+(all|select|insert|update|delete)\b[^;]*\bto\s+(anon|public)\b/i.test(line)) {
      findings.push(buildFinding({
        rule: "db.public_grant",
        severity: "high",
        title: "Permissive GRANT to anonymous role",
        category: "Database & Storage",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Restrict grants by role. Avoid granting write privileges to anon/public.",
        ruleType: "regex_match"
      }));
    }
  });
  return findings;
}

module.exports = { analyze };
