const { buildFinding } = require("../findings");

function strip(line) {
  return line.replace(/#.*$/, "");
}

function analyze(file) {
  const findings = [];
  const text = file.content;
  const lines = text.split(/\r?\n/);
  lines.forEach((rawLine, index) => {
    const line = strip(rawLine);
    if (!line.trim()) return;
    const lineNumber = index + 1;

    if (/`[^`]*#\{[^}]*params/i.test(line) || /system\s*\(\s*["'].*#\{[^}]*params/i.test(line)) {
      findings.push(buildFinding({
        rule: "rb.shell_injection",
        severity: "critical",
        title: "User input flows into shell command",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Use system with an argv array form and a strict allowlist for any input that influences arguments.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\.where\s*\(\s*["'].*#\{[^}]+\}/i.test(line) || /\.find_by_sql\s*\(\s*["'].*#\{[^}]+\}/i.test(line)) {
      findings.push(buildFinding({
        rule: "rb.sql_interpolation",
        severity: "critical",
        title: "SQL string interpolation in ActiveRecord query",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Use parameter placeholders (e.g. where('email = ?', email)) or hash conditions.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/skip_before_action\s+:verify_authenticity_token/.test(line)) {
      findings.push(buildFinding({
        rule: "rb.csrf_disabled",
        severity: "high",
        title: "CSRF protection disabled in Rails controller",
        category: "Cross-Site Request Forgery",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Leave protect_from_forgery enabled. Scope skip_before_action to APIs that use signed tokens.",
        ruleType: "regex_match"
      }));
    }

    if (/Marshal\.load\s*\(\s*(params|request|body)/.test(line)) {
      findings.push(buildFinding({
        rule: "rb.marshal_untrusted",
        severity: "critical",
        title: "Marshal.load on untrusted data",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Marshal.load executes arbitrary code. Replace with JSON.parse or a typed parser.",
        ruleType: "regex_match",
        signal: 4
      }));
    }
  });

  if (/class\s+\w+Controller/.test(text) && !/before_action\s*:[a-z_]+/.test(text) && /\.(create|update|destroy)\b/.test(text)) {
    findings.push(buildFinding({
      rule: "rb.unprotected_controller",
      severity: "medium",
      title: "Rails controller performs writes without a before_action guard",
      category: "Authentication & Authorization",
      file: file.path,
      line: 1,
      evidence: `${file.path} controller mutates records without a recognizable auth before_action`,
      fix: "Add a before_action :authenticate_user! (Devise) or equivalent guard.",
      ruleType: "semantic_match",
      signal: -2
    }));
  }

  return findings;
}

module.exports = { analyze };
