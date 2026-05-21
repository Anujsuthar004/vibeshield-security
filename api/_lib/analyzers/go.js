const { buildFinding } = require("../findings");

function strip(line) {
  return line.replace(/\/\/.*$/, "");
}

function analyze(file) {
  const findings = [];
  const text = file.content;
  const lines = text.split(/\r?\n/);
  lines.forEach((rawLine, index) => {
    const line = strip(rawLine);
    if (!line.trim()) return;
    const lineNumber = index + 1;

    if (/exec\.Command\([^,]+,\s*[^)]+r\.URL\.Query|exec\.Command\([^,]+,\s*[^)]+r\.FormValue/.test(line)) {
      findings.push(buildFinding({
        rule: "go.shell_injection",
        severity: "critical",
        title: "User input passed to exec.Command",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Validate against an allowlist and use a fixed argv. Never let request data control the binary path.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/db\.(Exec|Query|QueryRow)\s*\(\s*fmt\.Sprintf/.test(line)) {
      findings.push(buildFinding({
        rule: "go.sql_sprintf",
        severity: "critical",
        title: "SQL built with fmt.Sprintf",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Use parameterized queries (e.g. db.Query(\"SELECT ... WHERE id = $1\", id)).",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/tls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true/.test(line)) {
      findings.push(buildFinding({
        rule: "go.tls_insecure",
        severity: "high",
        title: "TLS verification disabled (InsecureSkipVerify: true)",
        category: "Infrastructure & Deployment",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Trust the system CA store. Use a custom RootCAs pool if you need to pin certificates.",
        ruleType: "regex_match"
      }));
    }

    if (/http\.HandleFunc\s*\(\s*"\/api/.test(line) && !/auth|middleware|protect|verify/i.test(text)) {
      findings.push(buildFinding({
        rule: "go.unprotected_route",
        severity: "medium",
        title: "Go HTTP handler exposes /api without visible auth wrapper",
        category: "Authentication & Authorization",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Wrap handlers in an auth middleware or check r.Context for the authenticated principal.",
        ruleType: "semantic_match",
        signal: -2
      }));
    }
  });
  return findings;
}

module.exports = { analyze };
