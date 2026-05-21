const { buildFinding } = require("../findings");

function strip(line) {
  return line.replace(/\/\/.*$|#.*$/, "");
}

function analyze(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  lines.forEach((rawLine, index) => {
    const line = strip(rawLine);
    if (!line.trim()) return;
    const lineNumber = index + 1;

    if (/(mysql_query|mysqli_query|->query)\s*\(\s*["'][^"']*\$_(GET|POST|REQUEST)/.test(line)) {
      findings.push(buildFinding({
        rule: "php.sql_injection",
        severity: "critical",
        title: "Raw SQL with $_GET/$_POST interpolation",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Use PDO prepared statements with bound parameters. Never interpolate $_GET/$_POST into SQL.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\b(shell_exec|exec|passthru|system)\s*\(\s*\$_(GET|POST|REQUEST)/.test(line)) {
      findings.push(buildFinding({
        rule: "php.command_injection",
        severity: "critical",
        title: "User input in shell command",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Avoid shell execution. If unavoidable, use escapeshellarg / argv-style execution with a strict allowlist.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/.test(line)) {
      findings.push(buildFinding({
        rule: "php.unserialize_user_input",
        severity: "critical",
        title: "unserialize() on user-controlled data",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Never unserialize untrusted input. Use json_decode with strict typing instead.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\beval\s*\(\s*\$_(GET|POST|REQUEST)/.test(line)) {
      findings.push(buildFinding({
        rule: "php.eval_user_input",
        severity: "critical",
        title: "eval() on user-controlled data",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Remove eval entirely. Parse data with json_decode or run user logic in a sandbox.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/include(_once)?\s*\(\s*\$_(GET|POST|REQUEST)/.test(line) || /require(_once)?\s*\(\s*\$_(GET|POST|REQUEST)/.test(line)) {
      findings.push(buildFinding({
        rule: "php.local_file_inclusion",
        severity: "critical",
        title: "Local file inclusion via user input",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Resolve include paths from a whitelist or static map. Never pass request data straight into include/require.",
        ruleType: "regex_match",
        signal: 4
      }));
    }
  });
  return findings;
}

module.exports = { analyze };
