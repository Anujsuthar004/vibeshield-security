const { buildFinding } = require("../findings");

function stripComments(line) {
  return line.replace(/(^|\s)#.*$/, "$1");
}

function looksLikeFlaskRoute(text) {
  return /@\w+\.route\s*\(/.test(text) || /@app\.(get|post|put|delete|patch)\s*\(/.test(text);
}

function looksLikeDjangoView(text, file) {
  return /class\s+\w+View\b|def\s+\w+_view\b/.test(text) || /\bviews\.py$/.test(file.path);
}

function fileLooksProtected(text) {
  return /(login_required|permission_classes|@authentication_classes|request\.user\.is_authenticated|require_auth)/i.test(text);
}

function analyze(file) {
  const findings = [];
  const text = file.content;
  const lines = text.split(/\r?\n/);

  lines.forEach((rawLine, index) => {
    const line = stripComments(rawLine);
    if (!line.trim()) return;
    const lineNumber = index + 1;

    if (/\bsubprocess\.(call|run|Popen|check_output)\s*\(.*shell\s*=\s*True/.test(line) && /(request\.|input\(|sys\.argv)/.test(line)) {
      findings.push(buildFinding({
        rule: "py.shell_injection",
        severity: "critical",
        title: "User input flows into subprocess with shell=True",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Pass an argument list, drop shell=True, and validate input against a strict allowlist.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\bos\.system\s*\(.*(request\.|input\()/.test(line)) {
      findings.push(buildFinding({
        rule: "py.os_system_user_input",
        severity: "critical",
        title: "User input reaches os.system",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Replace os.system with subprocess.run([...]) using an argument list, no shell.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\bcursor\.execute\s*\(\s*['"`].*%s.*['"`]\s*%\s*/.test(line) || /\bcursor\.execute\s*\(\s*f['"]/.test(line)) {
      findings.push(buildFinding({
        rule: "py.sql_injection",
        severity: "critical",
        title: "Possible SQL injection via string formatting",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Pass parameters as the second argument to cursor.execute. Never format SQL with f-strings or %.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\bDEBUG\s*=\s*True\b/.test(line) && /settings\.py$/.test(file.path)) {
      findings.push(buildFinding({
        rule: "py.django_debug_true",
        severity: "high",
        title: "Django DEBUG=True committed to settings",
        category: "Infrastructure & Deployment",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Set DEBUG via environment with a safe default of False; never ship DEBUG=True.",
        ruleType: "regex_match"
      }));
    }

    if (/(secret_key|SECRET_KEY)\s*=\s*['"][^'"]{0,24}['"]/.test(line)) {
      findings.push(buildFinding({
        rule: "py.weak_secret_key",
        severity: "critical",
        title: "Weak or short application SECRET_KEY",
        category: "Authentication & Authorization",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Read SECRET_KEY from environment with at least 32 bytes of entropy.",
        ruleType: "regex_match"
      }));
    }

    if (/yaml\.load\s*\(/.test(line) && !/SafeLoader/.test(line)) {
      findings.push(buildFinding({
        rule: "py.yaml_unsafe_load",
        severity: "high",
        title: "yaml.load without SafeLoader",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Use yaml.safe_load or pass Loader=yaml.SafeLoader to avoid arbitrary object instantiation.",
        ruleType: "regex_match"
      }));
    }

    if (/\bpickle\.loads\s*\(.*(request\.|body|payload|user)/.test(line)) {
      findings.push(buildFinding({
        rule: "py.pickle_loads_untrusted",
        severity: "critical",
        title: "pickle.loads on user-supplied data",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Never pickle.loads untrusted input. Use JSON or a typed schema.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/\beval\s*\(.*(request\.|input\()/.test(line) || /\bexec\s*\(.*(request\.|input\()/.test(line)) {
      findings.push(buildFinding({
        rule: "py.dynamic_eval",
        severity: "critical",
        title: "Dynamic eval/exec on user input",
        category: "Injection Vulnerabilities",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Avoid eval/exec on untrusted data. Parse with json, ast.literal_eval, or a typed validator.",
        ruleType: "regex_match",
        signal: 4
      }));
    }

    if (/requests\.(get|post|put|delete|patch)\s*\([^)]*verify\s*=\s*False/.test(line)) {
      findings.push(buildFinding({
        rule: "py.tls_verify_disabled",
        severity: "high",
        title: "TLS verification disabled on outbound request",
        category: "Infrastructure & Deployment",
        file: file.path,
        line: lineNumber,
        evidence: `${file.path}:${lineNumber} ${line.trim()}`,
        fix: "Always verify TLS certificates. Use a custom CA bundle if needed instead of verify=False.",
        ruleType: "regex_match"
      }));
    }
  });

  if ((looksLikeFlaskRoute(text) || looksLikeDjangoView(text, file)) && !fileLooksProtected(text)) {
    findings.push(buildFinding({
      rule: "py.unprotected_route",
      severity: "medium",
      title: "Python route has no obvious authentication guard",
      category: "Authentication & Authorization",
      file: file.path,
      line: 1,
      evidence: `${file.path} declares an HTTP handler without login_required / permission checks`,
      fix: "Wrap views with login_required, IsAuthenticated permissions, or your auth middleware.",
      ruleType: "semantic_match",
      signal: -2
    }));
  }

  return findings;
}

module.exports = { analyze };
