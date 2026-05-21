const crypto = require("node:crypto");

const SEVERITY_WEIGHTS = { critical: 18, high: 10, medium: 5, low: 2 };
const SECRET_MASKS = [
  [/(sk-(?:live|test|proj)-)[A-Za-z0-9_-]{12,}/g, "$1[redacted]"],
  [/(ghp_|github_pat_)[A-Za-z0-9_]{12,}/g, "$1[redacted]"],
  [/(AKIA)[A-Z0-9]{12,}/g, "$1[redacted]"],
  [/(xox[abprs]-)[A-Za-z0-9-]{12,}/g, "$1[redacted]"],
  [/(rk_(live|test)_)[A-Za-z0-9_]{12,}/g, "$1[redacted]"],
  [/(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})/g, "[redacted-jwt]"],
  [/([A-Za-z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|API_KEY|PASSWORD)[A-Za-z0-9_]*\s*[:=]\s*)[^\s"'`]+/gi, "$1[redacted]"]
];

const RULE_CONFIDENCE = {
  literal_credential: { base: 96, source: "literal pattern" },
  ast_match: { base: 88, source: "AST analysis" },
  semantic_match: { base: 82, source: "semantic heuristic" },
  regex_match: { base: 70, source: "regex heuristic" },
  dependency_cve: { base: 94, source: "OSV advisory" },
  inference: { base: 60, source: "inferred from context" }
};

function maskSecrets(value) {
  let output = String(value);
  for (const [pattern, replacement] of SECRET_MASKS) {
    output = output.replace(pattern, replacement);
  }
  return output.slice(0, 280);
}

function calibrateConfidence({ ruleType, signal = 0, falsePositiveAdjustment = 0 }) {
  const entry = RULE_CONFIDENCE[ruleType] || RULE_CONFIDENCE.regex_match;
  const adjusted = entry.base + Math.min(8, Math.max(-10, signal)) + falsePositiveAdjustment;
  const clamped = Math.max(40, Math.min(99, Math.round(adjusted)));
  return { value: `${clamped}%`, score: clamped, source: entry.source };
}

function fingerprint({ rule, file, line, evidence }) {
  return crypto
    .createHash("sha256")
    .update(`${rule}|${file}|${line}|${evidence}`)
    .digest("hex")
    .slice(0, 16);
}

function buildFinding({ rule, severity, title, category, file, line, lineText, evidence, fix, references = [], ruleType = "regex_match", signal = 0 }) {
  const cleanedEvidence = maskSecrets(evidence || (lineText ? `${file}:${line} ${lineText.trim()}` : ""));
  const confidence = calibrateConfidence({ ruleType, signal });
  return {
    id: fingerprint({ rule, file, line: line || 0, evidence: cleanedEvidence }),
    rule,
    severity,
    title,
    category,
    file: file || null,
    line: line || null,
    evidence: cleanedEvidence,
    fix,
    references,
    confidence: confidence.value,
    confidence_score: confidence.score,
    confidence_source: confidence.source,
    rule_type: ruleType,
    suppressed: false
  };
}

function calculateScore(findings) {
  const active = findings.filter((finding) => !finding.suppressed);
  const penalty = active.reduce((sum, finding) => sum + (SEVERITY_WEIGHTS[finding.severity] || 0), 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function uniqueFindings(items) {
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

module.exports = {
  buildFinding,
  calculateScore,
  calibrateConfidence,
  fingerprint,
  maskSecrets,
  uniqueFindings
};
