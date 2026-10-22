// Prompts a developer can paste straight into Cursor / Claude Code / v0 to fix
// findings. Written for an AI editor that can see the repository.

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function location(finding) {
  if (!finding.file) return "project-wide";
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function describe(finding, index) {
  const prefix = index == null ? "" : `${index + 1}. `;
  const indent = index == null ? "" : "   ";
  return [
    `${prefix}[${finding.severity}] ${location(finding)}: ${finding.title} (${finding.rule})`,
    finding.evidence ? `${indent}Evidence: ${finding.evidence}` : null,
    `${indent}Fix: ${finding.fix}`
  ].filter(Boolean).join("\n");
}

function fixPromptFor(finding) {
  return [
    "VibeShield flagged a security issue in this codebase. Fix it in place.",
    "",
    describe(finding),
    "",
    "Keep existing behaviour otherwise and don't add dependencies unless the fix names one. If this is a false positive, explain why instead of changing code."
  ].join("\n");
}

function withFixPrompts(findings) {
  return findings.map((finding) => ({ ...finding, fix_prompt: fixPromptFor(finding) }));
}

function combinedFixPrompt(findings) {
  const items = findings
    .filter((finding) => !finding.suppressed)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  if (!items.length) return null;
  return [
    `VibeShield found ${items.length} security issue${items.length === 1 ? "" : "s"} in this codebase. Fix them in order, most severe first.`,
    "Keep existing behaviour otherwise and don't add dependencies unless a fix names one.",
    "",
    items.map((finding, index) => describe(finding, index)).join("\n\n"),
    "",
    "When you're done, list what you changed for each numbered item. If an item is a false positive, say why instead of changing code."
  ].join("\n");
}

module.exports = { combinedFixPrompt, fixPromptFor, withFixPrompts };
