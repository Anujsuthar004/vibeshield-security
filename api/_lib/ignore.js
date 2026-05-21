const db = require("./db");

function fileGlobToRegex(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const pattern = escaped.replace(/\*\*/g, "::DOUBLE::").replace(/\*/g, "[^/]*").replace(/::DOUBLE::/g, ".*").replace(/\?/g, "[^/]");
  return new RegExp(`^${pattern}$`);
}

function parseIgnoreFile(contents) {
  const rules = [];
  if (!contents) return rules;
  const lines = String(contents).split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("rule:")) {
      const parts = line.slice("rule:".length).split(/\s+/).filter(Boolean);
      const ruleId = parts.shift();
      const pathGlob = parts.length ? parts.join(" ") : "**/*";
      rules.push({ kind: "rule", rule: ruleId, glob: pathGlob, regex: fileGlobToRegex(pathGlob) });
    } else if (line.startsWith("path:")) {
      const glob = line.slice("path:".length).trim();
      rules.push({ kind: "path", glob, regex: fileGlobToRegex(glob) });
    } else if (line.startsWith("finding:")) {
      const findingId = line.slice("finding:".length).trim();
      rules.push({ kind: "finding", findingId });
    } else {
      rules.push({ kind: "path", glob: line, regex: fileGlobToRegex(line) });
    }
  }
  return rules;
}

function fileLooksIgnored(rules, filePath) {
  return rules.some((rule) => rule.kind === "path" && rule.regex.test(filePath));
}

function findingLooksIgnored(rules, finding) {
  return rules.some((rule) => {
    if (rule.kind === "finding") return rule.findingId === finding.id;
    if (rule.kind === "rule") {
      const matchesRule = rule.rule === finding.rule || rule.rule === "*";
      if (!matchesRule) return false;
      if (!finding.file) return true;
      return rule.regex.test(finding.file);
    }
    return false;
  });
}

async function loadOrgSuppressions(orgId) {
  if (!orgId) return [];
  const rows = await db.findMany("suppressions", { org_id: orgId }, { limit: 500 });
  return rows.map((row) => ({
    findingId: row.finding_id,
    target: row.target,
    reason: row.reason || ""
  }));
}

function suppressionApplies(suppression, finding, target) {
  if (suppression.target && target && suppression.target !== "*" && suppression.target !== target) {
    return false;
  }
  return suppression.findingId === finding.id;
}

function applySuppressions({ findings, ignoreRules = [], orgSuppressions = [], target = "" }) {
  return findings.map((finding) => {
    const ignoredByFile = ignoreRules.length && findingLooksIgnored(ignoreRules, finding);
    const ignoredByOrg = orgSuppressions.find((suppression) => suppressionApplies(suppression, finding, target));
    if (ignoredByFile || ignoredByOrg) {
      return {
        ...finding,
        suppressed: true,
        suppression_reason: ignoredByOrg?.reason || "matched .vibeshield.ignore"
      };
    }
    return finding;
  });
}

module.exports = {
  applySuppressions,
  fileGlobToRegex,
  fileLooksIgnored,
  findingLooksIgnored,
  loadOrgSuppressions,
  parseIgnoreFile
};
