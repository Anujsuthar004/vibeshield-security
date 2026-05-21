const { buildFinding } = require("../findings");
const db = require("../db");

const OSV_ENDPOINT = "https://api.osv.dev/v1/query";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const ECOSYSTEMS = {
  npm: { manifests: ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"], ecosystem: "npm" },
  pypi: { manifests: ["requirements.txt", "Pipfile.lock", "poetry.lock"], ecosystem: "PyPI" },
  rubygems: { manifests: ["Gemfile", "Gemfile.lock"], ecosystem: "RubyGems" },
  go: { manifests: ["go.mod", "go.sum"], ecosystem: "Go" },
  packagist: { manifests: ["composer.lock", "composer.json"], ecosystem: "Packagist" },
  maven: { manifests: ["pom.xml"], ecosystem: "Maven" }
};

function detectEcosystem(filePath) {
  const lower = filePath.toLowerCase();
  for (const [, info] of Object.entries(ECOSYSTEMS)) {
    if (info.manifests.some((manifest) => lower.endsWith(`/${manifest}`) || lower === manifest)) {
      return info.ecosystem;
    }
  }
  return null;
}

function cleanVersion(version) {
  if (!version) return null;
  return String(version).replace(/^[\^~>=<\s*]+/, "").replace(/\s+.*$/, "").trim() || null;
}

function parsePackageJson(content) {
  try {
    const json = JSON.parse(content);
    const entries = [];
    for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
      const block = json[section];
      if (!block) continue;
      for (const [name, version] of Object.entries(block)) {
        const cleaned = cleanVersion(version);
        if (cleaned && /^\d/.test(cleaned)) {
          entries.push({ name, version: cleaned });
        }
      }
    }
    return entries;
  } catch {
    return [];
  }
}

function parsePackageLock(content) {
  try {
    const json = JSON.parse(content);
    const entries = [];
    if (json.packages) {
      for (const [key, value] of Object.entries(json.packages)) {
        if (!key || !value || !value.version) continue;
        const match = key.match(/node_modules\/(.+)$/);
        if (!match) continue;
        entries.push({ name: match[1], version: value.version });
      }
    } else if (json.dependencies) {
      for (const [name, value] of Object.entries(json.dependencies)) {
        if (value?.version) {
          entries.push({ name, version: value.version });
        }
      }
    }
    return entries;
  } catch {
    return [];
  }
}

function parseRequirementsTxt(content) {
  const entries = [];
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.split("#")[0].trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)/);
    if (match) {
      entries.push({ name: match[1], version: match[2] });
    }
  }
  return entries;
}

function parseGemfileLock(content) {
  const entries = [];
  let inGems = false;
  for (const line of content.split(/\r?\n/)) {
    if (/^GEM/.test(line.trim())) {
      inGems = true;
      continue;
    }
    if (inGems && /^[A-Z]/.test(line.trim())) {
      inGems = false;
    }
    if (inGems) {
      const match = line.match(/^\s{4}([A-Za-z0-9_.\-]+)\s*\(([0-9][^)]*)\)/);
      if (match) {
        entries.push({ name: match[1], version: match[2] });
      }
    }
  }
  return entries;
}

function parseGoMod(content) {
  const entries = [];
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
  const body = requireBlock ? requireBlock[1] : content;
  for (const line of body.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z0-9._\/-]+)\s+(v[0-9][^\s]*)/);
    if (match) {
      entries.push({ name: match[1], version: match[2].replace(/^v/, "") });
    }
  }
  return entries;
}

function parseEntries(file) {
  const base = file.path.split("/").pop().toLowerCase();
  if (base === "package.json") return parsePackageJson(file.content);
  if (base === "package-lock.json") return parsePackageLock(file.content);
  if (base === "requirements.txt") return parseRequirementsTxt(file.content);
  if (base === "gemfile.lock") return parseGemfileLock(file.content);
  if (base === "go.mod") return parseGoMod(file.content);
  return [];
}

async function readCache(cacheKey) {
  if (!db.usingPg()) return null;
  try {
    const row = await db.findOne("osv_cache", { cache_key: cacheKey });
    if (!row) return null;
    if (Date.parse(row.expires_at) <= Date.now()) {
      return null;
    }
    return typeof row.vulns === "string" ? JSON.parse(row.vulns) : row.vulns;
  } catch {
    return null;
  }
}

async function writeCache(cacheKey, ecosystem, name, version, vulns) {
  if (!db.usingPg()) return;
  try {
    const expiresAt = new Date(Date.now() + CACHE_TTL_MS).toISOString();
    const existing = await db.findOne("osv_cache", { cache_key: cacheKey });
    if (existing) {
      await db.update("osv_cache", { cache_key: cacheKey }, { vulns, expires_at: expiresAt });
    } else {
      await db.insert("osv_cache", {
        cache_key: cacheKey,
        ecosystem,
        package_name: name,
        version,
        vulns,
        expires_at: expiresAt
      });
    }
  } catch {
    // best effort
  }
}

async function osvQuery(name, version, ecosystem) {
  const cacheKey = `${ecosystem}:${name}:${version}`;
  const cached = await readCache(cacheKey);
  if (cached) return cached;
  try {
    const response = await fetch(OSV_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "VibeShield-Security-Scanner" },
      body: JSON.stringify({ package: { name, ecosystem }, version })
    });
    if (!response.ok) return [];
    const body = await response.json();
    const vulns = Array.isArray(body.vulns) ? body.vulns : [];
    await writeCache(cacheKey, ecosystem, name, version, vulns);
    return vulns;
  } catch {
    return [];
  }
}

function severityFromVuln(vuln) {
  const candidates = vuln.severity || [];
  for (const entry of candidates) {
    if (entry.type === "CVSS_V3" && entry.score) {
      const numeric = parseFloat(String(entry.score).replace(/.*\//, ""));
      if (Number.isFinite(numeric)) {
        if (numeric >= 9) return "critical";
        if (numeric >= 7) return "high";
        if (numeric >= 4) return "medium";
        return "low";
      }
    }
  }
  if (Array.isArray(vuln.database_specific?.severity)) {
    return String(vuln.database_specific.severity[0]).toLowerCase();
  }
  return "medium";
}

async function analyzeFiles(files, options = {}) {
  const manifestFiles = files.filter((file) => detectEcosystem(file.path));
  if (!manifestFiles.length || options.enabled === false) return [];
  const findings = [];
  const queried = new Set();
  for (const file of manifestFiles) {
    const ecosystem = detectEcosystem(file.path);
    if (!ecosystem) continue;
    const entries = parseEntries(file).slice(0, 100);
    for (const entry of entries) {
      const key = `${ecosystem}:${entry.name}:${entry.version}`;
      if (queried.has(key)) continue;
      queried.add(key);
      const vulns = await osvQuery(entry.name, entry.version, ecosystem);
      for (const vuln of vulns.slice(0, 3)) {
        const severity = severityFromVuln(vuln);
        const summary = (vuln.summary || vuln.id || "Vulnerable dependency").slice(0, 160);
        const refs = (vuln.references || []).slice(0, 3).map((reference) => reference.url).filter(Boolean);
        findings.push(buildFinding({
          rule: `deps.cve.${vuln.id || "unknown"}`,
          severity,
          title: `${entry.name}@${entry.version}: ${summary}`,
          category: "Supply Chain",
          file: file.path,
          line: null,
          evidence: `${entry.name}@${entry.version} (${ecosystem}) — ${vuln.id || "advisory"}`,
          fix: vuln.affected?.[0]?.ranges?.[0]?.events
            ? `Upgrade ${entry.name} past the affected range. See ${refs[0] || "OSV.dev"}.`
            : `Review and upgrade ${entry.name} to a non-affected version.`,
          references: refs.length ? refs : ["https://osv.dev/" + (vuln.id || "")],
          ruleType: "dependency_cve",
          signal: severity === "critical" ? 6 : severity === "high" ? 3 : 0
        }));
      }
    }
  }
  return findings;
}

module.exports = {
  analyzeFiles,
  detectEcosystem,
  parseEntries
};
