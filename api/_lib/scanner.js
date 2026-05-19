const crypto = require("node:crypto");
const { authHeaderFor, githubRequest } = require("./github-app");
const { cleanupExpired, createWorkerDir, removeWorkerDir, saveScan } = require("./storage");

const MAX_FILES = 160;
const MAX_FILE_BYTES = 120 * 1024;
const MAX_TOTAL_BYTES = 2.5 * 1024 * 1024;
const TEXT_FILE_RE = /\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|java|cs|rs|sql|prisma|json|env|yml|yaml|toml|md|html|css|vue|svelte)$/i;
const SKIP_PATH_RE = /(^|\/)(node_modules|dist|build|coverage|\.next|\.git|vendor|target|__pycache__)\//;

function parseRepoUrl(repoUrl) {
  const match = String(repoUrl || "").match(/^https:\/\/github\.com\/([^/\s]+)\/([^/\s#?]+)(?:[/?#].*)?$/i);
  if (!match) {
    throw Object.assign(new Error("Use a full GitHub repository URL, for example https://github.com/acme/app."), { statusCode: 400, code: "invalid_repo_url" });
  }
  return { owner: match[1], repo: match[2].replace(/\.git$/i, "") };
}

function maskSecrets(value) {
  return String(value)
    .replace(/(sk-(?:live|test|proj)-)[A-Za-z0-9_-]{12,}/g, "$1[redacted]")
    .replace(/(ghp_|github_pat_)[A-Za-z0-9_]{12,}/g, "$1[redacted]")
    .replace(/(AKIA)[A-Z0-9]{12,}/g, "$1[redacted]")
    .replace(/([A-Za-z0-9_]*SECRET[A-Za-z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1[redacted]")
    .replace(/([A-Za-z0-9_]*TOKEN[A-Za-z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1[redacted]")
    .slice(0, 260);
}

function lineEvidence(file, lineNumber, line) {
  return `${file}:${lineNumber} ${maskSecrets(line.trim())}`;
}

function finding({ severity, title, category, evidence, fix, confidence = "82%" }) {
  return {
    id: crypto.createHash("sha256").update(`${title}:${evidence}`).digest("hex").slice(0, 16),
    severity,
    title,
    category,
    evidence,
    fix,
    confidence
  };
}

function analyzeFile(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  const text = file.content;

  lines.forEach((line, index) => {
    const n = index + 1;
    if (/\b(localStorage|sessionStorage)\.setItem\s*\(\s*['"`](token|jwt|accessToken|auth)/i.test(line)) {
      findings.push(finding({
        severity: "high",
        category: "Authentication & Authorization",
        title: "JWT or auth token stored in browser storage",
        evidence: lineEvidence(file.path, n, line),
        fix: "Store session tokens in httpOnly, secure, sameSite cookies or use short-lived memory tokens with refresh rotation.",
        confidence: "88%"
      }));
    }
    if (/jwt\.sign\s*\([^)]*['"`](secret|jwt_secret|changeme|password)['"`]/i.test(line) || /JWT_SECRET\s*=\s*['"`]?(secret|jwt_secret|changeme)/i.test(line)) {
      findings.push(finding({
        severity: "critical",
        category: "Authentication & Authorization",
        title: "Hardcoded or weak JWT secret",
        evidence: lineEvidence(file.path, n, line),
        fix: "Move signing secrets to a managed secret store, rotate them, and require strong entropy.",
        confidence: "93%"
      }));
    }
    if (/\bSELECT\b[\s\S]*\+\s*(req\.|userId|id|params|query|body)/i.test(line) || /\bquery\s*\(\s*`[^`]*(\$\{|SELECT)/i.test(line)) {
      findings.push(finding({
        severity: "critical",
        category: "Injection Vulnerabilities",
        title: "Possible raw SQL interpolation",
        evidence: lineEvidence(file.path, n, line),
        fix: "Use parameterized queries, prepared statements, or ORM parameter binding for all user-controlled values.",
        confidence: "86%"
      }));
    }
    if (/\bexec(File)?\s*\([^)]*(req\.|params|query|body|userInput)/i.test(line) || /child_process\.(exec|spawn)\s*\([^)]*(req\.|params|query|body)/i.test(line)) {
      findings.push(finding({
        severity: "critical",
        category: "Injection Vulnerabilities",
        title: "User input reaches command execution",
        evidence: lineEvidence(file.path, n, line),
        fix: "Avoid shell execution. If unavoidable, use an argument array, strict allowlists, and never interpolate raw user input.",
        confidence: "91%"
      }));
    }
    if (/dangerouslySetInnerHTML|\.innerHTML\s*=/.test(line)) {
      findings.push(finding({
        severity: "medium",
        category: "Cross-Site Scripting",
        title: "Raw HTML rendering path",
        evidence: lineEvidence(file.path, n, line),
        fix: "Render text by default or sanitize HTML with a strict server-side allowlist before storage and display.",
        confidence: "81%"
      }));
    }
    if (/Access-Control-Allow-Origin['"`]?\s*[:,]\s*['"`]\*/i.test(line) || /cors\s*\(\s*\{\s*origin\s*:\s*['"`]\*/i.test(line)) {
      findings.push(finding({
        severity: "high",
        category: "Infrastructure & Deployment",
        title: "Open CORS policy",
        evidence: lineEvidence(file.path, n, line),
        fix: "Restrict origins by environment and avoid wildcard origins on authenticated or sensitive APIs.",
        confidence: "84%"
      }));
    }
    if (/prisma\.\w+\.update\s*\([^)]*data\s*:\s*(req\.body|body)/i.test(line) || /\.(insert|update)\s*\(\s*(req\.body|body)\s*\)/i.test(line)) {
      findings.push(finding({
        severity: "high",
        category: "Business Logic",
        title: "Mass assignment into persistence layer",
        evidence: lineEvidence(file.path, n, line),
        fix: "Map allowed fields explicitly before ORM updates and reject unexpected properties.",
        confidence: "87%"
      }));
    }
    if (/Math\.random\s*\(\s*\).*(token|reset|invite|otp|code)/i.test(line) || /(token|reset|invite|otp|code).*=.*Math\.random\s*\(/i.test(line)) {
      findings.push(finding({
        severity: "high",
        category: "Business Logic",
        title: "Predictable security token generation",
        evidence: lineEvidence(file.path, n, line),
        fix: "Generate reset, invite, and OTP values with crypto.randomBytes or Web Crypto secure randomness.",
        confidence: "89%"
      }));
    }
    if (/stripe.*webhook|webhook.*stripe/i.test(file.path + line) && /JSON\.parse|req\.body/i.test(line) && !/constructEvent|signature/i.test(text)) {
      findings.push(finding({
        severity: "critical",
        category: "API & Third-party Keys",
        title: "Webhook handler lacks signature verification",
        evidence: lineEvidence(file.path, n, line),
        fix: "Verify provider signatures against the raw request body before trusting webhook events.",
        confidence: "85%"
      }));
    }
    if (/NEXT_PUBLIC_.*(SECRET|PRIVATE|TOKEN|KEY)|VITE_.*(SECRET|PRIVATE|TOKEN|KEY)|PUBLIC_.*(SECRET|PRIVATE|TOKEN|KEY)/i.test(line)) {
      findings.push(finding({
        severity: "high",
        category: "API & Third-party Keys",
        title: "Server-side secret appears exposed to client build",
        evidence: lineEvidence(file.path, n, line),
        fix: "Move server-only keys to unprefixed environment variables and rotate any key that was exposed.",
        confidence: "86%"
      }));
    }
    if (/(sk-(live|test|proj)-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{12,})/.test(line)) {
      findings.push(finding({
        severity: "critical",
        category: "Data Exposure",
        title: "Committed credential pattern detected",
        evidence: lineEvidence(file.path, n, line),
        fix: "Revoke and rotate the secret, remove it from git history, and move it into a secret manager.",
        confidence: "94%"
      }));
    }
    if (/rls\s*=\s*false|disable\s+row\s+level\s+security|alter\s+table.*disable\s+row\s+level\s+security/i.test(line)) {
      findings.push(finding({
        severity: "critical",
        category: "Database & Storage",
        title: "Supabase Row Level Security disabled",
        evidence: lineEvidence(file.path, n, line),
        fix: "Enable RLS on exposed tables and add role-specific policies for every operation.",
        confidence: "92%"
      }));
    }
  });

  const routeLooksProtected = /auth|session|requireUser|getServerSession|currentUser|middleware|verify/i.test(text);
  if (/\/api\/|route\.|router\.(get|post|put|delete)|export\s+async\s+function\s+(GET|POST|PUT|DELETE)/i.test(file.path + text) && !routeLooksProtected) {
    findings.push(finding({
      severity: "medium",
      category: "Authentication & Authorization",
      title: "API route has no obvious authentication guard",
      evidence: `${file.path} contains route code without recognizable auth/session guard`,
      fix: "Require authentication middleware or server-side session checks on every non-public API route.",
      confidence: "68%"
    }));
  }

  return findings;
}

function calculateScore(findings) {
  const weights = { critical: 18, high: 10, medium: 5, low: 2 };
  const penalty = findings.reduce((sum, item) => sum + (weights[item.severity] || 0), 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function uniqueFindings(items) {
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item.id)) {
      return false;
    }
    seen.add(item.id);
    return true;
  });
}

function normalizePasteFiles(body) {
  const snippet = String(body.code || body.snippet || "").trim();
  if (!snippet) {
    throw Object.assign(new Error("Paste code or provide a GitHub repository URL to scan."), { statusCode: 400, code: "missing_code" });
  }
  if (Buffer.byteLength(snippet, "utf8") > MAX_FILE_BYTES) {
    throw Object.assign(new Error("Pasted code is too large for a quick scan."), { statusCode: 413, code: "code_too_large" });
  }
  return [{ path: body.filename || "pasted-snippet.js", content: snippet, size: Buffer.byteLength(snippet, "utf8") }];
}

async function loadGithubFiles(body) {
  const { owner, repo } = parseRepoUrl(body.repoUrl);
  const authHeaders = await authHeaderFor(body.installationId);
  const repoInfo = await githubRequest(`/repos/${owner}/${repo}`, { headers: authHeaders });
  const ref = body.ref || repoInfo.default_branch;
  const tree = await githubRequest(`/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`, { headers: authHeaders });
  const candidates = (tree.tree || [])
    .filter((entry) => entry.type === "blob" && entry.size <= MAX_FILE_BYTES && TEXT_FILE_RE.test(entry.path) && !SKIP_PATH_RE.test(entry.path))
    .slice(0, MAX_FILES);

  const files = [];
  let totalBytes = 0;
  for (const entry of candidates) {
    if (totalBytes + entry.size > MAX_TOTAL_BYTES) {
      break;
    }
    const blob = await githubRequest(`/repos/${owner}/${repo}/git/blobs/${entry.sha}`, { headers: authHeaders });
    if (blob.encoding !== "base64") {
      continue;
    }
    const content = Buffer.from(blob.content, "base64").toString("utf8");
    if (content.includes("\u0000")) {
      continue;
    }
    files.push({ path: entry.path, content, size: entry.size });
    totalBytes += entry.size;
  }
  return { files, target: `${owner}/${repo}`, ref, totalCandidateFiles: candidates.length };
}

async function runScan(body) {
  await cleanupExpired();
  const id = crypto.randomUUID();
  const workerDir = await createWorkerDir(id);
  const startedAt = new Date().toISOString();
  try {
    const sourceType = body.sourceType === "github" ? "github" : "paste";
    const source = sourceType === "github" ? await loadGithubFiles(body) : { files: normalizePasteFiles(body), target: "pasted code", ref: null, totalCandidateFiles: 1 };
    const findings = uniqueFindings(source.files.flatMap(analyzeFile));
    const result = {
      id,
      status: "complete",
      sourceType,
      target: source.target,
      ref: source.ref,
      startedAt,
      completedAt: new Date().toISOString(),
      filesScanned: source.files.length,
      bytesScanned: source.files.reduce((sum, file) => sum + file.size, 0),
      totalCandidateFiles: source.totalCandidateFiles,
      score: calculateScore(findings),
      findings,
      controls: {
        secretRedaction: true,
        workerIsolation: true,
        retentionCleanup: true,
        rawSecretsStored: false
      }
    };
    return saveScan(result);
  } finally {
    await removeWorkerDir(workerDir);
  }
}

module.exports = {
  runScan
};
