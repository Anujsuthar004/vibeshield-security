const crypto = require("node:crypto");
const { authHeaderFor, githubRequest, isConfigured } = require("./github-app");
const { analyzeFiles } = require("./analyzers");
const { analyzeFiles: analyzeDependencies } = require("./analyzers/dependencies");
const { applySuppressions, loadOrgSuppressions, parseIgnoreFile } = require("./ignore");
const { calculateScore, uniqueFindings } = require("./findings");
const { findingsWithPatches } = require("./patcher");
const { withFixPrompts } = require("./prompts");
const { cleanupWorkers, createWorkerDir, removeWorkerDir, saveScan } = require("./storage");

const MAX_FILES = 200;
const MAX_FILE_BYTES = 160 * 1024;
const MAX_TOTAL_BYTES = 4 * 1024 * 1024;
const TEXT_FILE_RE = /\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|java|cs|rs|sql|prisma|json|env|yml|yaml|toml|html|vue|svelte|gemfile|gemfile\.lock|lock|mod|sum)$/i;
const ALWAYS_INCLUDE = new Set(["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "poetry.lock", "Gemfile", "Gemfile.lock", "go.mod", "go.sum", "composer.lock", ".vibeshield.ignore"]);
const SKIP_PATH_RE = /(^|\/)(node_modules|dist|build|coverage|\.next|\.git|vendor|target|__pycache__)(\/|$)/;

function parseRepoUrl(repoUrl) {
  const match = String(repoUrl || "").match(/^https:\/\/github\.com\/([^/\s]+)\/([^/\s#?]+)(?:[/?#].*)?$/i);
  if (!match) {
    throw Object.assign(new Error("Use a full GitHub repository URL, for example https://github.com/acme/app."), {
      statusCode: 400,
      code: "invalid_repo_url"
    });
  }
  return { owner: match[1], repo: match[2].replace(/\.git$/i, "") };
}

function shouldInclude(entry) {
  const base = entry.path.split("/").pop();
  if (ALWAYS_INCLUDE.has(base)) return true;
  if (SKIP_PATH_RE.test(entry.path)) return false;
  return TEXT_FILE_RE.test(entry.path);
}

function normalizePasteFiles(body) {
  const snippet = String(body.code || body.snippet || "").trim();
  if (!snippet) {
    throw Object.assign(new Error("Paste code or provide a GitHub repository URL to scan."), {
      statusCode: 400,
      code: "missing_code"
    });
  }
  if (Buffer.byteLength(snippet, "utf8") > MAX_FILE_BYTES) {
    throw Object.assign(new Error("Pasted code is too large for a quick scan."), {
      statusCode: 413,
      code: "code_too_large"
    });
  }
  return {
    files: [{ path: body.filename || "pasted-snippet.js", content: snippet, size: Buffer.byteLength(snippet, "utf8") }],
    target: "pasted code",
    ref: null,
    totalCandidateFiles: 1,
    truncated: false
  };
}

async function loadGithubFiles(body) {
  const { owner, repo } = parseRepoUrl(body.repoUrl);
  const authHeaders = await authHeaderFor(body.installationId);
  const isAuthed = Boolean(authHeaders.Authorization);
  let repoInfo;
  try {
    repoInfo = await githubRequest(`/repos/${owner}/${repo}`, { headers: authHeaders });
  } catch (error) {
    if (error.statusCode === 404) {
      const message = isAuthed
        ? `Repository ${owner}/${repo} is not visible to the GitHub App installation. Add it to the install access list.`
        : `Repository ${owner}/${repo} is not public. Install the VibeShield GitHub App and pass installationId to scan private repos.`;
      throw Object.assign(new Error(message), { statusCode: 404, code: "repo_not_accessible" });
    }
    if (error.statusCode === 403 || error.statusCode === 401) {
      throw Object.assign(new Error("GitHub denied repository access for this scan. Re-install the GitHub App on the repository."), {
        statusCode: 403,
        code: "repo_access_denied"
      });
    }
    throw error;
  }
  const ref = body.ref || repoInfo.default_branch;
  const tree = await githubRequest(`/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`, { headers: authHeaders });
  const blobs = (tree.tree || []).filter((entry) => entry.type === "blob" && entry.size <= MAX_FILE_BYTES && shouldInclude(entry));
  const candidates = blobs.slice(0, MAX_FILES);
  const files = [];
  let totalBytes = 0;
  for (const entry of candidates) {
    if (totalBytes + entry.size > MAX_TOTAL_BYTES) break;
    const blob = await githubRequest(`/repos/${owner}/${repo}/git/blobs/${entry.sha}`, { headers: authHeaders });
    if (blob.encoding !== "base64") continue;
    const content = Buffer.from(blob.content, "base64").toString("utf8");
    if (content.includes("\u0000")) continue;
    files.push({ path: entry.path, content, size: entry.size });
    totalBytes += entry.size;
  }
  return {
    files,
    target: `${owner}/${repo}`,
    ref,
    sha: tree.sha,
    totalCandidateFiles: blobs.length,
    truncated: blobs.length > files.length,
    githubAuthenticated: isAuthed,
    defaultBranch: repoInfo.default_branch
  };
}

async function runScan(body, context = {}) {
  await cleanupWorkers();
  const scanId = crypto.randomUUID();
  const workerDir = await createWorkerDir(scanId);
  const startedAt = new Date().toISOString();
  try {
    const sourceType = body.sourceType === "github" ? "github" : "paste";
    const source = sourceType === "github" ? await loadGithubFiles(body) : normalizePasteFiles(body);
    const ignoreFile = source.files.find((file) => file.path === ".vibeshield.ignore" || file.path.endsWith("/.vibeshield.ignore"));
    const ignoreRules = ignoreFile ? parseIgnoreFile(ignoreFile.content) : [];
    const filesToScan = source.files.filter((file) => !ignoreRules.some((rule) => rule.kind === "path" && rule.regex.test(file.path)));

    const codeFindings = uniqueFindings(analyzeFiles(filesToScan));
    let depFindings = [];
    if (body.dependencyScan !== false) {
      depFindings = await analyzeDependencies(filesToScan, { enabled: body.dependencyScan !== false });
    }

    const orgSuppressions = await loadOrgSuppressions(context.orgId);
    const finalFindings = applySuppressions({
      findings: [...codeFindings, ...depFindings],
      ignoreRules,
      orgSuppressions,
      target: source.target
    });

    const withPatches = withFixPrompts(body.generatePatches ? findingsWithPatches(finalFindings) : finalFindings);
    const activeFindings = withPatches.filter((finding) => !finding.suppressed);

    const result = {
      id: scanId,
      org_id: context.orgId || null,
      status: "complete",
      sourceType,
      target: source.target,
      ref: source.ref || null,
      sha: source.sha || null,
      defaultBranch: source.defaultBranch || null,
      githubAuthenticated: source.githubAuthenticated || false,
      startedAt,
      completedAt: new Date().toISOString(),
      filesScanned: filesToScan.length,
      bytesScanned: filesToScan.reduce((sum, file) => sum + (file.size || 0), 0),
      totalCandidateFiles: source.totalCandidateFiles,
      truncated: source.truncated || false,
      ignoreRulesApplied: ignoreRules.length,
      score: calculateScore(withPatches),
      findings: withPatches,
      activeFindingsCount: activeFindings.length,
      suppressedFindingsCount: withPatches.length - activeFindings.length,
      controls: {
        secretRedaction: true,
        workerIsolation: true,
        retentionCleanup: true,
        rawSourceStored: false,
        astAnalysis: true,
        dependencyScan: body.dependencyScan !== false,
        patchSuggestions: Boolean(body.generatePatches),
        githubAppConfigured: isConfigured()
      }
    };

    if (context.orgId) {
      await saveScan({
        scanId,
        orgId: context.orgId,
        userId: context.userId,
        target: source.target,
        sourceType,
        ref: source.ref,
        status: result.status,
        score: result.score,
        result
      });
    }
    return result;
  } finally {
    await removeWorkerDir(workerDir);
  }
}

module.exports = {
  parseRepoUrl,
  runScan
};
