const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { authHeaderFor, githubRequest, isConfigured } = require("./_lib/github-app");
const { methodNotAllowed, normalizeError, readJson, sendJson } = require("./_lib/http");
const { buildPrSummary, findingsWithPatches } = require("./_lib/patcher");
const { getScan } = require("./_lib/storage");

async function postIssueComment({ owner, repo, issueNumber, body, authHeaders }) {
  return githubRequest(`/repos/${owner}/${repo}/issues/${issueNumber}/comments`, {
    method: "POST",
    headers: { ...authHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ body })
  });
}

async function ensurePatchBranch({ owner, repo, sha, branchName, authHeaders }) {
  try {
    await githubRequest(`/repos/${owner}/${repo}/git/refs/heads/${branchName}`, { headers: authHeaders });
    return false;
  } catch (error) {
    if (error.statusCode === 404) {
      await githubRequest(`/repos/${owner}/${repo}/git/refs`, {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha })
      });
      return true;
    }
    throw error;
  }
}

async function commitNotesFile({ owner, repo, branchName, content, authHeaders }) {
  const path = "vibeshield-fixes.md";
  let existingSha = null;
  try {
    const existing = await githubRequest(`/repos/${owner}/${repo}/contents/${path}?ref=${branchName}`, { headers: authHeaders });
    existingSha = existing.sha;
  } catch (error) {
    if (error.statusCode !== 404) throw error;
  }
  await githubRequest(`/repos/${owner}/${repo}/contents/${path}`, {
    method: "PUT",
    headers: { ...authHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({
      message: "vibeshield: add fix guidance",
      content: Buffer.from(content, "utf8").toString("base64"),
      branch: branchName,
      sha: existingSha || undefined
    })
  });
}

async function handleComment(req, res, principal) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const body = await readJson(req);
  if (!body.scanId || !body.fullName || !body.pullNumber || !body.installationId) {
    return sendJson(res, 400, {
      error: "missing_fields",
      message: "Provide scanId, fullName (owner/repo), pullNumber, and installationId."
    });
  }
  if (!isConfigured()) {
    return sendJson(res, 501, { error: "github_app_not_configured", message: "Set GITHUB_APP_ID and GITHUB_PRIVATE_KEY." });
  }
  const scan = await getScan({ scanId: body.scanId, orgId: principal.org_id });
  const authHeaders = await authHeaderFor(body.installationId);
  const [owner, repo] = String(body.fullName).split("/");
  const summary = buildPrSummary(scan);
  const comment = await postIssueComment({
    owner,
    repo,
    issueNumber: body.pullNumber,
    body: summary,
    authHeaders
  });
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "pr.comment",
    detail: { scanId: body.scanId, fullName: body.fullName, pullNumber: body.pullNumber }
  });
  return sendJson(res, 200, { ok: true, commentId: comment.id, url: comment.html_url });
}

async function handlePatch(req, res, principal) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const body = await readJson(req);
  if (!body.scanId || !body.installationId) {
    return sendJson(res, 400, { error: "missing_fields", message: "Provide scanId and installationId." });
  }
  if (!isConfigured()) {
    return sendJson(res, 501, { error: "github_app_not_configured" });
  }
  const scan = await getScan({ scanId: body.scanId, orgId: principal.org_id });
  if (!scan.target || !scan.sha) {
    return sendJson(res, 400, { error: "scan_missing_repo_metadata", message: "PR patch requires a GitHub-source scan." });
  }
  const [owner, repo] = scan.target.split("/");
  const authHeaders = await authHeaderFor(body.installationId);
  const branchName = `vibeshield/fixes-${scan.id.slice(0, 8)}`;
  const created = await ensurePatchBranch({ owner, repo, sha: scan.sha, branchName, authHeaders });
  const findings = findingsWithPatches(scan.findings.filter((finding) => !finding.suppressed));
  const guidance = [
    `# VibeShield fix guidance for scan ${scan.id}`,
    "",
    `Target: \`${scan.target}\``,
    `Score: ${scan.score}/100`,
    "",
    "Apply these patches manually after reviewing each context. VibeShield never edits source files directly."
  ];
  for (const finding of findings.slice(0, 40)) {
    guidance.push("");
    guidance.push(`## ${finding.severity.toUpperCase()} — ${finding.title}`);
    guidance.push("");
    guidance.push(`- File: \`${finding.file || "n/a"}${finding.line ? `:${finding.line}` : ""}\``);
    guidance.push(`- Rule: \`${finding.rule}\``);
    guidance.push(`- Why: ${finding.fix}`);
    guidance.push("");
    guidance.push("```");
    guidance.push(finding.patch?.body || finding.fix);
    guidance.push("```");
  }
  await commitNotesFile({ owner, repo, branchName, content: guidance.join("\n"), authHeaders });
  let pullRequest = null;
  if (body.openPullRequest !== false) {
    try {
      pullRequest = await githubRequest(`/repos/${owner}/${repo}/pulls`, {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({
          title: `VibeShield: review ${findings.length} security findings`,
          head: branchName,
          base: scan.defaultBranch || "main",
          body: buildPrSummary(scan)
        })
      });
    } catch (error) {
      if (error.statusCode !== 422) throw error;
    }
  }
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "pr.patch",
    detail: { scanId: body.scanId, branchCreated: created, pullRequestUrl: pullRequest?.html_url }
  });
  return sendJson(res, 200, {
    ok: true,
    branch: branchName,
    branchCreated: created,
    pullRequest: pullRequest ? { number: pullRequest.number, url: pullRequest.html_url } : null
  });
}

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const action = url.searchParams.get("action") || "comment";
    if (action === "comment") return await handleComment(req, res, principal);
    if (action === "patch") return await handlePatch(req, res, principal);
    return sendJson(res, 404, { error: "unknown_action" });
  } catch (error) {
    const normalized = normalizeError(error, { route: "pr", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
