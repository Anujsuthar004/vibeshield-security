const crypto = require("node:crypto");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, readBuffer, sendJson } = require("./_lib/http");
const { verifyWebhookSignature, isConfigured } = require("./_lib/github-app");
const { runScan } = require("./_lib/scanner");

async function handleGithub(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  if (!isConfigured() || !process.env.GITHUB_WEBHOOK_SECRET) {
    return sendJson(res, 501, {
      error: "webhook_not_configured",
      message: "Set GITHUB_APP_ID, GITHUB_PRIVATE_KEY, and GITHUB_WEBHOOK_SECRET on the deployment."
    });
  }
  const rawBody = await readBuffer(req);
  const signature = req.headers["x-hub-signature-256"];
  if (!verifyWebhookSignature({ rawBody, signatureHeader: signature })) {
    return sendJson(res, 401, { error: "invalid_signature", message: "Webhook signature did not validate." });
  }
  const event = req.headers["x-github-event"];
  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return sendJson(res, 400, { error: "invalid_payload" });
  }

  if (event === "ping") {
    return sendJson(res, 200, { ok: true, message: "pong" });
  }

  if (event === "installation_repositories" || event === "installation") {
    return sendJson(res, 200, { ok: true });
  }

  if (event !== "push" && event !== "pull_request") {
    return sendJson(res, 200, { ok: true, ignored: event });
  }

  const fullName = payload?.repository?.full_name;
  const installationId = payload?.installation?.id;
  if (!fullName || !installationId) {
    return sendJson(res, 400, { error: "missing_repo_or_installation" });
  }

  const repository = await db.findOne("repositories", { full_name: fullName });
  if (!repository) {
    return sendJson(res, 202, { ok: true, queued: false, reason: "repository_not_registered" });
  }

  if (event === "pull_request" && !["opened", "synchronize", "reopened"].includes(payload.action)) {
    return sendJson(res, 200, { ok: true, ignored: payload.action });
  }

  try {
    const result = await runScan(
      {
        sourceType: "github",
        repoUrl: `https://github.com/${fullName}`,
        installationId: String(installationId),
        ref: event === "pull_request" ? payload.pull_request?.head?.ref : payload.ref?.replace(/^refs\/heads\//, ""),
        generatePatches: false,
        dependencyScan: true
      },
      { orgId: repository.org_id, userId: null }
    );
    await db.insert("audit", {
      org_id: repository.org_id,
      action: "webhook.scan",
      detail: { event, fullName, scanId: result.id, score: result.score }
    });
    return sendJson(res, 200, { ok: true, scanId: result.id, score: result.score });
  } catch (error) {
    return sendJson(res, 200, { ok: true, error: error.code || "scan_failed", message: error.message });
  }
}

function pickProvider(req) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  return url.searchParams.get("provider") || req.query?.provider || "github";
}

module.exports = async function handler(req, res) {
  try {
    const provider = pickProvider(req);
    if (provider === "github") return await handleGithub(req, res);
    return sendJson(res, 404, { error: "unknown_provider", message: "Unsupported webhook provider." });
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
