const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, rateLimit, readJson, sendJson } = require("./_lib/http");
const { runScan } = require("./_lib/scanner");
const { listScans } = require("./_lib/storage");

async function ensureScanLimit(req, principal, res) {
  req.__principal = principal;
  const limit = rateLimit(req, { keyPrefix: principal ? "org" : "ip", max: principal ? 24 : 6 });
  res.setHeader("X-RateLimit-Remaining", String(limit.remaining));
  if (!limit.ok) {
    res.setHeader("Retry-After", String(Math.ceil((limit.resetAt - Date.now()) / 1000)));
    sendJson(res, 429, { error: "rate_limited", message: "Too many scan requests. Try again shortly." });
    return false;
  }
  return true;
}

async function handlePost(req, res) {
  let principal = await auth.principalFromRequest(req);
  const body = await readJson(req);
  if (!principal) {
    if (process.env.DISALLOW_ANONYMOUS_SCANS === "true") {
      return sendJson(res, 401, {
        error: "unauthenticated",
        message: "Sign in or provide a VibeShield API key to use the scanner."
      });
    }
    if (body.sourceType === "github" && body.installationId) {
      return sendJson(res, 401, {
        error: "unauthenticated",
        message: "Private GitHub scans require authentication. Sign in or use an API key."
      });
    }
  }
  if (!(await ensureScanLimit(req, principal, res))) return;

  const result = await runScan(body, principal ? { orgId: principal.org_id, userId: principal.user_id } : {});
  if (principal) {
    await db.insert("audit", {
      org_id: principal.org_id,
      user_id: principal.user_id,
      action: "scan.create",
      detail: { id: result.id, target: result.target, score: result.score, findings: result.findings.length }
    });
  }
  return sendJson(res, 201, result);
}

async function handleList(req, res) {
  const principal = await auth.requirePrincipal(req);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const target = url.searchParams.get("target");
  const limit = Math.min(Number(url.searchParams.get("limit")) || 50, 200);
  const scans = await listScans({ orgId: principal.org_id, target, limit });
  return sendJson(res, 200, { scans });
}

module.exports = async function handler(req, res) {
  try {
    if (req.method === "POST") return await handlePost(req, res);
    if (req.method === "GET") return await handleList(req, res);
    return methodNotAllowed(res, ["GET", "POST"]);
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
