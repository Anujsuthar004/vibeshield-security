const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, rateLimit, readJson, sendJson, logEvent } = require("./_lib/http");
const { runScan } = require("./_lib/scanner");
const { listScans } = require("./_lib/storage");

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;

async function ensureScanLimit(req, principal, res) {
  req.__principal = principal;
  // Burst limit per minute.
  const minuteLimit = await rateLimit(req, {
    scope: principal ? "scans.org.minute" : "scans.ip.minute",
    max: principal ? 12 : 3,
    windowMs: MINUTE_MS
  });
  res.setHeader("X-RateLimit-Remaining", String(minuteLimit.remaining));
  if (!minuteLimit.ok) {
    res.setHeader("Retry-After", String(Math.max(1, Math.ceil((minuteLimit.resetAt - Date.now()) / 1000))));
    sendJson(res, 429, {
      error: "rate_limited",
      message: principal ? "Too many scans this minute. Slow down a bit." : "Too many anonymous scans this minute. Sign in for higher limits."
    });
    return false;
  }
  // Hourly cap (anonymous gets a much tighter cap).
  const hourLimit = await rateLimit(req, {
    scope: principal ? "scans.org.hour" : "scans.ip.hour",
    max: principal ? 200 : 20,
    windowMs: HOUR_MS
  });
  if (!hourLimit.ok) {
    res.setHeader("Retry-After", String(Math.max(1, Math.ceil((hourLimit.resetAt - Date.now()) / 1000))));
    sendJson(res, 429, {
      error: "rate_limited",
      message: principal ? "Hourly scan budget reached for this workspace." : "Hourly anonymous scan budget reached. Sign in to keep going."
    });
    return false;
  }
  return true;
}

async function handlePost(req, res) {
  const principal = await auth.principalFromRequest(req);
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
  } else {
    logEvent("info", "scan.anonymous", { target: result.target, findings: result.findings.length, score: result.score });
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
    const normalized = normalizeError(error, { route: "scans", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
