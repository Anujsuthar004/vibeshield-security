const { methodNotAllowed, normalizeError, rateLimit, readJson, sendJson } = require("./_lib/http");
const { runScan } = require("./_lib/scanner");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return methodNotAllowed(res, ["POST"]);
  }

  const limit = rateLimit(req);
  res.setHeader("X-RateLimit-Remaining", String(limit.remaining));
  if (!limit.ok) {
    res.setHeader("Retry-After", String(Math.ceil((limit.resetAt - Date.now()) / 1000)));
    return sendJson(res, 429, { error: "rate_limited", message: "Too many scan requests. Try again shortly." });
  }

  try {
    const body = await readJson(req);
    const result = await runScan(body);
    return sendJson(res, 201, result);
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
