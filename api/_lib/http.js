const crypto = require("node:crypto");

const MAX_BODY_BYTES = 512 * 1024;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 12;
const buckets = new Map();

function sendJson(res, status, body) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.statusCode = status;
  res.end(JSON.stringify(body));
}

function methodNotAllowed(res, methods) {
  res.setHeader("Allow", methods.join(", "));
  return sendJson(res, 405, { error: "method_not_allowed", allowed: methods });
}

function clientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function rateLimit(req) {
  const key = crypto.createHash("sha256").update(clientIp(req)).digest("hex");
  const now = Date.now();
  const current = buckets.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > current.resetAt) {
    current.count = 0;
    current.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }
  current.count += 1;
  buckets.set(key, current);
  return {
    ok: current.count <= RATE_LIMIT_MAX,
    resetAt: current.resetAt,
    remaining: Math.max(0, RATE_LIMIT_MAX - current.count)
  };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let raw = "";
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body too large"), { statusCode: 413 }));
        req.destroy();
        return;
      }
      raw += chunk;
    });
    req.on("end", () => {
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(Object.assign(new Error("Invalid JSON body"), { statusCode: 400 }));
      }
    });
    req.on("error", reject);
  });
}

function normalizeError(error) {
  const status = Number(error.statusCode || error.status || 500);
  if (status >= 500) {
    return { status, body: { error: "internal_error", message: "The scanner could not complete safely." } };
  }
  return { status, body: { error: error.code || "request_error", message: error.message } };
}

module.exports = {
  methodNotAllowed,
  normalizeError,
  rateLimit,
  readJson,
  sendJson
};
