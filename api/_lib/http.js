const crypto = require("node:crypto");

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 30;
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

function rateLimit(req, { keyPrefix = "ip", max = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW_MS } = {}) {
  const principalKey = req.__principal?.org_id || req.__principal?.user_id || clientIp(req);
  const key = crypto.createHash("sha256").update(`${keyPrefix}:${principalKey}`).digest("hex");
  const now = Date.now();
  const current = buckets.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > current.resetAt) {
    current.count = 0;
    current.resetAt = now + windowMs;
  }
  current.count += 1;
  buckets.set(key, current);
  return {
    ok: current.count <= max,
    resetAt: current.resetAt,
    remaining: Math.max(0, max - current.count)
  };
}

function readBuffer(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body too large"), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

async function readJson(req) {
  const buffer = await readBuffer(req);
  const raw = buffer.toString("utf8");
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw Object.assign(new Error("Invalid JSON body"), { statusCode: 400 });
  }
}

function normalizeError(error) {
  const status = Number(error.statusCode || error.status || 500);
  if (status >= 500) {
    return { status, body: { error: "internal_error", message: "Request failed. Try again or contact support." } };
  }
  return { status, body: { error: error.code || "request_error", message: error.message } };
}

module.exports = {
  clientIp,
  methodNotAllowed,
  normalizeError,
  rateLimit,
  readBuffer,
  readJson,
  sendJson
};
