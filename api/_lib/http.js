const ratelimit = require("./ratelimit");

const MAX_BODY_BYTES = 2 * 1024 * 1024;

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
  return ratelimit.clientIp(req);
}

async function rateLimit(req, options) {
  const principal = req.__principal;
  const principalId = principal?.org_id || principal?.user_id || null;
  const identifier = principalId || clientIp(req);
  return ratelimit.check({
    scope: options.scope,
    identifier,
    max: options.max,
    windowMs: options.windowMs
  });
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

function logEvent(level, event, fields = {}) {
  try {
    const payload = { ts: new Date().toISOString(), level, event, ...fields };
    const text = JSON.stringify(payload);
    if (level === "error") console.error(text);
    else if (level === "warn") console.warn(text);
    else console.log(text);
  } catch {
    // ignore logging failures
  }
}

function normalizeError(error, context = {}) {
  const status = Number(error.statusCode || error.status || 500);
  if (status >= 500) {
    logEvent("error", "request.error", {
      ...context,
      code: error.code || "internal_error",
      message: error.message,
      stack: error.stack ? error.stack.split("\n").slice(0, 4).join(" ") : undefined
    });
    return { status, body: { error: "internal_error", message: "Request failed. Try again or open a GitHub issue." } };
  }
  logEvent("warn", "request.client_error", { ...context, code: error.code || "request_error", message: error.message, status });
  return { status, body: { error: error.code || "request_error", message: error.message } };
}

module.exports = {
  clientIp,
  logEvent,
  methodNotAllowed,
  normalizeError,
  rateLimit,
  readBuffer,
  readJson,
  sendJson
};
