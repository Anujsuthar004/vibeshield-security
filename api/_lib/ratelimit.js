const crypto = require("node:crypto");
const db = require("./db");

// In-process backstop for warm invocations on the same instance.
const memoryBuckets = new Map();

function makeKey(scope, identifier) {
  return crypto.createHash("sha256").update(`${scope}:${identifier}`).digest("hex").slice(0, 40);
}

function memoryHit(key, max, windowMs, now) {
  const current = memoryBuckets.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > current.resetAt) {
    current.count = 0;
    current.resetAt = now + windowMs;
  }
  current.count += 1;
  memoryBuckets.set(key, current);
  if (memoryBuckets.size > 4000) {
    // Cheap pruning: drop the oldest entries.
    const candidates = [...memoryBuckets.entries()].sort((a, b) => a[1].resetAt - b[1].resetAt).slice(0, 1000);
    for (const [oldKey] of candidates) memoryBuckets.delete(oldKey);
  }
  return current;
}

function clientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

/**
 * Sliding-window rate limit. Tries Postgres (durable across instances) when
 * DATABASE_URL is set, falls back to in-process memory in dev.
 */
async function check({ scope, identifier, max, windowMs }) {
  const now = Date.now();
  const key = makeKey(scope, identifier);
  if (!db.usingPg()) {
    const bucket = memoryHit(key, max, windowMs, now);
    return { ok: bucket.count <= max, remaining: Math.max(0, max - bucket.count), resetAt: bucket.resetAt };
  }
  try {
    const { findOne, update, insert, timestamp } = db;
    const existing = await findOne("rate_limits", { key });
    let count = 1;
    let resetAt = new Date(now + windowMs).toISOString();
    if (existing) {
      const previousReset = Date.parse(existing.reset_at);
      if (previousReset > now) {
        count = (existing.count || 0) + 1;
        resetAt = existing.reset_at;
        await update("rate_limits", { key }, { count, updated_at: timestamp() });
      } else {
        await update("rate_limits", { key }, { count: 1, reset_at: resetAt, updated_at: timestamp() });
      }
    } else {
      await insert("rate_limits", { key, scope, count, reset_at: resetAt, updated_at: timestamp() });
    }
    return { ok: count <= max, remaining: Math.max(0, max - count), resetAt: Date.parse(resetAt) };
  } catch (error) {
    // Never let the rate limiter take down a request — fall back to memory.
    const bucket = memoryHit(key, max, windowMs, now);
    return { ok: bucket.count <= max, remaining: Math.max(0, max - bucket.count), resetAt: bucket.resetAt };
  }
}

async function checkAndSend(res, options) {
  const result = await check(options);
  res.setHeader("X-RateLimit-Remaining", String(result.remaining));
  if (!result.ok) {
    res.setHeader("Retry-After", String(Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000))));
  }
  return result;
}

module.exports = { check, checkAndSend, clientIp, makeKey };
