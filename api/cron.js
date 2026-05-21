const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, sendJson, logEvent } = require("./_lib/http");

const AUDIT_RETENTION_DAYS = Number(process.env.AUDIT_RETENTION_DAYS || "90");

function authorized(req) {
  if (req.headers["x-vercel-cron"]) return true;
  const token = process.env.CRON_TOKEN;
  if (!token) return false;
  return req.headers.authorization === `Bearer ${token}`;
}

async function purge() {
  if (!db.usingPg()) {
    return { skipped: "no_postgres" };
  }
  const { Pool } = require("pg");
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === "disable" ? false : { rejectUnauthorized: false },
    max: 1
  });
  try {
    const cutoff = new Date(Date.now() - AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const [audit, sessions, rates, osv] = await Promise.all([
      pool.query("DELETE FROM audit WHERE created_at < $1", [cutoff]),
      pool.query("DELETE FROM sessions WHERE expires_at < NOW() - INTERVAL '1 day'"),
      pool.query("DELETE FROM rate_limits WHERE reset_at < NOW() - INTERVAL '1 hour'"),
      pool.query("DELETE FROM osv_cache WHERE expires_at < NOW()")
    ]);
    return {
      audit_deleted: audit.rowCount,
      sessions_deleted: sessions.rowCount,
      rate_limits_deleted: rates.rowCount,
      osv_cache_deleted: osv.rowCount
    };
  } finally {
    await pool.end();
  }
}

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET" && req.method !== "POST") {
      return methodNotAllowed(res, ["GET", "POST"]);
    }
    if (!authorized(req)) {
      return sendJson(res, 401, { error: "unauthorized", message: "Cron token required." });
    }
    const result = await purge();
    logEvent("info", "cron.purge", { retention_days: AUDIT_RETENTION_DAYS, ...result });
    return sendJson(res, 200, { ok: true, retention_days: AUDIT_RETENTION_DAYS, result });
  } catch (error) {
    const normalized = normalizeError(error, { route: "cron", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
