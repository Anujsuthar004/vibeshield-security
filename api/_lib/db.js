const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const dataRoot = process.env.VIBESHIELD_DATA_DIR || path.join(os.tmpdir(), "vibeshield-data");
const tables = ["users", "orgs", "memberships", "api_keys", "sessions", "scans", "repositories", "suppressions", "audit", "rate_limits", "osv_cache"];

let pgPool = null;
let pgInitPromise = null;

function usingPg() {
  return Boolean(process.env.DATABASE_URL);
}

async function ensureFsRoot() {
  await fsp.mkdir(dataRoot, { recursive: true, mode: 0o700 });
  for (const table of tables) {
    const file = path.join(dataRoot, `${table}.json`);
    if (!fs.existsSync(file)) {
      await fsp.writeFile(file, "[]", { mode: 0o600 });
    }
  }
}

function tablePath(table) {
  if (!tables.includes(table)) {
    throw new Error(`Unknown table ${table}`);
  }
  return path.join(dataRoot, `${table}.json`);
}

async function fsRead(table) {
  await ensureFsRoot();
  const raw = await fsp.readFile(tablePath(table), "utf8");
  return JSON.parse(raw || "[]");
}

async function fsWrite(table, rows) {
  await ensureFsRoot();
  await fsp.writeFile(tablePath(table), JSON.stringify(rows, null, 2), { mode: 0o600 });
}

const fsLocks = new Map();
async function fsMutate(table, mutator) {
  const previous = fsLocks.get(table) || Promise.resolve();
  let release;
  const next = new Promise((resolve) => {
    release = resolve;
  });
  fsLocks.set(table, previous.then(() => next));
  try {
    await previous;
    const rows = await fsRead(table);
    const result = await mutator(rows);
    await fsWrite(table, rows);
    return result;
  } finally {
    release();
    if (fsLocks.get(table) === previous.then(() => next)) {
      fsLocks.delete(table);
    }
  }
}

async function pgClient() {
  if (!pgInitPromise) {
    pgInitPromise = (async () => {
      const { Pool } = require("pg");
      pgPool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.PGSSL === "disable" ? false : { rejectUnauthorized: false },
        max: 4
      });
      await runMigrations(pgPool);
    })();
  }
  await pgInitPromise;
  return pgPool;
}

async function runMigrations(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orgs (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL DEFAULT 'free',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS memberships (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (org_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      label TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      target TEXT NOT NULL,
      source_type TEXT NOT NULL,
      ref TEXT,
      status TEXT NOT NULL,
      score INTEGER NOT NULL DEFAULT 0,
      result JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS scans_org_target_idx ON scans (org_id, target, created_at DESC);
    CREATE TABLE IF NOT EXISTS repositories (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
      full_name TEXT NOT NULL,
      installation_id TEXT,
      default_branch TEXT,
      webhook_secret TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (org_id, full_name)
    );
    CREATE TABLE IF NOT EXISTS suppressions (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL,
      target TEXT NOT NULL,
      reason TEXT,
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS suppressions_org_idx ON suppressions (org_id, target);
    CREATE TABLE IF NOT EXISTS audit (
      id TEXT PRIMARY KEY,
      org_id TEXT REFERENCES orgs(id) ON DELETE SET NULL,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      detail JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit (created_at);
    CREATE TABLE IF NOT EXISTS rate_limits (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      key TEXT UNIQUE NOT NULL,
      scope TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      reset_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS rate_limits_reset_idx ON rate_limits (reset_at);
    CREATE TABLE IF NOT EXISTS osv_cache (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      cache_key TEXT UNIQUE NOT NULL,
      ecosystem TEXT NOT NULL,
      package_name TEXT NOT NULL,
      version TEXT NOT NULL,
      vulns JSONB NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS osv_cache_expires_idx ON osv_cache (expires_at);
  `);
}

function newId() {
  return crypto.randomUUID();
}

function timestamp() {
  return new Date().toISOString();
}

function rowsMatch(row, filter) {
  return Object.entries(filter).every(([key, value]) => {
    if (Array.isArray(value)) {
      return value.includes(row[key]);
    }
    return row[key] === value;
  });
}

async function insert(table, row) {
  const fullRow = { id: row.id || newId(), created_at: row.created_at || timestamp(), ...row };
  if (usingPg()) {
    const pool = await pgClient();
    const keys = Object.keys(fullRow);
    const values = keys.map((key) => (key === "result" || key === "detail" ? JSON.stringify(fullRow[key]) : fullRow[key]));
    const placeholders = keys.map((_, index) => `$${index + 1}`).join(", ");
    await pool.query(`INSERT INTO ${table} (${keys.join(", ")}) VALUES (${placeholders})`, values);
    return fullRow;
  }
  await fsMutate(table, (rows) => {
    rows.push(fullRow);
  });
  return fullRow;
}

async function update(table, filter, patch) {
  if (usingPg()) {
    const pool = await pgClient();
    const filterKeys = Object.keys(filter);
    const patchKeys = Object.keys(patch);
    const setClause = patchKeys.map((key, index) => `${key} = $${index + 1}`).join(", ");
    const whereClause = filterKeys.map((key, index) => `${key} = $${patchKeys.length + index + 1}`).join(" AND ");
    const values = [
      ...patchKeys.map((key) => (key === "result" || key === "detail" ? JSON.stringify(patch[key]) : patch[key])),
      ...filterKeys.map((key) => filter[key])
    ];
    await pool.query(`UPDATE ${table} SET ${setClause} WHERE ${whereClause}`, values);
    return;
  }
  await fsMutate(table, (rows) => {
    for (const row of rows) {
      if (rowsMatch(row, filter)) {
        Object.assign(row, patch);
      }
    }
  });
}

async function findOne(table, filter) {
  if (usingPg()) {
    const pool = await pgClient();
    const keys = Object.keys(filter);
    const whereClause = keys.map((key, index) => `${key} = $${index + 1}`).join(" AND ") || "TRUE";
    const result = await pool.query(`SELECT * FROM ${table} WHERE ${whereClause} LIMIT 1`, keys.map((key) => filter[key]));
    return result.rows[0] || null;
  }
  const rows = await fsRead(table);
  return rows.find((row) => rowsMatch(row, filter)) || null;
}

async function findMany(table, filter = {}, { orderBy = "created_at", direction = "desc", limit = 200 } = {}) {
  if (usingPg()) {
    const pool = await pgClient();
    const keys = Object.keys(filter);
    const whereClause = keys.length ? "WHERE " + keys.map((key, index) => `${key} = $${index + 1}`).join(" AND ") : "";
    const result = await pool.query(
      `SELECT * FROM ${table} ${whereClause} ORDER BY ${orderBy} ${direction === "asc" ? "ASC" : "DESC"} LIMIT ${Math.min(Number(limit) || 200, 500)}`,
      keys.map((key) => filter[key])
    );
    return result.rows;
  }
  const rows = await fsRead(table);
  const filtered = rows.filter((row) => rowsMatch(row, filter));
  filtered.sort((a, b) => {
    const av = a[orderBy] || "";
    const bv = b[orderBy] || "";
    if (av === bv) return 0;
    return direction === "asc" ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
  });
  return filtered.slice(0, Math.min(Number(limit) || 200, 500));
}

async function deleteWhere(table, filter) {
  if (usingPg()) {
    const pool = await pgClient();
    const keys = Object.keys(filter);
    const whereClause = keys.length ? "WHERE " + keys.map((key, index) => `${key} = $${index + 1}`).join(" AND ") : "WHERE FALSE";
    await pool.query(`DELETE FROM ${table} ${whereClause}`, keys.map((key) => filter[key]));
    return;
  }
  await fsMutate(table, (rows) => {
    for (let index = rows.length - 1; index >= 0; index -= 1) {
      if (rowsMatch(rows[index], filter)) {
        rows.splice(index, 1);
      }
    }
  });
}

module.exports = {
  deleteWhere,
  findMany,
  findOne,
  insert,
  newId,
  timestamp,
  update,
  usingPg
};
