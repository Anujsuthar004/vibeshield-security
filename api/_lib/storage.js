const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const storageRoot = process.env.VIBESHIELD_STORAGE_DIR || path.join(os.tmpdir(), "vibeshield-scans");
const workerRoot = process.env.VIBESHIELD_WORKER_DIR || path.join(os.tmpdir(), "vibeshield-workers");

function retentionHours() {
  const configured = Number(process.env.SCAN_RETENTION_HOURS || "24");
  if (!Number.isFinite(configured) || configured <= 0) {
    return 24;
  }
  return Math.min(configured, 24);
}

async function ensureDirs() {
  await fsp.mkdir(storageRoot, { recursive: true, mode: 0o700 });
  await fsp.mkdir(workerRoot, { recursive: true, mode: 0o700 });
}

function resultPath(scanId) {
  if (!/^[a-f0-9-]{36}$/.test(scanId)) {
    throw Object.assign(new Error("Invalid scan id."), { statusCode: 400, code: "invalid_scan_id" });
  }
  return path.join(storageRoot, `${scanId}.json`);
}

async function createWorkerDir(scanId) {
  await ensureDirs();
  return fsp.mkdtemp(path.join(workerRoot, `${scanId}-`));
}

async function removeWorkerDir(dir) {
  if (!dir || !dir.startsWith(workerRoot)) {
    return;
  }
  await fsp.rm(dir, { recursive: true, force: true });
}

async function saveScan(result) {
  await ensureDirs();
  const expiresAt = new Date(Date.now() + retentionHours() * 60 * 60 * 1000).toISOString();
  const stored = { ...result, expiresAt, retentionHours: retentionHours() };
  await fsp.writeFile(resultPath(result.id), JSON.stringify(stored, null, 2), { mode: 0o600 });
  return stored;
}

async function getScan(scanId) {
  await ensureDirs();
  const file = resultPath(scanId);
  let raw;
  try {
    raw = await fsp.readFile(file, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      throw Object.assign(new Error("Scan result not found."), { statusCode: 404, code: "scan_not_found" });
    }
    throw error;
  }
  const result = JSON.parse(raw);
  if (Date.parse(result.expiresAt) <= Date.now()) {
    await fsp.rm(file, { force: true });
    throw Object.assign(new Error("Scan result expired."), { statusCode: 410, code: "scan_expired" });
  }
  return result;
}

async function deleteScan(scanId) {
  await ensureDirs();
  await fsp.rm(resultPath(scanId), { force: true });
}

async function cleanupExpired() {
  await ensureDirs();
  const now = Date.now();
  const storageEntries = fs.existsSync(storageRoot) ? await fsp.readdir(storageRoot, { withFileTypes: true }) : [];
  for (const entry of storageEntries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) {
      continue;
    }
    const file = path.join(storageRoot, entry.name);
    try {
      const parsed = JSON.parse(await fsp.readFile(file, "utf8"));
      if (Date.parse(parsed.expiresAt) <= now) {
        await fsp.rm(file, { force: true });
      }
    } catch {
      await fsp.rm(file, { force: true });
    }
  }

  const workerEntries = fs.existsSync(workerRoot) ? await fsp.readdir(workerRoot, { withFileTypes: true }) : [];
  for (const entry of workerEntries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const dir = path.join(workerRoot, entry.name);
    const stat = await fsp.stat(dir);
    if (now - stat.mtimeMs > 60 * 60 * 1000) {
      await fsp.rm(dir, { recursive: true, force: true });
    }
  }
}

module.exports = {
  cleanupExpired,
  createWorkerDir,
  deleteScan,
  getScan,
  removeWorkerDir,
  saveScan
};
