const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const db = require("./db");

const workerRoot = process.env.VIBESHIELD_WORKER_DIR || path.join(os.tmpdir(), "vibeshield-workers");

async function ensureWorkerRoot() {
  await fsp.mkdir(workerRoot, { recursive: true, mode: 0o700 });
}

async function createWorkerDir(scanId) {
  await ensureWorkerRoot();
  return fsp.mkdtemp(path.join(workerRoot, `${scanId}-`));
}

async function removeWorkerDir(dir) {
  if (!dir || !dir.startsWith(workerRoot)) {
    return;
  }
  await fsp.rm(dir, { recursive: true, force: true });
}

async function cleanupWorkers() {
  await ensureWorkerRoot();
  const now = Date.now();
  const entries = fs.existsSync(workerRoot) ? await fsp.readdir(workerRoot, { withFileTypes: true }) : [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(workerRoot, entry.name);
    try {
      const stat = await fsp.stat(dir);
      if (now - stat.mtimeMs > 60 * 60 * 1000) {
        await fsp.rm(dir, { recursive: true, force: true });
      }
    } catch {
      // ignore
    }
  }
}

async function saveScan({ scanId, orgId, userId, target, sourceType, ref, status, score, result }) {
  await db.insert("scans", {
    id: scanId,
    org_id: orgId,
    user_id: userId,
    target,
    source_type: sourceType,
    ref: ref || null,
    status,
    score: Math.round(score || 0),
    result
  });
  return result;
}

async function getScan({ scanId, orgId }) {
  if (!/^[a-f0-9-]{36}$/.test(String(scanId))) {
    throw Object.assign(new Error("Invalid scan id."), { statusCode: 400, code: "invalid_scan_id" });
  }
  const record = await db.findOne("scans", { id: scanId });
  if (!record) {
    throw Object.assign(new Error("Scan not found."), { statusCode: 404, code: "scan_not_found" });
  }
  if (orgId && record.org_id !== orgId) {
    throw Object.assign(new Error("Scan not found."), { statusCode: 404, code: "scan_not_found" });
  }
  const result = typeof record.result === "string" ? JSON.parse(record.result) : record.result;
  return { ...result, id: record.id, org_id: record.org_id, created_at: record.created_at };
}

async function deleteScan({ scanId, orgId }) {
  const record = await db.findOne("scans", { id: scanId });
  if (!record) return;
  if (orgId && record.org_id !== orgId) {
    throw Object.assign(new Error("Scan not found."), { statusCode: 404, code: "scan_not_found" });
  }
  await db.deleteWhere("scans", { id: scanId });
}

async function listScans({ orgId, target, limit }) {
  const filter = { org_id: orgId };
  if (target) filter.target = target;
  const records = await db.findMany("scans", filter, { orderBy: "created_at", direction: "desc", limit });
  return records.map((record) => {
    const result = typeof record.result === "string" ? JSON.parse(record.result) : record.result;
    return {
      id: record.id,
      target: record.target,
      ref: record.ref,
      source_type: record.source_type,
      score: record.score,
      status: record.status,
      created_at: record.created_at,
      finding_count: Array.isArray(result?.findings) ? result.findings.length : 0,
      critical_count: Array.isArray(result?.findings) ? result.findings.filter((finding) => finding.severity === "critical").length : 0,
      suppressed_count: Array.isArray(result?.findings) ? result.findings.filter((finding) => finding.suppressed).length : 0
    };
  });
}

module.exports = {
  cleanupWorkers,
  createWorkerDir,
  deleteScan,
  getScan,
  listScans,
  removeWorkerDir,
  saveScan
};
