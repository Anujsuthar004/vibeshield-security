const auth = require("../_lib/auth");
const db = require("../_lib/db");
const { methodNotAllowed, normalizeError, sendJson } = require("../_lib/http");
const { deleteScan, getScan } = require("../_lib/storage");

function parseSegments(req) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const parts = url.pathname.split("/").filter(Boolean);
  const scanIndex = parts.indexOf("scans");
  return parts.slice(scanIndex + 1);
}

async function handleSuppress(req, res, scanId, principal) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const findingId = url.searchParams.get("finding");
  if (!findingId) {
    return sendJson(res, 400, { error: "missing_finding", message: "Provide ?finding=<id>" });
  }
  const scan = await getScan({ scanId, orgId: principal.org_id });
  const finding = (scan.findings || []).find((entry) => entry.id === findingId);
  if (!finding) {
    return sendJson(res, 404, { error: "finding_not_found", message: "Finding not in this scan." });
  }
  const url2 = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const reason = url2.searchParams.get("reason") || "Suppressed via dashboard";
  await db.insert("suppressions", {
    org_id: principal.org_id,
    finding_id: findingId,
    target: scan.target,
    reason,
    created_by: principal.user_id
  });
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "finding.suppress",
    detail: { scanId, findingId, reason }
  });
  return sendJson(res, 200, { ok: true });
}

async function handleDiff(req, res, scanId, principal) {
  if (req.method !== "GET") return methodNotAllowed(res, ["GET"]);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const against = url.searchParams.get("against");
  if (!against) {
    return sendJson(res, 400, { error: "missing_against", message: "Provide ?against=<scan_id>" });
  }
  const current = await getScan({ scanId, orgId: principal.org_id });
  const previous = await getScan({ scanId: against, orgId: principal.org_id });
  const currentIds = new Set(current.findings.map((finding) => finding.id));
  const previousIds = new Set(previous.findings.map((finding) => finding.id));
  const added = current.findings.filter((finding) => !previousIds.has(finding.id));
  const removed = previous.findings.filter((finding) => !currentIds.has(finding.id));
  const persisted = current.findings.filter((finding) => previousIds.has(finding.id));
  return sendJson(res, 200, {
    current: { id: current.id, target: current.target, ref: current.ref, score: current.score, created_at: current.created_at },
    previous: { id: previous.id, target: previous.target, ref: previous.ref, score: previous.score, created_at: previous.created_at },
    diff: {
      added,
      removed,
      persisted,
      score_delta: current.score - previous.score
    }
  });
}

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    const segments = parseSegments(req);
    const scanId = segments[0];
    if (!scanId) {
      return sendJson(res, 400, { error: "missing_id", message: "Scan id required." });
    }
    if (segments[1] === "suppress") {
      return await handleSuppress(req, res, scanId, principal);
    }
    if (segments[1] === "diff") {
      return await handleDiff(req, res, scanId, principal);
    }
    if (req.method === "DELETE") {
      await deleteScan({ scanId, orgId: principal.org_id });
      await db.insert("audit", {
        org_id: principal.org_id,
        user_id: principal.user_id,
        action: "scan.delete",
        detail: { id: scanId }
      });
      return sendJson(res, 200, { ok: true, deleted: scanId });
    }
    if (req.method === "GET") {
      const scan = await getScan({ scanId, orgId: principal.org_id });
      return sendJson(res, 200, scan);
    }
    return methodNotAllowed(res, ["GET", "DELETE"]);
  } catch (error) {
    const normalized = normalizeError(error, { route: "[id]", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
