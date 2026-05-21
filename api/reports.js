const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, sendJson } = require("./_lib/http");
const { renderPdf } = require("./_lib/report");
const { getScan } = require("./_lib/storage");

function sendBinary(res, status, buffer, contentType, filename) {
  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Cache-Control", "no-store");
  res.statusCode = status;
  res.end(buffer);
}

async function handlePdf(req, res, principal) {
  if (req.method !== "GET") return methodNotAllowed(res, ["GET"]);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const scanId = url.searchParams.get("scanId");
  if (!scanId) return sendJson(res, 400, { error: "missing_scan_id" });
  const scan = await getScan({ scanId, orgId: principal.org_id });
  const buffer = await renderPdf(scan);
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "report.export_pdf",
    detail: { scanId }
  });
  return sendBinary(res, 200, buffer, "application/pdf", `vibeshield-${scanId}.pdf`);
}

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const action = url.searchParams.get("action") || "pdf";
    if (action === "pdf") return await handlePdf(req, res, principal);
    return sendJson(res, 404, { error: "unknown_action", message: "PDF download is the only supported report action." });
  } catch (error) {
    const normalized = normalizeError(error, { route: "reports", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
