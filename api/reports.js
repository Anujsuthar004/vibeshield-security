const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { isConfigured: emailConfigured, sendReportEmail } = require("./_lib/email");
const { methodNotAllowed, normalizeError, readJson, sendJson } = require("./_lib/http");
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

async function handleEmail(req, res, principal) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  if (!emailConfigured()) {
    return sendJson(res, 501, {
      error: "email_not_configured",
      message: "Configure SMTP_HOST, SMTP_USER, SMTP_PASS, and SMTP_FROM to send email reports."
    });
  }
  const body = await readJson(req);
  if (!body.scanId || !body.to) {
    return sendJson(res, 400, { error: "missing_fields", message: "Provide { scanId, to }." });
  }
  const scan = await getScan({ scanId: body.scanId, orgId: principal.org_id });
  const pdf = await renderPdf(scan);
  const recipientList = Array.isArray(body.to) ? body.to : String(body.to).split(",").map((value) => value.trim()).filter(Boolean);
  await sendReportEmail({
    to: recipientList,
    subject: `VibeShield scan ${scan.target} — score ${scan.score}/100`,
    text: `VibeShield scan ${scan.id} for ${scan.target} completed with score ${scan.score}/100 and ${scan.activeFindingsCount} active findings. PDF attached.`,
    html: `<p>VibeShield scan <code>${scan.id}</code> for <code>${scan.target}</code> finished with score <strong>${scan.score}/100</strong> and ${scan.activeFindingsCount} active findings. PDF attached.</p>`,
    attachments: [{ filename: `vibeshield-${scan.id}.pdf`, content: pdf, contentType: "application/pdf" }]
  });
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "report.email",
    detail: { scanId: body.scanId, recipients: recipientList.length }
  });
  return sendJson(res, 200, { ok: true });
}

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const action = url.searchParams.get("action") || "pdf";
    if (action === "pdf") return await handlePdf(req, res, principal);
    if (action === "email") return await handleEmail(req, res, principal);
    return sendJson(res, 404, { error: "unknown_action" });
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
