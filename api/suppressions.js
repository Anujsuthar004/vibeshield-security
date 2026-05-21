const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, readJson, sendJson } = require("./_lib/http");

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    if (req.method === "GET") {
      const records = await db.findMany("suppressions", { org_id: principal.org_id });
      return sendJson(res, 200, { suppressions: records });
    }
    if (req.method === "POST") {
      const body = await readJson(req);
      const findingId = String(body.findingId || "").trim();
      const target = String(body.target || "*");
      if (!findingId) {
        return sendJson(res, 400, { error: "missing_finding_id" });
      }
      const record = await db.insert("suppressions", {
        org_id: principal.org_id,
        finding_id: findingId,
        target,
        reason: body.reason ? String(body.reason).slice(0, 240) : "",
        created_by: principal.user_id
      });
      return sendJson(res, 201, { suppression: record });
    }
    if (req.method === "DELETE") {
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const id = url.searchParams.get("id");
      if (!id) return sendJson(res, 400, { error: "missing_id" });
      const record = await db.findOne("suppressions", { id });
      if (!record || record.org_id !== principal.org_id) return sendJson(res, 404, { error: "not_found" });
      await db.deleteWhere("suppressions", { id });
      return sendJson(res, 200, { ok: true });
    }
    return methodNotAllowed(res, ["GET", "POST", "DELETE"]);
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
