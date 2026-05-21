const crypto = require("node:crypto");
const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, readJson, sendJson } = require("./_lib/http");

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    if (req.method === "GET") {
      const records = await db.findMany("repositories", { org_id: principal.org_id });
      return sendJson(res, 200, { repositories: records });
    }
    if (req.method === "POST") {
      const body = await readJson(req);
      const fullName = String(body.fullName || "").trim();
      const installationId = body.installationId ? String(body.installationId) : null;
      const defaultBranch = body.defaultBranch ? String(body.defaultBranch) : null;
      if (!/^[\w.-]+\/[\w.-]+$/.test(fullName)) {
        return sendJson(res, 400, { error: "invalid_full_name", message: "Provide owner/repo." });
      }
      const existing = await db.findOne("repositories", { org_id: principal.org_id, full_name: fullName });
      if (existing) {
        return sendJson(res, 200, { repository: existing });
      }
      const repository = await db.insert("repositories", {
        org_id: principal.org_id,
        full_name: fullName,
        installation_id: installationId,
        default_branch: defaultBranch,
        webhook_secret: crypto.randomBytes(24).toString("base64url")
      });
      await db.insert("audit", {
        org_id: principal.org_id,
        user_id: principal.user_id,
        action: "repository.create",
        detail: { fullName }
      });
      return sendJson(res, 201, { repository });
    }
    if (req.method === "DELETE") {
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const id = url.searchParams.get("id");
      if (!id) {
        return sendJson(res, 400, { error: "missing_id" });
      }
      const repository = await db.findOne("repositories", { id });
      if (!repository || repository.org_id !== principal.org_id) {
        return sendJson(res, 404, { error: "not_found" });
      }
      await db.deleteWhere("repositories", { id });
      return sendJson(res, 200, { ok: true });
    }
    return methodNotAllowed(res, ["GET", "POST", "DELETE"]);
  } catch (error) {
    const normalized = normalizeError(error, { route: "repositories", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
