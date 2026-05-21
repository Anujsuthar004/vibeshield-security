const auth = require("./_lib/auth");
const db = require("./_lib/db");
const { methodNotAllowed, normalizeError, readJson, sendJson } = require("./_lib/http");

function publicView(record) {
  return {
    id: record.id,
    prefix: record.prefix,
    label: record.label,
    created_at: record.created_at,
    last_used_at: record.last_used_at || null
  };
}

async function listKeys(principal, res) {
  const records = await db.findMany("api_keys", { org_id: principal.org_id });
  return sendJson(res, 200, { keys: records.map(publicView) });
}

async function createKey(principal, req, res) {
  if (principal.via !== "session") {
    throw Object.assign(new Error("API keys must be created from the dashboard."), { statusCode: 403, code: "session_required" });
  }
  const body = await readJson(req);
  const label = body.label ? String(body.label).slice(0, 80) : "default";
  const { key, prefix, hash } = auth.generateApiKey();
  const record = await db.insert("api_keys", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    prefix,
    key_hash: hash,
    label
  });
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "api_key.create",
    detail: { id: record.id, label }
  });
  return sendJson(res, 201, {
    ok: true,
    secret: key,
    notice: "Save this key now. It will not be shown again.",
    key: publicView(record)
  });
}

async function deleteKey(principal, req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const id = url.searchParams.get("id");
  if (!id) {
    return sendJson(res, 400, { error: "missing_id", message: "Provide ?id=<key_id>" });
  }
  const record = await db.findOne("api_keys", { id });
  if (!record || record.org_id !== principal.org_id) {
    return sendJson(res, 404, { error: "key_not_found", message: "No such API key." });
  }
  await db.deleteWhere("api_keys", { id });
  await db.insert("audit", {
    org_id: principal.org_id,
    user_id: principal.user_id,
    action: "api_key.delete",
    detail: { id }
  });
  return sendJson(res, 200, { ok: true });
}

module.exports = async function handler(req, res) {
  try {
    const principal = await auth.requirePrincipal(req);
    if (req.method === "GET") return await listKeys(principal, res);
    if (req.method === "POST") return await createKey(principal, req, res);
    if (req.method === "DELETE") return await deleteKey(principal, req, res);
    return methodNotAllowed(res, ["GET", "POST", "DELETE"]);
  } catch (error) {
    const normalized = normalizeError(error, { route: "keys", method: req.method });
    return sendJson(res, normalized.status, normalized.body);
  }
};
