const { deleteScan, getScan } = require("../_lib/storage");
const { methodNotAllowed, normalizeError, sendJson } = require("../_lib/http");

module.exports = async function handler(req, res) {
  if (!["GET", "DELETE"].includes(req.method)) {
    return methodNotAllowed(res, ["GET", "DELETE"]);
  }

  try {
    const id = req.query?.id || req.url.split("/").pop();
    if (req.method === "DELETE") {
      await deleteScan(String(id));
      return sendJson(res, 200, { ok: true, deleted: String(id) });
    }
    const result = await getScan(String(id));
    return sendJson(res, 200, result);
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
