const auth = require("./_lib/auth");
const { methodNotAllowed, normalizeError, rateLimit, readJson, sendJson } = require("./_lib/http");
const db = require("./_lib/db");

function pickAction(req) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  return url.searchParams.get("action") || req.query?.action || "";
}

async function handleSignup(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const limit = rateLimit(req, { keyPrefix: "auth", max: 6 });
  if (!limit.ok) {
    return sendJson(res, 429, { error: "rate_limited", message: "Too many auth attempts. Try again shortly." });
  }
  const body = await readJson(req);
  const { user, org } = await auth.createUser(body);
  const { session } = await auth.authenticate({ email: user.email, password: body.password });
  auth.setSessionCookie(res, session.id);
  await db.insert("audit", { user_id: user.id, org_id: org.id, action: "auth.signup", detail: { email: user.email } });
  return sendJson(res, 201, {
    ok: true,
    user: { id: user.id, email: user.email, name: user.name },
    org: { id: org.id, name: org.name, plan: org.plan }
  });
}

async function handleLogin(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const limit = rateLimit(req, { keyPrefix: "auth", max: 10 });
  if (!limit.ok) {
    return sendJson(res, 429, { error: "rate_limited", message: "Too many login attempts." });
  }
  const body = await readJson(req);
  const { user, session, org_id } = await auth.authenticate(body);
  auth.setSessionCookie(res, session.id);
  await db.insert("audit", { user_id: user.id, org_id, action: "auth.login" });
  return sendJson(res, 200, { ok: true, user: { id: user.id, email: user.email, name: user.name } });
}

async function handleLogout(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const session = await auth.sessionFromCookie(req);
  if (session) {
    await auth.destroySession(session.id);
  }
  auth.clearSessionCookie(res);
  return sendJson(res, 200, { ok: true });
}

async function handleMe(req, res) {
  if (req.method !== "GET") return methodNotAllowed(res, ["GET"]);
  const principal = await auth.principalFromRequest(req);
  if (!principal) {
    return sendJson(res, 200, { ok: true, authenticated: false });
  }
  const summary = await auth.getUserSummary(principal.user_id);
  return sendJson(res, 200, {
    ok: true,
    authenticated: true,
    via: principal.via,
    active_org_id: principal.org_id,
    user: summary
  });
}

module.exports = async function handler(req, res) {
  try {
    const action = pickAction(req);
    if (action === "signup") return await handleSignup(req, res);
    if (action === "login") return await handleLogin(req, res);
    if (action === "logout") return await handleLogout(req, res);
    if (action === "me") return await handleMe(req, res);
    return sendJson(res, 404, { error: "unknown_action", message: "Use ?action=signup|login|logout|me" });
  } catch (error) {
    const normalized = normalizeError(error);
    return sendJson(res, normalized.status, normalized.body);
  }
};
