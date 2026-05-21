const auth = require("./_lib/auth");
const { methodNotAllowed, normalizeError, rateLimit, readJson, sendJson, clientIp, logEvent } = require("./_lib/http");
const db = require("./_lib/db");

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
  "trashmail.com", "yopmail.com", "sharklasers.com", "throwawaymail.com", "dispostable.com",
  "fakeinbox.com", "getnada.com", "maildrop.cc", "tempinbox.com", "spambox.us",
  "tempr.email", "moakt.com", "emailondeck.com", "tempmailaddress.com", "spam4.me"
]);

function pickAction(req) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  return url.searchParams.get("action") || req.query?.action || "";
}

function emailDomain(email) {
  const at = String(email || "").lastIndexOf("@");
  return at === -1 ? "" : email.slice(at + 1).toLowerCase().trim();
}

async function applyAuthRateLimit(req, res, scope, { hourly, daily }) {
  const ip = clientIp(req);
  const ipHour = await rateLimit(req, { scope: `${scope}.ip.hour`, max: hourly, windowMs: HOUR_MS });
  res.setHeader("X-RateLimit-Remaining", String(ipHour.remaining));
  if (!ipHour.ok) {
    res.setHeader("Retry-After", String(Math.ceil((ipHour.resetAt - Date.now()) / 1000)));
    logEvent("warn", "auth.rate_limited", { scope, ip, window: "hour" });
    sendJson(res, 429, { error: "rate_limited", message: "Too many attempts. Try again in an hour." });
    return false;
  }
  const ipDay = await rateLimit(req, { scope: `${scope}.ip.day`, max: daily, windowMs: DAY_MS });
  if (!ipDay.ok) {
    res.setHeader("Retry-After", String(Math.ceil((ipDay.resetAt - Date.now()) / 1000)));
    logEvent("warn", "auth.rate_limited", { scope, ip, window: "day" });
    sendJson(res, 429, { error: "rate_limited", message: "Daily limit reached. Try again tomorrow." });
    return false;
  }
  return true;
}

async function handleSignup(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  if (!(await applyAuthRateLimit(req, res, "signup", { hourly: 3, daily: 10 }))) return;
  const body = await readJson(req);
  const domain = emailDomain(body.email);
  if (DISPOSABLE_DOMAINS.has(domain)) {
    logEvent("warn", "auth.signup.disposable_domain", { domain });
    return sendJson(res, 400, {
      error: "disposable_email",
      message: "Disposable email domains are not accepted. Use a regular email address."
    });
  }
  const { user, org } = await auth.createUser(body);
  const { session } = await auth.authenticate({ email: user.email, password: body.password });
  auth.setSessionCookie(res, session.id);
  await db.insert("audit", { user_id: user.id, org_id: org.id, action: "auth.signup", detail: { email: user.email, ip: clientIp(req) } });
  return sendJson(res, 201, {
    ok: true,
    user: { id: user.id, email: user.email, name: user.name },
    org: { id: org.id, name: org.name, plan: org.plan }
  });
}

async function handleLogin(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  if (!(await applyAuthRateLimit(req, res, "login", { hourly: 12, daily: 60 }))) return;
  const body = await readJson(req);
  const { user, session, org_id } = await auth.authenticate(body);
  auth.setSessionCookie(res, session.id);
  await db.insert("audit", { user_id: user.id, org_id, action: "auth.login", detail: { ip: clientIp(req) } });
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

async function handleCloseAccount(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);
  const principal = await auth.principalFromRequest(req);
  if (!principal || principal.via !== "session") {
    return sendJson(res, 401, { error: "session_required", message: "Sign in to close your account." });
  }
  const body = await readJson(req);
  const user = await db.findOne("users", { id: principal.user_id });
  if (!user) return sendJson(res, 404, { error: "user_not_found" });
  if (!body.confirm || String(body.confirm).trim().toLowerCase() !== user.email) {
    return sendJson(res, 400, {
      error: "confirmation_mismatch",
      message: "Type your email exactly into confirm to close the workspace."
    });
  }
  const orgs = (await db.findMany("memberships", { user_id: user.id })).map((row) => row.org_id);
  // Cascade explicitly so the file-based fallback matches Postgres FK cascades.
  for (const orgId of orgs) {
    await db.deleteWhere("scans", { org_id: orgId });
    await db.deleteWhere("api_keys", { org_id: orgId });
    await db.deleteWhere("repositories", { org_id: orgId });
    await db.deleteWhere("suppressions", { org_id: orgId });
    await db.deleteWhere("memberships", { org_id: orgId });
    await db.deleteWhere("sessions", { org_id: orgId });
    await db.deleteWhere("orgs", { id: orgId });
  }
  await db.deleteWhere("sessions", { user_id: user.id });
  await db.deleteWhere("memberships", { user_id: user.id });
  await db.deleteWhere("api_keys", { user_id: user.id });
  await db.deleteWhere("audit", { user_id: user.id });
  await db.deleteWhere("users", { id: user.id });
  auth.clearSessionCookie(res);
  logEvent("warn", "account.closed", { user_id: user.id, orgs: orgs.length });
  return sendJson(res, 200, { ok: true, orgs_deleted: orgs.length });
}

module.exports = async function handler(req, res) {
  try {
    const action = pickAction(req);
    if (action === "signup") return await handleSignup(req, res);
    if (action === "login") return await handleLogin(req, res);
    if (action === "logout") return await handleLogout(req, res);
    if (action === "me") return await handleMe(req, res);
    if (action === "close-account") return await handleCloseAccount(req, res);
    return sendJson(res, 404, { error: "unknown_action", message: "Use ?action=signup|login|logout|me|close-account" });
  } catch (error) {
    const normalized = normalizeError(error, { route: "auth", action: pickAction(req) });
    return sendJson(res, normalized.status, normalized.body);
  }
};
