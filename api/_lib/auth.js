const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const db = require("./db");

const SESSION_COOKIE = "vs_session";
const SESSION_TTL_DAYS = 14;
const API_KEY_PREFIX = "vss_";

function nowPlusDays(days) {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const result = {};
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    result[trimmed.slice(0, eq)] = decodeURIComponent(trimmed.slice(eq + 1));
  }
  return result;
}

function setSessionCookie(res, sessionId) {
  const maxAge = SESSION_TTL_DAYS * 24 * 60 * 60;
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`
  );
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
}

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function generateApiKey() {
  const raw = crypto.randomBytes(28).toString("base64url");
  const key = `${API_KEY_PREFIX}${raw}`;
  const prefix = key.slice(0, 10);
  const hash = crypto.createHash("sha256").update(key).digest("hex");
  return { key, prefix, hash };
}

function hashApiKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

async function createUser({ email, password, name }) {
  const normalizedEmail = String(email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    throw Object.assign(new Error("Enter a valid email address."), { statusCode: 400, code: "invalid_email" });
  }
  if (!password || password.length < 10) {
    throw Object.assign(new Error("Password must be at least 10 characters."), { statusCode: 400, code: "weak_password" });
  }
  const existing = await db.findOne("users", { email: normalizedEmail });
  if (existing) {
    throw Object.assign(new Error("An account with that email already exists."), { statusCode: 409, code: "email_taken" });
  }
  const user = await db.insert("users", {
    email: normalizedEmail,
    password_hash: await hashPassword(password),
    name: name ? String(name).slice(0, 80) : null
  });
  const org = await db.insert("orgs", {
    name: `${user.name || normalizedEmail.split("@")[0]}'s workspace`,
    owner_id: user.id,
    plan: "free"
  });
  await db.insert("memberships", { org_id: org.id, user_id: user.id, role: "owner" });
  return { user, org };
}

async function authenticate({ email, password }) {
  const normalizedEmail = String(email || "").trim().toLowerCase();
  const user = await db.findOne("users", { email: normalizedEmail });
  if (!user) {
    throw Object.assign(new Error("Email or password is incorrect."), { statusCode: 401, code: "invalid_credentials" });
  }
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    throw Object.assign(new Error("Email or password is incorrect."), { statusCode: 401, code: "invalid_credentials" });
  }
  const membership = await db.findOne("memberships", { user_id: user.id });
  if (!membership) {
    throw Object.assign(new Error("Account is missing a workspace."), { statusCode: 500, code: "no_workspace" });
  }
  const session = await db.insert("sessions", {
    user_id: user.id,
    org_id: membership.org_id,
    expires_at: nowPlusDays(SESSION_TTL_DAYS)
  });
  return { user, session, org_id: membership.org_id };
}

async function destroySession(sessionId) {
  if (!sessionId) return;
  await db.deleteWhere("sessions", { id: sessionId });
}

async function sessionFromCookie(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies[SESSION_COOKIE];
  if (!sessionId) return null;
  const session = await db.findOne("sessions", { id: sessionId });
  if (!session) return null;
  if (Date.parse(session.expires_at) <= Date.now()) {
    await db.deleteWhere("sessions", { id: sessionId });
    return null;
  }
  return session;
}

async function principalFromApiKey(req) {
  const header = req.headers?.authorization || "";
  let candidate = "";
  if (header.toLowerCase().startsWith("bearer ")) {
    candidate = header.slice(7).trim();
  } else if (req.headers?.["x-api-key"]) {
    candidate = String(req.headers["x-api-key"]).trim();
  }
  if (!candidate || !candidate.startsWith(API_KEY_PREFIX)) {
    return null;
  }
  const hash = hashApiKey(candidate);
  const record = await db.findOne("api_keys", { key_hash: hash });
  if (!record) return null;
  await db.update("api_keys", { id: record.id }, { last_used_at: new Date().toISOString() });
  return { user_id: record.user_id, org_id: record.org_id, via: "api_key", api_key_id: record.id };
}

async function principalFromRequest(req) {
  const apiKeyPrincipal = await principalFromApiKey(req);
  if (apiKeyPrincipal) return apiKeyPrincipal;
  const session = await sessionFromCookie(req);
  if (session) {
    return { user_id: session.user_id, org_id: session.org_id, via: "session", session_id: session.id };
  }
  return null;
}

async function requirePrincipal(req) {
  const principal = await principalFromRequest(req);
  if (!principal) {
    throw Object.assign(new Error("Sign in or provide a VibeShield API key."), { statusCode: 401, code: "unauthenticated" });
  }
  return principal;
}

async function getUserSummary(userId) {
  const user = await db.findOne("users", { id: userId });
  if (!user) return null;
  const memberships = await db.findMany("memberships", { user_id: userId });
  const orgs = [];
  for (const membership of memberships) {
    const org = await db.findOne("orgs", { id: membership.org_id });
    if (org) {
      orgs.push({ id: org.id, name: org.name, plan: org.plan, role: membership.role });
    }
  }
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    orgs
  };
}

module.exports = {
  API_KEY_PREFIX,
  SESSION_COOKIE,
  authenticate,
  clearSessionCookie,
  createUser,
  destroySession,
  generateApiKey,
  getUserSummary,
  hashApiKey,
  parseCookies,
  principalFromRequest,
  requirePrincipal,
  sessionFromCookie,
  setSessionCookie
};
