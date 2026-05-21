const crypto = require("node:crypto");

const GITHUB_API = "https://api.github.com";

function base64Url(input) {
  return Buffer.from(input).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function normalizePrivateKey(value) {
  return value ? value.replace(/\\n/g, "\n") : "";
}

function isConfigured() {
  return Boolean(process.env.GITHUB_APP_ID && process.env.GITHUB_PRIVATE_KEY);
}

function createAppJwt() {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = normalizePrivateKey(process.env.GITHUB_PRIVATE_KEY);
  if (!appId || !privateKey) {
    throw Object.assign(new Error("GitHub App is not configured. Set GITHUB_APP_ID and GITHUB_PRIVATE_KEY."), {
      statusCode: 501,
      code: "github_app_not_configured"
    });
  }
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: String(appId) }));
  const data = `${header}.${payload}`;
  const signature = crypto.createSign("RSA-SHA256").update(data).sign(privateKey);
  return `${data}.${base64Url(signature)}`;
}

async function githubRequest(path, options = {}) {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "VibeShield-Security-Scanner",
    "X-GitHub-Api-Version": "2022-11-28",
    ...(options.headers || {})
  };
  const response = await fetch(`${GITHUB_API}${path}`, { ...options, headers });
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const message = body?.message || `GitHub request failed with ${response.status}`;
    const status = response.status === 404 || response.status === 403 || response.status === 401 || response.status === 422 ? response.status : 502;
    throw Object.assign(new Error(message), { statusCode: status, code: "github_request_failed" });
  }
  return body;
}

async function installationToken(installationId) {
  const resolved = installationId || process.env.GITHUB_INSTALLATION_ID;
  if (!resolved) {
    throw Object.assign(new Error("Install the VibeShield GitHub App on the target repository and pass installationId."), {
      statusCode: 400,
      code: "missing_installation_id"
    });
  }
  if (!isConfigured()) {
    throw Object.assign(new Error("GitHub App is not configured on this deployment."), {
      statusCode: 501,
      code: "github_app_not_configured"
    });
  }
  const body = await githubRequest(`/app/installations/${resolved}/access_tokens`, {
    method: "POST",
    headers: { Authorization: `Bearer ${createAppJwt()}` }
  });
  return body.token;
}

async function authHeaderFor(installationId) {
  if (!installationId && !process.env.GITHUB_INSTALLATION_ID) {
    return {};
  }
  if (!isConfigured()) {
    return {};
  }
  try {
    const token = await installationToken(installationId);
    return { Authorization: `Bearer ${token}` };
  } catch (error) {
    if (error.code === "github_app_not_configured" || error.code === "missing_installation_id") {
      return {};
    }
    throw error;
  }
}

function verifyWebhookSignature({ rawBody, signatureHeader }) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return false;
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) return false;
  const expected = `sha256=${crypto.createHmac("sha256", secret).update(rawBody).digest("hex")}`;
  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = {
  authHeaderFor,
  createAppJwt,
  githubRequest,
  installationToken,
  isConfigured,
  verifyWebhookSignature
};
