const crypto = require("node:crypto");

function base64Url(input) {
  return Buffer.from(input).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function normalizePrivateKey(value) {
  return value ? value.replace(/\\n/g, "\n") : "";
}

function createAppJwt() {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = normalizePrivateKey(process.env.GITHUB_PRIVATE_KEY);
  if (!appId || !privateKey) {
    throw Object.assign(new Error("GitHub App credentials are not configured."), { statusCode: 501, code: "github_app_not_configured" });
  }

  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: appId }));
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
  const response = await fetch(`https://api.github.com${path}`, { ...options, headers });
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const message = typeof body === "object" && body?.message ? body.message : `GitHub request failed with ${response.status}`;
    throw Object.assign(new Error(message), { statusCode: response.status, code: "github_request_failed" });
  }
  return body;
}

async function installationToken(installationId) {
  const resolvedInstallationId = installationId || process.env.GITHUB_INSTALLATION_ID;
  if (!resolvedInstallationId) {
    throw Object.assign(new Error("A GitHub installation id is required for private repository scans."), { statusCode: 400, code: "missing_installation_id" });
  }
  const body = await githubRequest(`/app/installations/${resolvedInstallationId}/access_tokens`, {
    method: "POST",
    headers: { Authorization: `Bearer ${createAppJwt()}` }
  });
  return body.token;
}

async function authHeaderFor(installationId) {
  if (!installationId && !process.env.GITHUB_INSTALLATION_ID) {
    return {};
  }
  const token = await installationToken(installationId);
  return { Authorization: `Bearer ${token}` };
}

module.exports = {
  authHeaderFor,
  createAppJwt,
  githubRequest,
  installationToken
};
