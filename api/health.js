const { sendJson } = require("./_lib/http");

module.exports = async function handler(req, res) {
  return sendJson(res, 200, {
    ok: true,
    service: "vibeshield-scanner",
    githubAppConfigured: Boolean(process.env.GITHUB_APP_ID && process.env.GITHUB_PRIVATE_KEY),
    maxRetentionHours: 24
  });
};
