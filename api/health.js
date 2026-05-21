const { sendJson } = require("./_lib/http");
const { isConfigured: githubConfigured } = require("./_lib/github-app");
const { isConfigured: emailConfigured } = require("./_lib/email");

module.exports = async function handler(req, res) {
  return sendJson(res, 200, {
    ok: true,
    service: "vibeshield-scanner",
    version: "0.2.0",
    githubAppConfigured: githubConfigured(),
    emailConfigured: emailConfigured(),
    databaseConfigured: Boolean(process.env.DATABASE_URL),
    features: {
      ast_analysis: true,
      dependency_cve: true,
      ignore_file: true,
      pr_patches: true,
      pdf_reports: true,
      webhooks: githubConfigured(),
      multi_tenant: true
    }
  });
};
