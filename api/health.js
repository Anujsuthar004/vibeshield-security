const { sendJson } = require("./_lib/http");
const { isConfigured: githubConfigured } = require("./_lib/github-app");

module.exports = async function handler(req, res) {
  return sendJson(res, 200, {
    ok: true,
    service: "vibeshield-scanner",
    version: "0.4.0",
    githubAppConfigured: githubConfigured(),
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
