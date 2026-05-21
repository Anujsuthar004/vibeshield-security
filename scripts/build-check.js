const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const required = [
  "index.html",
  "app.html",
  "styles.css",
  "app.js",
  "dashboard.js",
  "security.html",
  "privacy.html",
  "terms.html",
  "dpa.html",
  "404.html",
  "robots.txt",
  "sitemap.xml",
  "site.webmanifest",
  "assets/favicon.svg",
  "assets/preview.png"
];

let failed = false;

for (const file of required) {
  const target = path.join(root, file);
  if (!fs.existsSync(target)) {
    console.error(`Missing required file: ${file}`);
    failed = true;
  }
}

for (const script of ["app.js", "dashboard.js"]) {
  const source = fs.readFileSync(path.join(root, script), "utf8");
  try {
    new Function(source);
  } catch (error) {
    console.error(`${script} has a syntax error: ${error.message}`);
    failed = true;
  }
}

const apiModules = [
  "api/_lib/http.js",
  "api/_lib/db.js",
  "api/_lib/auth.js",
  "api/_lib/findings.js",
  "api/_lib/github-app.js",
  "api/_lib/ignore.js",
  "api/_lib/patcher.js",
  "api/_lib/report.js",
  "api/_lib/email.js",
  "api/_lib/storage.js",
  "api/_lib/scanner.js",
  "api/_lib/analyzers/index.js",
  "api/_lib/analyzers/generic.js",
  "api/_lib/analyzers/javascript.js",
  "api/_lib/analyzers/python.js",
  "api/_lib/analyzers/ruby.js",
  "api/_lib/analyzers/go.js",
  "api/_lib/analyzers/php.js",
  "api/_lib/analyzers/sql.js",
  "api/_lib/analyzers/dependencies.js",
  "api/health.js",
  "api/auth.js",
  "api/keys.js",
  "api/scans.js",
  "api/scans/[id].js",
  "api/reports.js",
  "api/repositories.js",
  "api/suppressions.js",
  "api/webhooks.js",
  "api/pr.js"
];

for (const modulePath of apiModules) {
  try {
    require(path.join(root, modulePath));
  } catch (error) {
    console.error(`Failed to load ${modulePath}: ${error.message}`);
    failed = true;
  }
}

const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
for (const token of ["VibeShield Security", "og:title", "site.webmanifest", "security.html", "privacy.html", "terms.html", "dpa.html", "app.html"]) {
  if (!html.includes(token)) {
    console.error(`index.html is missing publish token: ${token}`);
    failed = true;
  }
}

for (const file of ["index.html", "security.html", "privacy.html", "terms.html", "dpa.html"]) {
  const contents = fs.readFileSync(path.join(root, file), "utf8");
  if (/\bSOC\s*2\b/i.test(contents) && !/do not hold|not.*certif|roadmap|will not claim/i.test(contents)) {
    console.error(`${file} mentions SOC 2 without an honest disclaimer.`);
    failed = true;
  }
}

if (failed) {
  process.exit(1);
}

console.log("Publish checks passed.");
