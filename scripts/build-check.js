const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const required = [
  "index.html",
  "styles.css",
  "app.js",
  "security.html",
  "privacy.html",
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

const app = fs.readFileSync(path.join(root, "app.js"), "utf8");
new Function(app);

for (const modulePath of [
  "api/_lib/http.js",
  "api/_lib/github-app.js",
  "api/_lib/storage.js",
  "api/_lib/scanner.js",
  "api/health.js",
  "api/scans.js",
  "api/scans/[id].js"
]) {
  require(path.join(root, modulePath));
}

const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
for (const token of ["VibeShield Security", "og:title", "site.webmanifest", "security.html", "privacy.html"]) {
  if (!html.includes(token)) {
    console.error(`index.html is missing publish token: ${token}`);
    failed = true;
  }
}

for (const file of ["index.html", "security.html", "privacy.html", "robots.txt", "sitemap.xml", "README.md", "SECURITY.md"]) {
  const contents = fs.readFileSync(path.join(root, file), "utf8");
  for (const placeholder of ["vibeshield.dev", "hello@vibeshield.dev"]) {
    if (contents.includes(placeholder)) {
      console.error(`${file} still contains placeholder: ${placeholder}`);
      failed = true;
    }
  }
}

if (failed) {
  process.exit(1);
}

console.log("Publish checks passed.");
