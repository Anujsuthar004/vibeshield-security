const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");

const root = path.resolve(__dirname, "..");
const port = Number(process.env.PORT || 4173);

const mime = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webmanifest": "application/manifest+json; charset=utf-8"
};

function serveFile(res, filePath, status = 200) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }
    res.writeHead(status, { "Content-Type": mime[path.extname(filePath)] || "application/octet-stream" });
    res.end(data);
  });
}

const apiRoutes = [
  { match: /^\/api\/health$/, handler: "../api/health" },
  { match: /^\/api\/auth$/, handler: "../api/auth" },
  { match: /^\/api\/keys$/, handler: "../api/keys" },
  { match: /^\/api\/scans$/, handler: "../api/scans" },
  { match: /^\/api\/scans\/.+/, handler: "../api/scans/[id]" },
  { match: /^\/api\/reports$/, handler: "../api/reports" },
  { match: /^\/api\/repositories$/, handler: "../api/repositories" },
  { match: /^\/api\/suppressions$/, handler: "../api/suppressions" },
  { match: /^\/api\/webhooks$/, handler: "../api/webhooks" },
  { match: /^\/api\/pr$/, handler: "../api/pr" },
  { match: /^\/api\/cron$/, handler: "../api/cron" }
];

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  for (const route of apiRoutes) {
    if (route.match.test(url.pathname)) {
      return require(route.handler)(req, res);
    }
  }

  const cleanPath = decodeURIComponent(url.pathname).replace(/^\/+/, "");
  const candidate = cleanPath ? path.join(root, cleanPath) : path.join(root, "index.html");
  if (!candidate.startsWith(root) || candidate.includes(`${path.sep}.git${path.sep}`) || candidate.includes(`${path.sep}.vercel${path.sep}`)) {
    return serveFile(res, path.join(root, "404.html"), 404);
  }
  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    return serveFile(res, candidate);
  }
  if (!path.extname(candidate)) {
    const htmlCandidate = `${candidate}.html`;
    if (fs.existsSync(htmlCandidate)) {
      return serveFile(res, htmlCandidate);
    }
  }
  return serveFile(res, path.join(root, "404.html"), 404);
});

server.listen(port, () => {
  console.log(`VibeShield running at http://localhost:${port}`);
});
