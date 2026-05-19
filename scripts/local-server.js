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

function apiResponse(res) {
  return {
    setHeader: (...args) => res.setHeader(...args),
    end: (...args) => res.end(...args),
    get statusCode() {
      return res.statusCode;
    },
    set statusCode(value) {
      res.statusCode = value;
    }
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/api/health") {
    return require("../api/health")(req, apiResponse(res));
  }
  if (url.pathname === "/api/scans") {
    return require("../api/scans")(req, apiResponse(res));
  }
  if (url.pathname.startsWith("/api/scans/")) {
    req.query = { id: decodeURIComponent(url.pathname.split("/").pop()) };
    return require("../api/scans/[id]")(req, apiResponse(res));
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
