const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { scanUrl } = require("../api/_lib/url-scan");

// Fake tokens are assembled at runtime so nothing key-shaped is committed.
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const jwt = (claims) => [b64({ alg: "HS256", typ: "JWT" }), b64(claims), "c2lnbmF0dXJlLW5vdC1yZWFs"].join(".");
const SERVICE_ROLE = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "service_role" });
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "anon" });
const STRIPE = ["sk", "live", "FAKEfakeFAKEfake00000000"].join("_");

const ROUTES = {
  "/": [
    "text/html",
    `<html><head>
      <script src="/_next/static/chunks/main.js"></script>
      <link rel="modulepreload" href="/_next/static/chunks/app.js">
      <script src="https://cdn.example.com/analytics.js"></script>
      <script id="__NEXT_DATA__" type="application/json">{"buildId":"build123"}</script>
    </head><body></body></html>`
  ],
  "/_next/static/chunks/main.js": ["application/javascript", `const supabase = createClient(url, "${ANON}");\n//# sourceMappingURL=main.js.map`],
  "/_next/static/chunks/main.js.map": ["application/json", "{}"],
  "/_next/static/chunks/app.js": ["application/javascript", `fetch("/api", { headers: { k: "${STRIPE}" } });`],
  "/_next/static/build123/_buildManifest.js": ["application/javascript", `self.__BUILD_MANIFEST={"/admin":["static/chunks/pages/admin.js"]};`],
  "/_next/static/chunks/pages/admin.js": ["application/javascript", `\nconst admin = createClient(url, "${SERVICE_ROLE}");`]
};

function startServer() {
  const requested = [];
  const server = http.createServer((req, res) => {
    requested.push(req.url);
    const route = ROUTES[req.url];
    if (!route) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "Content-Type": route[0] }).end(req.method === "HEAD" ? undefined : route[1]);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, requested, url: `http://127.0.0.1:${server.address().port}/` })));
}

test("scanUrl finds service-role keys, secrets and public source maps", async () => {
  const { server, requested, url } = await startServer();
  try {
    const result = await scanUrl(url);
    const rules = result.findings.map((f) => `${f.rule} @ ${f.file}`).sort();
    assert.deepEqual(rules, [
      "bundle.source_maps_public @ /_next/static/chunks/main.js",
      "bundle.stripe_live @ /_next/static/chunks/app.js",
      "bundle.supabase_service_role @ /_next/static/chunks/pages/admin.js"
    ]);
    const serviceRole = result.findings.find((f) => f.rule === "bundle.supabase_service_role");
    assert.equal(serviceRole.line, 2);
    assert.match(serviceRole.evidence, /project abcdefghijklmnop/);
    for (const finding of result.findings) assert.ok(!finding.evidence.includes("FAKEfake"), finding.evidence);
    assert.ok(!requested.some((r) => r.includes("analytics")), "cross-origin script must not be fetched");
    assert.equal(result.filesScanned, 4);
  } finally {
    server.close();
  }
});

test("vibeshield --url exits 1 on critical findings and rejects non-http URLs", async () => {
  const { server, url } = await startServer();
  const cli = path.join(__dirname, "..", "scripts", "cli.js");
  const run = (args) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [cli, ...args], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      child.on("close", (status) => resolve({ status, out }));
    });
  try {
    const res = await run(["--url", url, "--fail-on", "critical", "--quiet"]);
    assert.equal(res.status, 1, res.out);
    assert.match(res.out, /Supabase service-role key shipped to the browser/);
    const bad = await run(["--url", "file:///etc/passwd"]);
    assert.equal(bad.status, 2);
  } finally {
    server.close();
  }
});
