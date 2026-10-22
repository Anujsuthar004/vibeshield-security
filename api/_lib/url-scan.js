const { buildFinding } = require("./findings");
const { SECRET_PATTERNS } = require("./analyzers/generic");

// Scans what a deployed site actually ships to the browser: the page's own
// JavaScript (script tags, modulepreload links, Next.js build manifest chunks)
// for secrets, Supabase service-role keys, and publicly readable source maps.
// Only same-origin assets are fetched.

const MAX_SCRIPTS = 80;
const MAX_SCRIPT_BYTES = 6 * 1024 * 1024;
const MAX_TOTAL_BYTES = 40 * 1024 * 1024;
const TIMEOUT_MS = 15000;
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

async function get(url, { method = "GET", userAgent }) {
  const response = await fetch(url, {
    method,
    redirect: "follow",
    headers: { "User-Agent": userAgent, Accept: method === "HEAD" ? "*/*" : "text/html,application/javascript,*/*" },
    signal: AbortSignal.timeout(TIMEOUT_MS)
  });
  return response;
}

async function readText(response, limit) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > limit) return null;
  const text = await response.text();
  return Buffer.byteLength(text) > limit ? null : text;
}

function scriptUrlsFromHtml(html, base) {
  const urls = new Set();
  const attr = /<(script|link)\b[^>]*?\b(src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = attr.exec(html))) {
    const [tag, kind, , value] = match;
    if (kind.toLowerCase() === "link" && !/rel\s*=\s*["'](modulepreload|preload)["']/i.test(tag)) continue;
    if (kind.toLowerCase() === "link" && /\bas\s*=\s*["'](?!script)/i.test(tag)) continue;
    if (!/\.m?js(\?|#|$)/i.test(value) && kind.toLowerCase() === "link") continue;
    try {
      urls.add(new URL(value, base).href);
    } catch {
      // ignore malformed URLs
    }
  }
  return [...urls];
}

function inlineScripts(html) {
  const out = [];
  const re = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = re.exec(html))) {
    if (match[1].trim()) out.push(match[1]);
  }
  return out;
}

// Chunk paths for every route, so secrets that only ship on other pages are found too.
function nextManifestChunks(manifestText, origin) {
  const urls = new Set();
  const re = /["'](static\/[^"']+\.js)["']/g;
  let match;
  while ((match = re.exec(manifestText))) urls.add(new URL(`/_next/${match[1]}`, origin).href);
  return [...urls];
}

function decodeJwtPayload(token) {
  try {
    const payload = token.split(".")[1];
    return JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

function scanScript(source, label) {
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.rule === "secrets.supabase_service_role") continue; // JWTs are decoded below
    const re = new RegExp(pattern.rx.source, "g");
    let match;
    while ((match = re.exec(source))) {
      const line = lineOf(source, match.index);
      findings.push(buildFinding({
        rule: `bundle.${pattern.rule.replace(/^secrets\./, "")}`,
        severity: "critical",
        title: `${pattern.label} shipped to the browser`,
        category: "Data Exposure",
        file: label,
        line,
        evidence: `${label}:${line} ${match[0].slice(0, 8)}…[redacted]`,
        fix: "Anyone visiting the site can read this key. Revoke and rotate it now, move the call that needs it to a server route, and remove any NEXT_PUBLIC_ / VITE_ prefix from its env var.",
        ruleType: "literal_credential"
      }));
    }
  }
  let match;
  JWT_RE.lastIndex = 0;
  while ((match = JWT_RE.exec(source))) {
    const claims = decodeJwtPayload(match[0]);
    if (claims?.role !== "service_role") continue;
    const line = lineOf(source, match.index);
    findings.push(buildFinding({
      rule: "bundle.supabase_service_role",
      severity: "critical",
      title: "Supabase service-role key shipped to the browser",
      category: "Data Exposure",
      file: label,
      line,
      evidence: `${label}:${line} JWT with role "service_role"${claims.ref ? ` for project ${claims.ref}` : ""}`,
      fix: "The service-role key bypasses every RLS policy, and anyone can copy it from your JavaScript. Rotate the JWT secret in Supabase now, use the anon key in client code, and keep service-role calls in server routes.",
      references: ["https://supabase.com/docs/guides/api/api-keys"],
      ruleType: "literal_credential",
      signal: 4
    }));
  }
  return findings;
}

async function scanUrl(target, { userAgent = "VibeShield", onProgress = () => {} } = {}) {
  const started = Date.now();
  const pageUrl = new URL(target);
  if (!/^https?:$/.test(pageUrl.protocol)) throw new Error("Only http(s) URLs can be scanned.");

  const page = await get(pageUrl.href, { userAgent });
  if (!page.ok) throw new Error(`${pageUrl.href} returned HTTP ${page.status}`);
  const finalUrl = new URL(page.url || pageUrl.href);
  const origin = finalUrl.origin;
  const html = (await readText(page, MAX_SCRIPT_BYTES)) || "";

  const findings = [];
  inlineScripts(html).forEach((script, index) => findings.push(...scanScript(script, `${finalUrl.pathname} (inline script ${index + 1})`)));

  const queue = scriptUrlsFromHtml(html, finalUrl).filter((url) => new URL(url).origin === origin);
  // Next.js lists every route's chunks in _buildManifest.js; queue it even if this page didn't.
  const buildId = html.match(/"buildId"\s*:\s*"([^"]+)"/)?.[1] || html.match(/\/_next\/static\/([^/"]+)\/_(?:ssg|build)Manifest\.js/)?.[1];
  if (buildId) queue.push(new URL(`/_next/static/${buildId}/_buildManifest.js`, origin).href);
  const seen = new Set();
  let totalBytes = 0;
  let scriptsScanned = 0;
  const sourceMaps = [];

  while (queue.length && scriptsScanned < MAX_SCRIPTS && totalBytes < MAX_TOTAL_BYTES) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);
    let text;
    try {
      const response = await get(url, { userAgent });
      if (!response.ok) continue;
      text = await readText(response, MAX_SCRIPT_BYTES);
    } catch {
      continue;
    }
    if (text == null) continue;
    scriptsScanned += 1;
    totalBytes += Buffer.byteLength(text);
    const label = new URL(url).pathname;
    onProgress(label);
    findings.push(...scanScript(text, label));

    if (/\/_buildManifest\.js$/.test(label)) {
      for (const chunk of nextManifestChunks(text, origin)) if (!seen.has(chunk)) queue.push(chunk);
    }
    const map = text.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m);
    if (map && !map[1].startsWith("data:")) sourceMaps.push({ script: label, url: new URL(map[1], url).href });
  }

  const exposedMaps = [];
  for (const map of sourceMaps.slice(0, 10)) {
    try {
      const response = await get(map.url, { method: "HEAD", userAgent });
      if (response.ok) exposedMaps.push(map);
    } catch {
      // unreachable map is the good outcome
    }
  }
  if (exposedMaps.length) {
    findings.push(buildFinding({
      rule: "bundle.source_maps_public",
      severity: "medium",
      title: `Production source maps are publicly downloadable (${exposedMaps.length} found)`,
      category: "Data Exposure",
      file: exposedMaps[0].script,
      line: null,
      evidence: exposedMaps.map((map) => new URL(map.url).pathname).join(", "),
      fix: "Source maps hand anyone your original source code, comments included. Set productionBrowserSourceMaps: false (Next.js) or build.sourcemap: false / 'hidden' (Vite), or upload them to your error tracker without serving them.",
      ruleType: "inference",
      signal: 10
    }));
  }

  return {
    target: finalUrl.host,
    url: finalUrl.href,
    filesScanned: scriptsScanned,
    bytesScanned: totalBytes,
    durationMs: Date.now() - started,
    findings
  };
}

module.exports = { decodeJwtPayload, scanScript, scanUrl, scriptUrlsFromHtml };
