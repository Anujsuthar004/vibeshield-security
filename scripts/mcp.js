#!/usr/bin/env node
"use strict";

// VibeShield MCP server (stdio). Lets Claude Code, Cursor and other MCP clients
// scan the project they're editing and get fix instructions back.
//
//   claude mcp add vibeshield -- npx -y -p vibeshield vibeshield-mcp
//
// Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout; logs go to stderr only.

const path = require("node:path");
const readline = require("node:readline");

const { scanDirectory, summarize } = require("./cli");
const { scanUrl } = require("../api/_lib/url-scan");
const { combinedFixPrompt } = require("../api/_lib/prompts");
const { version: VERSION } = require("../package.json");

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

const TOOLS = [
  {
    name: "vibeshield_scan",
    description:
      "Scan a project directory for security issues common in AI-built Next.js / Supabase / Stripe / Clerk apps: missing auth and ownership checks, unverified webhooks, Supabase RLS gaps, leaked keys, injection. Run it after editing route handlers, server actions, migrations or env handling. Returns numbered findings with fix instructions.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project root to scan. Defaults to the server's working directory." },
        files: {
          type: "array",
          items: { type: "string" },
          description: "Only report findings in these files (paths relative to `path`). The whole project is still analyzed so cross-file checks like RLS work."
        },
        severity: { type: "string", enum: ["critical", "high", "medium", "low"], description: "Minimum severity to report. Default: low." },
        dependencies: { type: "boolean", description: "Also look up dependency CVEs on osv.dev (network). Default: false." }
      }
    }
  },
  {
    name: "vibeshield_scan_url",
    description:
      "Fetch a deployed site and scan the JavaScript it ships to browsers for leaked secret keys, Supabase service-role keys and public source maps. Only use on sites the user owns.",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string", description: "http(s) URL of the deployed app." } },
      required: ["url"]
    }
  }
];

function report(result, severity = "low") {
  const visible = result.findings.filter((f) => !f.suppressed && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[severity]);
  const header = `VibeShield scanned ${result.target} (${result.filesScanned} files). Score ${result.score}/100.`;
  if (!visible.length) return `${header}\nNo findings at ${severity} severity or above.`;
  return `${header}\n\n${combinedFixPrompt(visible)}`;
}

async function callTool(name, args = {}) {
  if (name === "vibeshield_scan") {
    const root = path.resolve(process.cwd(), args.path || ".");
    let result = await scanDirectory(root, { deps: Boolean(args.dependencies) });
    if (Array.isArray(args.files) && args.files.length) {
      const wanted = new Set(args.files.map((file) => path.relative(root, path.resolve(root, file)).split(path.sep).join("/")));
      result = summarize({ ...result, findings: result.findings.filter((f) => wanted.has(f.file)) });
    }
    return report(result, args.severity);
  }
  if (name === "vibeshield_scan_url") {
    if (!/^https?:\/\//i.test(args.url || "")) throw new Error("url must start with http:// or https://");
    const result = summarize(await scanUrl(args.url, { userAgent: `VibeShield/${VERSION} MCP` }));
    return report(result);
  }
  throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
}

async function handle(message) {
  const { id, method, params } = message;
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params?.protocolVersion || "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "vibeshield", version: VERSION },
        instructions: "Run vibeshield_scan after changing auth, data access, webhooks, Supabase migrations or env handling, and fix what it reports before finishing."
      };
    case "ping":
      return {};
    case "tools/list":
      return { tools: TOOLS };
    case "tools/call":
      try {
        const text = await callTool(params?.name, params?.arguments);
        return { content: [{ type: "text", text }] };
      } catch (error) {
        if (error.code === -32602) throw error;
        return { content: [{ type: "text", text: `VibeShield error: ${error.message}` }], isError: true };
      }
    default:
      if (id === undefined) return undefined; // notification, e.g. notifications/initialized
      throw Object.assign(new Error(`Method not found: ${method}`), { code: -32601 });
  }
}

function send(payload) {
  process.stdout.write(JSON.stringify(payload) + "\n");
}

function main() {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    if (!line.trim()) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    try {
      const result = await handle(message);
      if (message.id !== undefined && result !== undefined) send({ jsonrpc: "2.0", id: message.id, result });
    } catch (error) {
      if (message.id !== undefined) send({ jsonrpc: "2.0", id: message.id, error: { code: error.code || -32603, message: error.message } });
    }
  });
  process.stderr.write(`vibeshield MCP server ${VERSION} ready on stdio\n`);
}

if (require.main === module) main();

module.exports = { handle };
