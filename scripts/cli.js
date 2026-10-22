#!/usr/bin/env node
/* eslint-disable no-console */
"use strict";

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const { analyzeFiles } = require("../api/_lib/analyzers");
const { analyzeFiles: analyzeDependencies } = require("../api/_lib/analyzers/dependencies");
const { applySuppressions, parseIgnoreFile } = require("../api/_lib/ignore");
const { calculateScore, uniqueFindings } = require("../api/_lib/findings");
const { combinedFixPrompt, withFixPrompts } = require("../api/_lib/prompts");
const { scanUrl } = require("../api/_lib/url-scan");
const { version: VERSION } = require("../package.json");

const MAX_FILE_BYTES = 200 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 400;
const TEXT_FILE_RE = /\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|java|cs|rs|sql|prisma|json|env|yml|yaml|toml|html|vue|svelte)$/i;
const ALWAYS_INCLUDE = new Set([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "Pipfile.lock",
  "poetry.lock",
  "Gemfile",
  "Gemfile.lock",
  "go.mod",
  "go.sum",
  "composer.lock",
  ".vibeshield.ignore"
]);
const SKIP_DIR_RE = /(^|\/)(node_modules|dist|build|coverage|\.next|\.git|\.turbo|\.vercel|vendor|target|__pycache__|\.cache)(\/|$)/;

function parseArgs(argv) {
  const args = {
    path: ".",
    format: "pretty",
    severity: "low",
    failOn: null,
    output: null,
    deps: true,
    quiet: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.format = "json";
    } else if (arg === "--sarif") {
      args.format = "sarif";
    } else if (arg === "--fix-prompt") {
      args.format = "prompt";
    } else if (arg === "--quiet" || arg === "-q") {
      args.quiet = true;
    } else if (arg === "--no-deps") {
      args.deps = false;
    } else if (arg === "--output" || arg === "-o") {
      args.output = argv[++i];
    } else if (arg === "--fail-on") {
      args.failOn = argv[++i];
    } else if (arg === "--severity") {
      args.severity = argv[++i];
    } else if (arg === "--staged") {
      args.staged = true;
    } else if (arg === "--install-hook") {
      args.installHook = true;
    } else if (arg === "--url") {
      args.url = argv[++i];
    } else if (!arg.startsWith("-")) {
      args.path = arg;
      args.pathGiven = true;
    }
  }
  return args;
}

function printHelp() {
  console.log(`vibeshield — local security scanner for the Next.js + Supabase + Stripe + Clerk stack.

Usage: vibeshield [path] [options]

Options:
  --json              Output JSON
  --sarif             Output SARIF 2.1.0 (for GitHub Code Scanning)
  --fix-prompt        Output one prompt covering every finding, to paste into Cursor / Claude Code
  --output, -o <f>    Write output to file instead of stdout
  --severity <lvl>    Minimum severity to show: critical | high | medium | low (default: low)
  --fail-on <lvl>     Exit non-zero if any finding meets or exceeds severity
  --url <url>         Scan a deployed site's public JavaScript for leaked keys and source maps
                      (add a path too to scan the code and the site together)
  --staged            Only report findings in files staged for commit (for pre-commit hooks)
  --install-hook      Install a git pre-commit hook that runs --staged --fail-on high
  --no-deps           Skip dependency CVE scan (faster, no network)
  --quiet, -q         Suppress informational output
  -h, --help          Show this help

Examples:
  vibeshield .
  vibeshield ./app --fail-on high
  vibeshield --url https://myapp.vercel.app
  vibeshield --install-hook
  vibeshield --sarif -o vibeshield.sarif --fail-on critical
  vibeshield --fix-prompt --severity high | pbcopy
`);
}

async function walk(root) {
  const files = [];
  let totalBytes = 0;

  async function visit(current) {
    if (files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await fsp.readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const relative = path.relative(root, fullPath);
      if (SKIP_DIR_RE.test("/" + relative + "/")) continue;
      if (entry.isDirectory()) {
        await visit(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const baseName = entry.name;
      if (!ALWAYS_INCLUDE.has(baseName) && !TEXT_FILE_RE.test(baseName)) continue;
      let stat;
      try {
        stat = await fsp.stat(fullPath);
      } catch {
        continue;
      }
      if (stat.size > MAX_FILE_BYTES) continue;
      if (totalBytes + stat.size > MAX_TOTAL_BYTES) continue;
      let content;
      try {
        content = await fsp.readFile(fullPath, "utf8");
      } catch {
        continue;
      }
      if (content.includes("\u0000")) continue;
      files.push({ path: relative.split(path.sep).join("/"), content, size: stat.size });
      totalBytes += stat.size;
      if (files.length >= MAX_FILES) return;
    }
  }

  await visit(root);
  return { files, totalBytes };
}

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
function meetsSeverity(finding, threshold) {
  return SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold];
}

function severityColor(severity) {
  switch (severity) {
    case "critical": return "\x1b[91m"; // bright red
    case "high": return "\x1b[31m"; // red
    case "medium": return "\x1b[33m"; // yellow
    case "low": return "\x1b[36m"; // cyan
    default: return "\x1b[37m";
  }
}

function reset() {
  return process.stdout.isTTY ? "\x1b[0m" : "";
}

function colorize(text, severity) {
  if (!process.stdout.isTTY) return text;
  return `${severityColor(severity)}${text}${reset()}`;
}

function renderPretty(result, args) {
  const lines = [];
  lines.push(`VibeShield scan — score ${result.score}/100`);
  lines.push(`Target: ${result.target}`);
  lines.push(`Files scanned: ${result.filesScanned}`);
  lines.push(`Findings: ${result.activeFindingsCount} active, ${result.suppressedFindingsCount} suppressed`);
  lines.push("");

  const visible = result.findings.filter((finding) => !finding.suppressed && meetsSeverity(finding, args.severity));
  if (!visible.length) {
    lines.push("No findings at this severity threshold.");
    return lines.join("\n");
  }

  const grouped = visible.reduce((acc, finding) => {
    (acc[finding.severity] = acc[finding.severity] || []).push(finding);
    return acc;
  }, {});

  for (const severity of ["critical", "high", "medium", "low"]) {
    const bucket = grouped[severity];
    if (!bucket?.length) continue;
    lines.push(colorize(`[${severity.toUpperCase()}] ${bucket.length}`, severity));
    for (const finding of bucket) {
      const loc = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "general";
      lines.push(`  ${colorize("•", severity)} ${finding.title}`);
      lines.push(`      ${loc}  (${finding.rule}, ${finding.confidence})`);
      lines.push(`      fix: ${finding.fix}`);
    }
    lines.push("");
  }
  lines.push("Get a paste-ready prompt for Cursor / Claude Code: vibeshield --fix-prompt" + (args.severity !== "low" ? ` --severity ${args.severity}` : ""));
  return lines.join("\n");
}

function renderSarif(result) {
  const rules = new Map();
  const results = [];
  for (const finding of result.findings) {
    if (finding.suppressed) continue;
    if (!rules.has(finding.rule)) {
      rules.set(finding.rule, {
        id: finding.rule,
        name: finding.rule.replace(/\W+/g, "_"),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.fix },
        helpUri: finding.references?.[0],
        properties: {
          category: finding.category,
          confidence: finding.confidence,
          rule_type: finding.rule_type
        }
      });
    }
    results.push({
      ruleId: finding.rule,
      level: finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "note",
      message: { text: finding.title + " — " + finding.fix },
      properties: finding.fix_prompt ? { fixPrompt: finding.fix_prompt } : undefined,
      locations: finding.file
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: finding.line ? { startLine: finding.line } : undefined
              }
            }
          ]
        : []
    });
  }
  return JSON.stringify(
    {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "VibeShield",
              version: VERSION,
              informationUri: "https://github.com/Anujsuthar004/vibeshield-security",
              rules: [...rules.values()]
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}

async function scanDirectory(root, { deps = true } = {}) {
  const started = Date.now();
  const { files, totalBytes } = await walk(root);

  const ignoreFile = files.find((f) => f.path === ".vibeshield.ignore" || f.path.endsWith("/.vibeshield.ignore"));
  const ignoreRules = ignoreFile ? parseIgnoreFile(ignoreFile.content) : [];
  const filesToScan = files.filter((file) => !ignoreRules.some((rule) => rule.kind === "path" && rule.regex.test(file.path)));

  const codeFindings = uniqueFindings(analyzeFiles(filesToScan));
  let depFindings = [];
  if (deps) {
    depFindings = await analyzeDependencies(filesToScan, { enabled: true });
  }
  const finalFindings = applySuppressions({
    findings: [...codeFindings, ...depFindings],
    ignoreRules,
    orgSuppressions: [],
    target: path.basename(root)
  });

  return summarize({
    target: path.basename(root),
    filesScanned: filesToScan.length,
    bytesScanned: totalBytes,
    durationMs: Date.now() - started,
    findings: finalFindings
  });
}

function summarize({ findings, ...rest }) {
  const withPrompts = withFixPrompts(findings);
  return {
    ...rest,
    score: calculateScore(withPrompts),
    findings: withPrompts,
    activeFindingsCount: withPrompts.filter((f) => !f.suppressed).length,
    suppressedFindingsCount: withPrompts.filter((f) => f.suppressed).length
  };
}

// Combine a code scan and a deployed-site scan into one result.
function mergeResults(results) {
  if (results.length === 1) return results[0];
  return summarize({
    target: results.map((r) => r.target).join(" + "),
    filesScanned: results.reduce((sum, r) => sum + r.filesScanned, 0),
    bytesScanned: results.reduce((sum, r) => sum + r.bytesScanned, 0),
    durationMs: results.reduce((sum, r) => sum + r.durationMs, 0),
    findings: results.flatMap((r) => r.findings)
  });
}

const HOOK_MARKER = "# vibeshield pre-commit hook";
const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}
# Blocks commits that add high or critical security issues. Skip once with: git commit --no-verify
npx --yes vibeshield --staged --fail-on high --no-deps --quiet
`;

function git(args, cwd) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

async function installHook(cwd) {
  let hooksDir;
  try {
    // Respects core.hooksPath and git worktrees.
    hooksDir = path.resolve(cwd, git(["rev-parse", "--git-path", "hooks"], cwd));
  } catch {
    console.error("error: not inside a git repository");
    return 2;
  }
  const hookPath = path.join(hooksDir, "pre-commit");
  const existing = fs.existsSync(hookPath) ? await fsp.readFile(hookPath, "utf8") : null;
  if (existing && !existing.includes(HOOK_MARKER)) {
    console.error(`error: ${hookPath} already exists. Add this line to it instead:\n  npx --yes vibeshield --staged --fail-on high --no-deps --quiet`);
    return 2;
  }
  await fsp.mkdir(hooksDir, { recursive: true });
  await fsp.writeFile(hookPath, HOOK_SCRIPT, { mode: 0o755 });
  await fsp.chmod(hookPath, 0o755);
  console.log(`Installed ${hookPath}`);
  return 0;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return 0;
  }
  if (args.installHook) return installHook(process.cwd());
  let stagedFiles = null;
  if (args.staged) {
    try {
      const top = git(["rev-parse", "--show-toplevel"], path.resolve(args.path));
      stagedFiles = new Set(git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"], top).split("\n").filter(Boolean));
      args.path = top;
    } catch {
      console.error("error: --staged needs to run inside a git repository");
      return 2;
    }
    if (!stagedFiles.size) return 0;
  }
  for (const [flag, value] of [["--severity", args.severity], ["--fail-on", args.failOn]]) {
    if (value != null && !SEVERITY_ORDER[value]) {
      console.error(`error: ${flag} must be one of critical, high, medium, low`);
      return 2;
    }
  }
  const scanCode = !args.url || args.pathGiven;
  const root = path.resolve(args.path);
  if (scanCode) {
    try {
      const stat = await fsp.stat(root);
      if (!stat.isDirectory()) {
        console.error(`error: ${root} is not a directory`);
        return 2;
      }
    } catch {
      console.error(`error: ${root} does not exist`);
      return 2;
    }
  }
  if (args.url && !/^https?:\/\//i.test(args.url)) {
    console.error("error: --url must start with http:// or https://");
    return 2;
  }

  const log = (message) => {
    if (!args.quiet && args.format === "pretty") process.stderr.write(message);
  };
  const results = [];
  if (scanCode) {
    log(`Scanning ${root}…\n`);
    results.push(await scanDirectory(root, { deps: args.deps }));
  }
  if (args.url) {
    log(`Fetching ${args.url} and its JavaScript…\n`);
    try {
      const site = await scanUrl(args.url, { userAgent: `VibeShield/${VERSION} (+https://github.com/Anujsuthar004/vibeshield-security)` });
      results.push(summarize(site));
    } catch (error) {
      console.error(`error: could not scan ${args.url}: ${error.message}`);
      return 2;
    }
  }
  let result = mergeResults(results);
  if (stagedFiles) {
    // The whole repo is analyzed so cross-file checks (RLS, ownership) still see context.
    result = summarize({ ...result, findings: result.findings.filter((finding) => stagedFiles.has(finding.file)) });
  }

  let output;
  if (args.format === "json") {
    output = JSON.stringify(result, null, 2);
  } else if (args.format === "sarif") {
    output = renderSarif(result);
  } else if (args.format === "prompt") {
    const visible = result.findings.filter((finding) => meetsSeverity(finding, args.severity));
    output = combinedFixPrompt(visible) || "No findings at this severity threshold.";
  } else {
    output = renderPretty(result, args);
  }

  if (args.output) {
    await fsp.writeFile(args.output, output, "utf8");
    if (!args.quiet) process.stderr.write(`Wrote ${args.output}\n`);
  } else {
    // Wait for the flush: process.exit() right after a large write to a pipe truncates it at 64 KB.
    await new Promise((resolve) => process.stdout.write(output + "\n", resolve));
  }

  if (args.failOn) {
    const failing = result.findings.find((f) => !f.suppressed && meetsSeverity(f, args.failOn));
    if (failing) return 1;
  }
  return 0;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code || 0))
    .catch((error) => {
      console.error("vibeshield: " + (error.stack || error.message));
      process.exit(2);
    });
}

module.exports = {
  meetsSeverity,
  renderSarif,
  scanDirectory,
  summarize
};
