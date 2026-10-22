#!/usr/bin/env node
/* eslint-disable no-console */
"use strict";

// Turns a `vibeshield --json` result into GitHub Actions output: inline
// annotations, a job summary table, a SARIF file, and step outputs.
// Used by action.yml; always exits 0 so SARIF upload can run before the
// action decides whether to fail.

const fs = require("node:fs");
const path = require("node:path");

const { meetsSeverity, renderSarif } = require("./cli");
const { combinedFixPrompt } = require("../api/_lib/prompts");

function parseArgs(argv) {
  const args = { input: null, sarif: "vibeshield.sarif", failOn: "high", scanPath: "." };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--sarif") args.sarif = argv[++i];
    else if (arg === "--fail-on") args.failOn = argv[++i];
    else if (arg === "--path") args.scanPath = argv[++i];
    else if (!arg.startsWith("-")) args.input = arg;
  }
  return args;
}

function escapeData(value) {
  return String(value).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(value) {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function annotationLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "notice";
}

function escapeCell(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function renderSummary(result, active, failOn, failed) {
  const lines = [];
  lines.push(`## VibeShield: score ${result.score}/100`);
  lines.push("");
  lines.push(`${result.filesScanned} files scanned, ${active.length} active findings, ${result.suppressedFindingsCount} suppressed.`);
  if (failOn !== "none") {
    lines.push("");
    lines.push(failed ? `**Failing:** at least one finding is \`${failOn}\` or above.` : `No findings at \`${failOn}\` or above.`);
  }
  if (!active.length) return lines.join("\n") + "\n";
  lines.push("");
  lines.push("| Severity | Finding | Location | Rule | Fix |");
  lines.push("| --- | --- | --- | --- | --- |");
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  for (const finding of [...active].sort((a, b) => order[a.severity] - order[b.severity])) {
    const loc = finding.file ? `\`${finding.file}${finding.line ? `:${finding.line}` : ""}\`` : "general";
    lines.push(`| ${finding.severity} | ${escapeCell(finding.title)} | ${loc} | \`${finding.rule}\` | ${escapeCell(finding.fix)} |`);
  }
  lines.push("");
  lines.push("<details><summary>Fix with your AI editor: copy this prompt into Cursor / Claude Code</summary>");
  lines.push("");
  lines.push("````text");
  lines.push(combinedFixPrompt(active));
  lines.push("````");
  lines.push("");
  lines.push("</details>");
  return lines.join("\n") + "\n";
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.input) {
    console.error("usage: github-report.js <result.json> [--sarif file] [--fail-on level|none] [--path scanned-dir]");
    return 2;
  }
  if (!["none", "critical", "high", "medium", "low"].includes(args.failOn)) {
    console.error(`::error::fail-on must be one of none, critical, high, medium, low (got "${args.failOn}")`);
    return 2;
  }
  const result = JSON.parse(fs.readFileSync(args.input, "utf8"));

  // Findings are relative to the scanned directory; GitHub wants paths relative to the repo root.
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const base = path.relative(workspace, path.resolve(workspace, args.scanPath));
  for (const finding of result.findings) {
    if (finding.file && base) finding.file = path.posix.join(base.split(path.sep).join("/"), finding.file);
  }

  const active = result.findings.filter((finding) => !finding.suppressed);
  const failed = args.failOn !== "none" && active.some((finding) => meetsSeverity(finding, args.failOn));

  for (const finding of active) {
    const props = [`title=${escapeProperty(`${finding.title} (${finding.rule})`)}`];
    if (finding.file) props.unshift(`file=${escapeProperty(finding.file)}`);
    if (finding.file && finding.line) props.splice(1, 0, `line=${finding.line}`);
    console.log(`::${annotationLevel(finding.severity)} ${props.join(",")}::${escapeData(finding.fix)}`);
  }

  fs.writeFileSync(args.sarif, renderSarif(result), "utf8");

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, renderSummary(result, active, args.failOn, failed));
  }
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(
      process.env.GITHUB_OUTPUT,
      `findings=${active.length}\nscore=${result.score}\nfailed=${failed}\n`
    );
  }
  return 0;
}

process.exit(main());
