const generic = require("./generic");
const javascript = require("./javascript");
const python = require("./python");
const ruby = require("./ruby");
const go = require("./go");
const php = require("./php");
const sql = require("./sql");

const LANGUAGES = [
  { rx: /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte)$/i, language: "javascript", analyzer: javascript },
  { rx: /\.py$/i, language: "python", analyzer: python },
  { rx: /\.rb$/i, language: "ruby", analyzer: ruby },
  { rx: /\.go$/i, language: "go", analyzer: go },
  { rx: /\.(php|phtml)$/i, language: "php", analyzer: php },
  { rx: /\.sql$/i, language: "sql", analyzer: sql }
];

function detectLanguage(filePath) {
  for (const entry of LANGUAGES) {
    if (entry.rx.test(filePath)) return entry.language;
  }
  return "unknown";
}

function analyzeFile(file) {
  const findings = [];
  for (const entry of LANGUAGES) {
    if (entry.rx.test(file.path)) {
      findings.push(...entry.analyzer.analyze(file));
      break;
    }
  }
  findings.push(...generic.analyze(file));
  return findings;
}

module.exports = {
  analyzeFile,
  detectLanguage
};
