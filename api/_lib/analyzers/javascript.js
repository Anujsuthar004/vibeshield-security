const parser = require("@babel/parser");
const traverseModule = require("@babel/traverse");
const { buildFinding } = require("../findings");

const traverse = traverseModule.default || traverseModule;

const PARSE_OPTIONS = {
  sourceType: "unambiguous",
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowImportExportEverywhere: true,
  errorRecovery: true,
  plugins: [
    "jsx",
    "typescript",
    "decorators-legacy",
    "classProperties",
    "topLevelAwait",
    "asyncGenerators",
    "optionalChaining",
    "nullishCoalescingOperator",
    "objectRestSpread",
    "dynamicImport",
    "exportDefaultFrom"
  ]
};

function safeParse(source) {
  try {
    return parser.parse(source, PARSE_OPTIONS);
  } catch (error) {
    return null;
  }
}

function getCalleeName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const object = getCalleeName(node.object);
    const property = node.computed ? null : node.property?.name;
    if (object && property) return `${object}.${property}`;
    return property || object || null;
  }
  return null;
}

function getLiteralString(node) {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked).join("");
  }
  return null;
}

function templateUsesIdentifiers(node, names) {
  if (!node || node.type !== "TemplateLiteral") return false;
  return node.expressions.some((expression) => {
    const callee = getCalleeName(expression);
    return callee && names.some((name) => callee.startsWith(name));
  });
}

function isUserInputExpression(node) {
  const name = getCalleeName(node);
  if (!name) return false;
  return (
    name.startsWith("req.body") ||
    name.startsWith("req.query") ||
    name.startsWith("req.params") ||
    name.startsWith("req.headers") ||
    name.startsWith("ctx.request") ||
    name.startsWith("ctx.params") ||
    name === "userInput" ||
    name === "input"
  );
}

function fileLooksProtected(source) {
  return /(requireUser|requireAuth|getServerSession|authMiddleware|verifyToken|withAuth|isAuthenticated|currentUser|protect\()/i.test(source);
}

function isCommented(file, line) {
  const text = file.content.split(/\r?\n/)[line - 1] || "";
  return /^\s*(\/\/|\*|#)/.test(text);
}

function looksLikeApiRoute(file) {
  return /(^|\/)(api|routes|server|controllers)\//i.test(file.path) || /\.(controller|route|handler)\.(js|ts|tsx|jsx|mjs|cjs)$/.test(file.path);
}

function analyze(file) {
  const findings = [];
  const source = file.content;
  if (!source.trim()) return findings;
  const ast = safeParse(source);
  if (!ast) {
    return analyzeFallback(file);
  }

  let usesWebhookConstruct = false;
  let usesAuthGuard = fileLooksProtected(source);

  traverse(ast, {
    enter(path) {
      const node = path.node;
      if (node.type === "Identifier" && (node.name === "requireUser" || node.name === "requireAuth" || node.name === "withAuth")) {
        usesAuthGuard = true;
      }
      if (node.type === "MemberExpression") {
        const fullName = getCalleeName(node);
        if (fullName === "stripe.webhooks.constructEvent" || fullName === "webhooks.constructEvent") {
          usesWebhookConstruct = true;
        }
      }
    },
    StringLiteral(path) {
      const value = path.node.value || "";
      const line = path.node.loc?.start.line;
      if (isCommented(file, line || 0)) return;
      const credentialMatchers = [
        { rx: /sk-(live|test|proj)-[A-Za-z0-9_-]{12,}/, label: "Stripe live/test/proj key" },
        { rx: /ghp_[A-Za-z0-9_]{20,}/, label: "GitHub PAT" },
        { rx: /github_pat_[A-Za-z0-9_]{20,}/, label: "GitHub fine-grained PAT" },
        { rx: /AKIA[A-Z0-9]{12,}/, label: "AWS access key id" },
        { rx: /xox[abprs]-[A-Za-z0-9-]{12,}/, label: "Slack token" }
      ];
      for (const matcher of credentialMatchers) {
        if (matcher.rx.test(value)) {
          findings.push(buildFinding({
            rule: "secrets.literal_credential",
            severity: "critical",
            title: `Committed ${matcher.label}`,
            category: "Data Exposure",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${value}`,
            fix: "Revoke and rotate the credential, remove it from git history, and load it from a secret manager.",
            references: ["https://docs.github.com/code-security/secret-scanning"],
            ruleType: "literal_credential"
          }));
        }
      }
    },
    CallExpression(path) {
      const node = path.node;
      const callee = getCalleeName(node.callee);
      const line = node.loc?.start.line;
      if (isCommented(file, line || 0)) return;

      if (callee === "localStorage.setItem" || callee === "sessionStorage.setItem") {
        const firstArg = node.arguments[0];
        const key = getLiteralString(firstArg);
        if (key && /^(token|jwt|accessToken|auth|session)$/i.test(key)) {
          findings.push(buildFinding({
            rule: "auth.token_in_browser_storage",
            severity: "high",
            title: "Authentication token stored in browser storage",
            category: "Authentication & Authorization",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${callee}('${key}', ...)`,
            fix: "Store session tokens in httpOnly Secure SameSite cookies or short-lived in-memory values with refresh rotation.",
            references: ["https://owasp.org/www-community/HttpOnly"],
            ruleType: "ast_match",
            signal: 4
          }));
        }
      }

      if (callee === "jwt.sign") {
        const secret = node.arguments[2] || node.arguments[1];
        const literal = getLiteralString(secret);
        if (literal && (literal.length < 24 || /^(secret|changeme|jwt_secret|password)$/i.test(literal))) {
          findings.push(buildFinding({
            rule: "auth.weak_jwt_secret",
            severity: "critical",
            title: "Hardcoded or weak JWT signing secret",
            category: "Authentication & Authorization",
            file: file.path,
            line,
            evidence: `${file.path}:${line} jwt.sign(..., '${literal}', ...)`,
            fix: "Read the signing secret from environment configuration with at least 32 bytes of entropy, and rotate it on compromise.",
            references: ["https://datatracker.ietf.org/doc/html/rfc8725"],
            ruleType: "ast_match",
            signal: 6
          }));
        }
      }

      if (callee === "child_process.exec" || callee === "child_process.execSync" || callee === "exec" || callee === "execSync") {
        const firstArg = node.arguments[0];
        const usesUserInput =
          firstArg && (
            isUserInputExpression(firstArg) ||
            (firstArg.type === "BinaryExpression" && (isUserInputExpression(firstArg.left) || isUserInputExpression(firstArg.right))) ||
            (firstArg.type === "TemplateLiteral" && firstArg.expressions.some(isUserInputExpression))
          );
        if (usesUserInput) {
          findings.push(buildFinding({
            rule: "injection.shell_command",
            severity: "critical",
            title: "User input flows into shell execution",
            category: "Injection Vulnerabilities",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${callee}(<user-input>)`,
            fix: "Avoid the shell. Use an argument array form, an allowlist, and never interpolate raw request data.",
            references: ["https://owasp.org/www-community/attacks/Command_Injection"],
            ruleType: "ast_match",
            signal: 6
          }));
        }
      }

      if (callee === "eval" || callee === "Function") {
        findings.push(buildFinding({
          rule: "injection.dynamic_code",
          severity: "high",
          title: `Dynamic code execution via ${callee}()`,
          category: "Injection Vulnerabilities",
          file: file.path,
          line,
          evidence: `${file.path}:${line} ${callee}(...)`,
          fix: "Replace eval/Function with explicit parsers, schema validation, or safe templating.",
          ruleType: "ast_match",
          signal: 2
        }));
      }

      if ((callee === "db.query" || callee === "client.query" || callee === "pool.query" || callee === "knex.raw" || callee === "sequelize.query") && node.arguments[0]) {
        const arg = node.arguments[0];
        if (arg.type === "TemplateLiteral" && templateUsesIdentifiers(arg, ["req.", "params", "query", "body", "ctx.request"])) {
          findings.push(buildFinding({
            rule: "injection.sql_template",
            severity: "critical",
            title: "Possible SQL injection via template literal",
            category: "Injection Vulnerabilities",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${callee}(\`SELECT ... \${user}\`)`,
            fix: "Use parameterized queries or ORM bindings. Never interpolate request data into SQL.",
            references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
            ruleType: "ast_match",
            signal: 6
          }));
        }
        if (arg.type === "BinaryExpression" && arg.operator === "+") {
          findings.push(buildFinding({
            rule: "injection.sql_concat",
            severity: "critical",
            title: "Possible SQL injection via string concatenation",
            category: "Injection Vulnerabilities",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${callee}('...' + req.*)`,
            fix: "Use parameterized queries and bind variables.",
            references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
            ruleType: "ast_match",
            signal: 4
          }));
        }
      }

      if (callee && /^prisma\.[A-Za-z0-9_]+\.(update|upsert|create)$/.test(callee)) {
        const opts = node.arguments[0];
        if (opts && opts.type === "ObjectExpression") {
          const dataProp = opts.properties.find((property) => property.type === "ObjectProperty" && property.key?.name === "data");
          if (dataProp && (isUserInputExpression(dataProp.value) || dataProp.value.type === "Identifier")) {
            findings.push(buildFinding({
              rule: "logic.mass_assignment",
              severity: "high",
              title: "Mass assignment into ORM update",
              category: "Business Logic",
              file: file.path,
              line,
              evidence: `${file.path}:${line} ${callee}({ data: ${getCalleeName(dataProp.value) || "<expression>"} })`,
              fix: "Explicitly pick allowed fields before passing them to the ORM. Reject unexpected properties.",
              ruleType: "ast_match",
              signal: 4
            }));
          }
        }
      }

      if (callee === "Math.random") {
        const parent = path.parentPath;
        const grand = parent?.parentPath;
        const enclosingName = grand?.node?.type === "VariableDeclarator" ? grand.node.id?.name : grand?.node?.left?.property?.name;
        if (enclosingName && /(token|reset|invite|otp|code|nonce)/i.test(enclosingName)) {
          findings.push(buildFinding({
            rule: "logic.predictable_random",
            severity: "high",
            title: "Predictable random used for security-sensitive value",
            category: "Business Logic",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${enclosingName} = Math.random()`,
            fix: "Use crypto.randomBytes / Web Crypto getRandomValues for tokens, resets, OTPs, and invites.",
            ruleType: "ast_match",
            signal: 4
          }));
        }
      }

      if (callee === "cors") {
        const arg = node.arguments[0];
        if (arg?.type === "ObjectExpression") {
          const originProp = arg.properties.find((property) => property.type === "ObjectProperty" && property.key?.name === "origin");
          if (originProp && getLiteralString(originProp.value) === "*") {
            findings.push(buildFinding({
              rule: "infra.open_cors",
              severity: "high",
              title: "Open CORS policy permits any origin",
              category: "Infrastructure & Deployment",
              file: file.path,
              line,
              evidence: `${file.path}:${line} cors({ origin: '*' })`,
              fix: "List specific origins per environment. Never combine wildcard origins with credentialed APIs.",
              ruleType: "ast_match",
              signal: 3
            }));
          }
        }
      }
    },
    AssignmentExpression(path) {
      const node = path.node;
      const line = node.loc?.start.line;
      if (isCommented(file, line || 0)) return;
      const target = getCalleeName(node.left);
      if (!target) return;
      if (target.endsWith(".innerHTML") || target.endsWith(".outerHTML")) {
        findings.push(buildFinding({
          rule: "xss.inner_html",
          severity: "medium",
          title: "Raw HTML rendering path",
          category: "Cross-Site Scripting",
          file: file.path,
          line,
          evidence: `${file.path}:${line} ${target} = ...`,
          fix: "Render text by default. If HTML is required, sanitize with a strict allowlist (DOMPurify) before display.",
          references: ["https://owasp.org/www-community/attacks/xss/"],
          ruleType: "ast_match",
          signal: 2
        }));
      }
    },
    JSXAttribute(path) {
      const node = path.node;
      const line = node.loc?.start.line;
      if (node.name?.name === "dangerouslySetInnerHTML") {
        findings.push(buildFinding({
          rule: "xss.dangerously_set_inner_html",
          severity: "medium",
          title: "dangerouslySetInnerHTML used in JSX",
          category: "Cross-Site Scripting",
          file: file.path,
          line,
          evidence: `${file.path}:${line} dangerouslySetInnerHTML={...}`,
          fix: "Render text by default or sanitize the HTML with a strict allowlist before assignment.",
          ruleType: "ast_match",
          signal: 1
        }));
      }
    }
  });

  if (looksLikeApiRoute(file) && !usesAuthGuard) {
    findings.push(buildFinding({
      rule: "auth.unprotected_route",
      severity: "medium",
      title: "API route has no obvious authentication guard",
      category: "Authentication & Authorization",
      file: file.path,
      line: 1,
      evidence: `${file.path} contains route code without recognizable auth/session guard`,
      fix: "Require authentication middleware or server-side session checks on every non-public API route.",
      ruleType: "semantic_match",
      signal: -2
    }));
  }

  if (/stripe|webhook/i.test(file.path) && /req\.body|JSON\.parse/i.test(source) && !usesWebhookConstruct) {
    findings.push(buildFinding({
      rule: "webhooks.unverified_signature",
      severity: "critical",
      title: "Webhook handler lacks signature verification",
      category: "API & Third-party Keys",
      file: file.path,
      line: 1,
      evidence: `${file.path} parses webhook payload without constructEvent / signature verification`,
      fix: "Verify the provider signature against the raw request body before trusting any webhook payload.",
      references: ["https://stripe.com/docs/webhooks/signatures"],
      ruleType: "semantic_match",
      signal: 4
    }));
  }

  if (/(NEXT_PUBLIC|VITE|PUBLIC)_[A-Z_]*(SECRET|PRIVATE|API_KEY|TOKEN)/i.test(source)) {
    findings.push(buildFinding({
      rule: "secrets.client_bundle_exposure",
      severity: "high",
      title: "Server-only secret exposed via public env prefix",
      category: "API & Third-party Keys",
      file: file.path,
      line: 1,
      evidence: `${file.path} references a public-prefixed secret name`,
      fix: "Drop the public prefix for any value that must stay on the server, and rotate the exposed credential.",
      ruleType: "semantic_match",
      signal: 3
    }));
  }

  return findings;
}

function analyzeFallback(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (/^\s*(\/\/|\*|#)/.test(line)) return;
    if (/jwt\.sign\s*\([^)]*['"`](secret|changeme|jwt_secret)['"`]/i.test(line)) {
      findings.push(buildFinding({
        rule: "auth.weak_jwt_secret",
        severity: "critical",
        title: "Hardcoded JWT signing secret (heuristic)",
        category: "Authentication & Authorization",
        file: file.path,
        line: index + 1,
        evidence: `${file.path}:${index + 1} ${line.trim()}`,
        fix: "Load JWT secrets from environment with strong entropy and rotate them.",
        ruleType: "regex_match"
      }));
    }
  });
  return findings;
}

module.exports = { analyze };
