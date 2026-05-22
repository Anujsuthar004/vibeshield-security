const { buildFinding } = require("../findings");
const { getCalleeName, isCommented, traverse } = require("./_jsutils");

// Identifiers that are tainted at the function boundary.
const TAINT_PARAM_NAMES = new Set([
  "req", "request", "ctx", "context",
  "formData", "form", "data",
  "searchParams", "params", "query"
]);

// Member-expression heads that always read user input.
const TAINT_MEMBER_RE = /^(req|request)\.(body|query|params|headers|cookies|url|nextUrl)/;
// Specific call expressions that return user input.
const TAINT_CALL_NAMES = new Set([
  "formData.get", "form.get", "searchParams.get", "params.get",
  "url.searchParams.get", "request.headers.get", "headers.get",
  "cookies.get", "request.cookies.get",
  "request.json", "request.text", "request.formData", "request.arrayBuffer",
  "req.json", "req.text", "req.formData",
  "Object.fromEntries"
]);

const SINK_RULES = [
  {
    name: "db.query (template)",
    test: (callee) => /^(db|client|pool|knex|sequelize|prisma|connection)\.(query|raw|execute|\$queryRaw|\$executeRaw)$/.test(callee),
    severity: "critical",
    title: "User input flows into SQL query",
    rule: "taint.sql_injection",
    category: "Injection Vulnerabilities",
    fix: "Use parameter placeholders or ORM parameter binding. Never interpolate request data into SQL."
  },
  {
    name: "shell exec",
    test: (callee) => /^(child_process\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(callee),
    severity: "critical",
    title: "User input flows into shell execution",
    rule: "taint.command_injection",
    category: "Injection Vulnerabilities",
    fix: "Pass an argument array, avoid shell=true, and validate input against a strict allowlist."
  },
  {
    name: "eval / Function",
    test: (callee) => callee === "eval" || callee === "Function" || callee === "globalThis.eval",
    severity: "critical",
    title: "User input flows into dynamic code execution",
    rule: "taint.code_injection",
    category: "Injection Vulnerabilities",
    fix: "Avoid eval/Function entirely. Parse or validate input with a typed schema."
  },
  {
    name: "redirect",
    test: (callee) => /^(redirect|NextResponse\.redirect|Response\.redirect|res\.redirect)$/.test(callee),
    severity: "high",
    title: "Open redirect — user input flows into redirect target",
    rule: "taint.open_redirect",
    category: "Cross-Site Scripting",
    fix: "Validate the redirect target against an allowlist. Never redirect to a fully user-supplied URL."
  },
  {
    name: "fs read/write",
    test: (callee) => /^fs\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|stat|statSync)$/.test(callee),
    severity: "high",
    title: "User input flows into a filesystem path",
    rule: "taint.path_traversal",
    category: "Injection Vulnerabilities",
    fix: "Resolve paths inside a fixed base directory and reject any path that escapes it (../). Use path.resolve and verify with startsWith(base)."
  },
  {
    name: "fetch URL",
    test: (callee) => callee === "fetch" || callee === "axios.get" || callee === "axios.post" || callee === "got.get" || callee === "got.post",
    severity: "high",
    title: "User input flows into a server-side fetch (possible SSRF)",
    rule: "taint.ssrf",
    category: "Infrastructure & Deployment",
    fix: "Validate the URL host against an allowlist before fetching. Block private/internal address ranges (10.x, 172.16/12, 192.168.x, 169.254.x, localhost)."
  }
];

function addPatternBindings(pattern, tainted) {
  if (!pattern) return;
  if (pattern.type === "Identifier") {
    tainted.add(pattern.name);
    return;
  }
  if (pattern.type === "ObjectPattern") {
    for (const prop of pattern.properties || []) {
      if (prop.type === "ObjectProperty" && prop.value?.type === "Identifier") {
        tainted.add(prop.value.name);
      }
      if (prop.type === "RestElement" && prop.argument?.type === "Identifier") {
        tainted.add(prop.argument.name);
      }
    }
    return;
  }
  if (pattern.type === "ArrayPattern") {
    for (const elt of pattern.elements || []) {
      if (elt?.type === "Identifier") tainted.add(elt.name);
    }
  }
}

function expressionIsTainted(node, tainted, depth = 0) {
  if (!node || depth > 8) return false;
  switch (node.type) {
    case "Identifier":
      return tainted.has(node.name);
    case "MemberExpression":
    case "OptionalMemberExpression": {
      const name = getCalleeName(node);
      if (name && TAINT_MEMBER_RE.test(name)) return true;
      if (name && name.startsWith("params.")) return true;
      if (name && name.startsWith("searchParams.")) return true;
      if (name && name.startsWith("formData.")) return true;
      if (node.object?.type === "Identifier" && tainted.has(node.object.name)) return true;
      return expressionIsTainted(node.object, tainted, depth + 1);
    }
    case "CallExpression":
    case "OptionalCallExpression": {
      const callee = getCalleeName(node.callee);
      if (callee && TAINT_CALL_NAMES.has(callee)) return true;
      if (callee && /\.(json|text|formData|arrayBuffer)$/.test(callee)) {
        return true;
      }
      // .get / .getAll on a tainted receiver: req.nextUrl.searchParams.get('x')
      if (
        callee &&
        /\.(get|getAll)$/.test(callee) &&
        (node.callee.type === "MemberExpression" || node.callee.type === "OptionalMemberExpression") &&
        expressionIsTainted(node.callee.object, tainted, depth + 1)
      ) {
        return true;
      }
      if (callee === "Object.fromEntries" && node.arguments[0]) {
        return expressionIsTainted(node.arguments[0], tainted, depth + 1);
      }
      return node.arguments.some((arg) => expressionIsTainted(arg, tainted, depth + 1));
    }
    case "AwaitExpression":
      return expressionIsTainted(node.argument, tainted, depth + 1);
    case "TemplateLiteral":
      return node.expressions.some((expr) => expressionIsTainted(expr, tainted, depth + 1));
    case "BinaryExpression":
    case "LogicalExpression":
      return (
        expressionIsTainted(node.left, tainted, depth + 1) ||
        expressionIsTainted(node.right, tainted, depth + 1)
      );
    case "ConditionalExpression":
      return (
        expressionIsTainted(node.consequent, tainted, depth + 1) ||
        expressionIsTainted(node.alternate, tainted, depth + 1)
      );
    case "ObjectExpression":
      return node.properties.some(
        (prop) => prop.type === "ObjectProperty" && expressionIsTainted(prop.value, tainted, depth + 1)
      );
    case "ArrayExpression":
      return node.elements.some((elt) => expressionIsTainted(elt, tainted, depth + 1));
    case "SpreadElement":
      return expressionIsTainted(node.argument, tainted, depth + 1);
    case "TaggedTemplateExpression":
      return expressionIsTainted(node.quasi, tainted, depth + 1);
    case "TSAsExpression":
    case "TSNonNullExpression":
    case "TSTypeAssertion":
      return expressionIsTainted(node.expression, tainted, depth + 1);
    default:
      return false;
  }
}

function collectTainted(funcPath, file) {
  const tainted = new Set();
  // Function/method parameters by convention.
  for (const param of funcPath.node.params || []) {
    if (param.type === "Identifier" && TAINT_PARAM_NAMES.has(param.name)) {
      tainted.add(param.name);
    }
    if (param.type === "AssignmentPattern" && param.left?.type === "Identifier" && TAINT_PARAM_NAMES.has(param.left.name)) {
      tainted.add(param.left.name);
    }
    if (param.type === "ObjectPattern") {
      for (const prop of param.properties || []) {
        if (prop.type === "ObjectProperty" && prop.value?.type === "Identifier" && TAINT_PARAM_NAMES.has(prop.value.name)) {
          tainted.add(prop.value.name);
        }
      }
    }
  }

  // Walk for assignments.
  funcPath.traverse({
    VariableDeclarator(p) {
      const init = p.node.init;
      if (!init) return;
      if (isCommented(file, p.node.loc?.start.line || 0)) return;
      if (expressionIsTainted(init, tainted)) {
        addPatternBindings(p.node.id, tainted);
      }
    },
    AssignmentExpression(p) {
      if (isCommented(file, p.node.loc?.start.line || 0)) return;
      if (expressionIsTainted(p.node.right, tainted)) {
        if (p.node.left?.type === "Identifier") tainted.add(p.node.left.name);
        if (p.node.left?.type === "MemberExpression") {
          const name = getCalleeName(p.node.left);
          if (name) tainted.add(name);
        }
      }
    }
  });

  return tainted;
}

function recordSink(findings, file, node, tainted, rule, seen) {
  if (!node?.loc) return;
  const line = node.loc.start.line;
  if (isCommented(file, line)) return;
  const sig = `${rule.rule}:${line}`;
  if (seen.has(sig)) return;
  seen.add(sig);
  const callee = getCalleeName(node.callee) || rule.name;
  findings.push(buildFinding({
    rule: rule.rule,
    severity: rule.severity,
    title: rule.title,
    category: rule.category,
    file: file.path,
    line,
    evidence: `${file.path}:${line} ${callee}(<tainted>) — value originated from request input`,
    fix: rule.fix,
    references: [],
    ruleType: "ast_match",
    signal: 6
  }));
}

function analyzeTaint(file, ast) {
  if (!ast) return [];
  const findings = [];
  const seen = new Set();

  traverse(ast, {
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ClassMethod|ObjectMethod"(funcPath) {
      const tainted = collectTainted(funcPath, file);
      if (!tainted.size) return;

      funcPath.traverse({
        CallExpression(p) {
          const callee = getCalleeName(p.node.callee);
          if (!callee) return;
          for (const rule of SINK_RULES) {
            if (rule.test(callee) && p.node.arguments.some((arg) => expressionIsTainted(arg, tainted))) {
              recordSink(findings, file, p.node, tainted, rule, seen);
              return;
            }
          }
        },
        TaggedTemplateExpression(p) {
          const callee = getCalleeName(p.node.tag);
          if (!callee) return;
          // Tagged SQL templates (sql`SELECT ...`, db.sql`...`).
          if (/^(sql|db\.sql|prisma\.\$queryRaw|prisma\.\$executeRaw)$/.test(callee)) {
            if (expressionIsTainted(p.node.quasi, tainted)) {
              recordSink(
                findings,
                file,
                { ...p.node, callee: p.node.tag, arguments: [], loc: p.node.loc },
                tainted,
                SINK_RULES[0],
                seen
              );
            }
          }
        },
        JSXAttribute(p) {
          if (p.node.name?.name !== "dangerouslySetInnerHTML") return;
          const expression = p.node.value?.expression;
          if (!expression || expression.type !== "ObjectExpression") return;
          const htmlProp = expression.properties.find(
            (prop) => prop.type === "ObjectProperty" && (prop.key?.name === "__html" || prop.key?.value === "__html")
          );
          if (!htmlProp) return;
          if (!expressionIsTainted(htmlProp.value, tainted)) return;
          const line = p.node.loc?.start.line;
          if (!line || isCommented(file, line)) return;
          const sig = `taint.xss_dangerous_html:${line}`;
          if (seen.has(sig)) return;
          seen.add(sig);
          findings.push(buildFinding({
            rule: "taint.xss_dangerous_html",
            severity: "high",
            title: "User input flows into dangerouslySetInnerHTML",
            category: "Cross-Site Scripting",
            file: file.path,
            line,
            evidence: `${file.path}:${line} dangerouslySetInnerHTML={{ __html: <tainted> }}`,
            fix: "Render plain text by default. If HTML is required, sanitize with a strict allowlist (DOMPurify) before assignment.",
            ruleType: "ast_match",
            signal: 5
          }));
        }
      });
    }
  });

  return findings;
}

module.exports = { analyzeTaint };
