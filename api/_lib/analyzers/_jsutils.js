const parser = require("@babel/parser");
const traverseModule = require("@babel/traverse");

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
  if (node.type === "ThisExpression") return "this";
  if (node.type === "Super") return "super";
  if (node.type === "MemberExpression") {
    const object = getCalleeName(node.object);
    const property = node.computed ? null : node.property?.name || node.property?.value;
    if (object && property) return `${object}.${property}`;
    return property || object || null;
  }
  if (node.type === "CallExpression") {
    return getCalleeName(node.callee);
  }
  if (node.type === "OptionalMemberExpression") {
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

function isCommented(file, line) {
  if (!line) return false;
  const text = file.content.split(/\r?\n/)[line - 1] || "";
  return /^\s*(\/\/|\*|#)/.test(text);
}

function getDirectives(ast) {
  const directives = new Set();
  if (!ast || !ast.program || !Array.isArray(ast.program.directives)) return directives;
  for (const directive of ast.program.directives) {
    const value = directive.value?.value;
    if (typeof value === "string") directives.add(value);
  }
  return directives;
}

function getImports(ast) {
  const imports = new Map();
  if (!ast?.program?.body) return imports;
  for (const node of ast.program.body) {
    if (node.type === "ImportDeclaration" && node.source?.value) {
      const source = node.source.value;
      const list = imports.get(source) || [];
      for (const specifier of node.specifiers || []) {
        list.push(specifier.local?.name);
      }
      imports.set(source, list);
    }
    if (node.type === "VariableDeclaration") {
      for (const decl of node.declarations) {
        if (
          decl.init?.type === "CallExpression" &&
          decl.init.callee?.type === "Identifier" &&
          decl.init.callee.name === "require" &&
          decl.init.arguments[0]?.type === "StringLiteral"
        ) {
          const source = decl.init.arguments[0].value;
          const list = imports.get(source) || [];
          if (decl.id?.type === "Identifier") list.push(decl.id.name);
          imports.set(source, list);
        }
      }
    }
  }
  return imports;
}

function looksLikeRouteHandler(file) {
  return (
    /(^|\/)app\/.+\/route\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file.path) ||
    /(^|\/)pages\/api\//i.test(file.path) ||
    /(^|\/)api\//i.test(file.path) ||
    /\.(controller|route|handler)\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file.path)
  );
}

function looksLikeServerComponent(file) {
  return /(^|\/)app\/.+\.(ts|tsx|js|jsx)$/i.test(file.path);
}

function looksLikeClientComponent(file, ast) {
  if (!ast) return false;
  return getDirectives(ast).has("use client");
}

function looksLikeServerAction(file, ast) {
  if (!ast) return false;
  return getDirectives(ast).has("use server");
}

function looksLikeNextjsProject(file) {
  return /(^|\/)(app|pages)\//.test(file.path) || /next\.config\.(js|mjs|ts)$/.test(file.path);
}

function hasAuthCallNearby(text) {
  return /(auth\s*\(|getServerSession|currentUser\s*\(|requireUser|requireAuth|withAuth|protectRoute|isAuthenticated|session\.user|user\?\.id|user\.id)/i.test(text);
}

module.exports = {
  getCalleeName,
  getDirectives,
  getImports,
  getLiteralString,
  hasAuthCallNearby,
  isCommented,
  looksLikeClientComponent,
  looksLikeNextjsProject,
  looksLikeRouteHandler,
  looksLikeServerAction,
  looksLikeServerComponent,
  safeParse,
  traverse
};
