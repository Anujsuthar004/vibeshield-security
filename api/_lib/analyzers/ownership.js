const { buildFinding } = require("../findings");
const { getCalleeName, getLiteralString, isCommented } = require("./_jsutils");

// IDOR check for Next.js route handlers and Server Actions: a record is looked up
// or changed by an id the client controls (route params, query string, form
// field, action argument) and nothing ties that record to the signed-in user.

const NEXTJS_ROUTE_RE = /(^|\/)app\/.+\/route\.(ts|tsx|js|jsx|mjs|cjs)$/i;
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const IDENTITY_CALLS = /(^|\.)(auth|currentUser|getServerSession|getSession|getUser|requireUser|requireAuth|getCurrentUser|validateRequest)$/;
const DB_ROOT_RE = /^(prisma|db|drizzle|knex|tx|supabase|supabaseAdmin|admin|[A-Z]\w*)$/;
const LOOKUP_METHODS = new Set([
  "findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "update", "updateMany", "delete", "deleteMany", "upsert",
  "findById", "findByIdAndUpdate", "findByIdAndDelete", "findOne", "findOneAndUpdate", "findOneAndDelete",
  "eq", "match", "where", "getUserById", "updateUserById", "deleteUser"
]);
const OWNER_COLUMN_RE = /^(user_?id|owner_?id|author_?id|created_?by|org_?id|organization_?id|tenant_?id|team_?id|account_?id)$/i;
const AUTHZ_CALL_RE = /(^|\.)(authorize|can|ability\.can|checkPermission|assertOwner|ensureOwner|requireOwner|requireRole|isAdmin|hasRole|hasPermission)$/;
const SKIP_KEYS = new Set(["loc", "start", "end", "leadingComments", "trailingComments", "innerComments", "typeAnnotation", "returnType", "typeParameters"]);

function walk(node, visit) {
  if (!node || typeof node !== "object") return;
  if (visit(node) === false) return;
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const child = node[key];
    if (Array.isArray(child)) child.forEach((item) => item && typeof item.type === "string" && walk(item, visit));
    else if (child && typeof child.type === "string") walk(child, visit);
  }
}

function some(node, predicate) {
  let found = false;
  walk(node, (current) => {
    if (found) return false;
    if (predicate(current)) {
      found = true;
      return false;
    }
    return undefined;
  });
  return found;
}

function unwrap(node) {
  let current = node;
  while (current && (current.type === "AwaitExpression" || current.type === "TSAsExpression" || current.type === "TSNonNullExpression" || current.type === "ParenthesizedExpression")) {
    current = current.type === "AwaitExpression" ? current.argument : current.expression;
  }
  return current;
}

function rootIdentifier(node) {
  let current = unwrap(node);
  while (current) {
    if (current.type === "Identifier") return current.name;
    if (current.type === "MemberExpression" || current.type === "OptionalMemberExpression") current = unwrap(current.object);
    else if (current.type === "CallExpression" || current.type === "OptionalCallExpression") current = unwrap(current.callee);
    else return null;
  }
  return null;
}

function patternNames(pattern, out = []) {
  if (!pattern) return out;
  if (pattern.type === "Identifier") out.push(pattern.name);
  else if (pattern.type === "ObjectPattern") pattern.properties.forEach((prop) => patternNames(prop.type === "RestElement" ? prop.argument : prop.value, out));
  else if (pattern.type === "ArrayPattern") pattern.elements.forEach((el) => patternNames(el, out));
  else if (pattern.type === "AssignmentPattern") patternNames(pattern.left, out);
  return out;
}

function isIdLike(name) {
  return typeof name === "string" && /(^id$|Id$|_id$|^slug$|^uuid$)/.test(name);
}

// Expression that reads a client-controlled identifier directly.
function isClientIdSource(node, sources) {
  const current = unwrap(node);
  if (!current) return false;
  if (current.type === "Identifier") return sources.has(current.name);
  if (current.type === "MemberExpression" || current.type === "OptionalMemberExpression") {
    const name = getCalleeName(current) || "";
    if (/(^|\.)params\.\w+$/.test(name)) return true;
    return sources.has(rootIdentifier(current));
  }
  if (current.type === "CallExpression") {
    const callee = getCalleeName(current.callee) || "";
    if (/(searchParams|formData|form)\.get$/.test(callee)) {
      const key = getLiteralString(current.arguments[0]);
      return key ? isIdLike(key) : false;
    }
    if (/^(String|Number|parseInt|BigInt)$/.test(callee)) return isClientIdSource(current.arguments[0], sources);
  }
  return false;
}

function collectFunctionFacts(fn, initialSources) {
  const sources = new Set(initialSources);
  const identities = new Set();
  // Two passes so `const { id } = await params; const docId = id;` both resolve.
  for (let pass = 0; pass < 2; pass += 1) {
    walk(fn.body, (node) => {
      if (node.type !== "VariableDeclarator" || !node.init) return;
      const init = unwrap(node.init);
      const names = patternNames(node.id);
      if (init?.type === "CallExpression" && IDENTITY_CALLS.test(getCalleeName(init.callee) || "")) {
        names.forEach((name) => identities.add(name));
        return;
      }
      if (init?.type === "Identifier" && init.name === "params") {
        names.forEach((name) => sources.add(name));
        return;
      }
      if (some(init, (child) => isClientIdSource(child, sources))) {
        names.forEach((name) => sources.add(name));
      }
    });
  }
  return { sources, identities };
}

function referencesIdentity(node, identities) {
  return some(node, (child) => {
    if (child.type === "Identifier" && identities.has(child.name)) return true;
    if (child.type === "MemberExpression") {
      const name = getCalleeName(child) || "";
      return /(^|\.)(session\.user|user)\.id$/.test(name);
    }
    if (child.type === "CallExpression") return /(^|\.)auth\.uid$/.test(getCalleeName(child.callee) || "");
    return false;
  });
}

function hasOwnershipCheck(fn, identities) {
  return some(fn.body, (node) => {
    // record.userId !== userId — but not a bare null check like user == null
    if (node.type === "BinaryExpression" && /^[!=]==?$/.test(node.operator)) {
      const isNullish = (side) => side.type === "NullLiteral" || (side.type === "Identifier" && side.name === "undefined");
      return !isNullish(node.left) && !isNullish(node.right) && referencesIdentity(node, identities);
    }
    if (node.type !== "CallExpression" && node.type !== "OptionalCallExpression") return false;
    const callee = getCalleeName(node.callee) || "";
    if (AUTHZ_CALL_RE.test(callee)) return true;
    const method = node.callee?.property?.name;
    // .eq("user_id", …) / .match({ user_id: … })
    const column = getLiteralString(node.arguments[0]);
    if (column && OWNER_COLUMN_RE.test(column) && /^(eq|match|filter|where|is)$/.test(method || "")) return true;
    // where: { id, userId: user.id } or any DB call that carries the caller's identity
    if (method && LOOKUP_METHODS.has(method)) return node.arguments.some((arg) => referencesIdentity(arg, identities));
    return false;
  });
}

function findLookup(fn, sources, fileUsesServiceRole) {
  let hit = null;
  walk(fn.body, (node) => {
    if (hit) return false;
    if (node.type !== "CallExpression" && node.type !== "OptionalCallExpression") return undefined;
    const method = node.callee?.property?.name || (node.callee?.type === "Identifier" ? node.callee.name : null);
    if (!method || !LOOKUP_METHODS.has(method)) return undefined;
    const root = rootIdentifier(node.callee);
    if (!root || !DB_ROOT_RE.test(root)) return undefined;
    // A Supabase client created with the user's session is still protected by RLS.
    if (/^supabase/.test(root) && !fileUsesServiceRole) return undefined;
    if (node.arguments.some((arg) => some(arg, (child) => isClientIdSource(child, sources)))) {
      hit = { line: node.loc?.start.line, call: getCalleeName(node.callee) || `${root}….${method}` };
      return false;
    }
    return undefined;
  });
  return hit;
}

function handlerFunctions(ast) {
  const out = [];
  for (const node of ast.program?.body || []) {
    if (node.type !== "ExportNamedDeclaration" || !node.declaration) continue;
    const decl = node.declaration;
    if (decl.type === "FunctionDeclaration" && decl.id) out.push({ name: decl.id.name, fn: decl });
    if (decl.type === "VariableDeclaration") {
      for (const d of decl.declarations) {
        if (d.id?.name && (d.init?.type === "ArrowFunctionExpression" || d.init?.type === "FunctionExpression")) out.push({ name: d.id.name, fn: d.init });
      }
    }
  }
  return out;
}

function analyzeOwnership(file, ast, { isServerAction }) {
  const findings = [];
  const isRoute = NEXTJS_ROUTE_RE.test(file.path);
  if (!ast || (!isRoute && !isServerAction)) return findings;
  if (/webhook/i.test(file.path)) return findings;
  const usesServiceRole = /SERVICE_ROLE/.test(file.content);

  for (const { name, fn } of handlerFunctions(ast)) {
    if (isRoute && !HTTP_METHODS.has(name)) continue;
    if (!fn.body || fn.body.type !== "BlockStatement") continue;
    const initial = [];
    if (isRoute) {
      // GET(request, { params }) or GET(request, context)
      const second = fn.params[1];
      if (second?.type === "Identifier") initial.push(second.name);
      patternNames(second).forEach((n) => initial.push(n));
    } else {
      // Server Action arguments named like ids: deleteProject(projectId: string)
      fn.params.forEach((param) => patternNames(param).filter(isIdLike).forEach((n) => initial.push(n)));
    }
    const { sources, identities } = collectFunctionFacts(fn, initial);
    const lookup = findLookup(fn, sources, usesServiceRole);
    if (!lookup || isCommented(file, lookup.line || 0)) continue;
    if (hasOwnershipCheck(fn, identities)) continue;

    findings.push(buildFinding({
      rule: "authz.idor_missing_ownership_check",
      severity: "high",
      title: `${isRoute ? `${name} handler` : `Server Action "${name}"`} loads a record by a client-supplied id without checking who owns it`,
      category: "Authentication & Authorization",
      file: file.path,
      line: lookup.line,
      evidence: `${file.path}:${lookup.line} ${lookup.call}(…) uses an id from the request; no comparison against the signed-in user`,
      fix: "Scope the query to the caller: add the owner to the filter (where: { id, userId: user.id } / .eq('user_id', user.id)) or compare record.userId to the session user and return 404 when they differ. Being signed in is not the same as owning the record.",
      references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
      ruleType: "semantic_match",
      signal: 2
    }));
  }
  return findings;
}

module.exports = { analyzeOwnership };
