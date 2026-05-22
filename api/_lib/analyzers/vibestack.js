const { buildFinding } = require("../findings");
const {
  getCalleeName,
  getDirectives,
  getImports,
  getLiteralString,
  hasAuthCallNearby,
  isCommented,
  looksLikeClientComponent,
  looksLikeRouteHandler,
  looksLikeServerAction,
  looksLikeServerComponent,
  traverse
} = require("./_jsutils");

const NEXTJS_ROUTE_RE = /(^|\/)app\/.+\/route\.(ts|tsx|js|jsx|mjs|cjs)$/i;
const NEXTJS_SERVER_DIRS_RE = /(^|\/)app\//i;
const SERVER_ACTION_RE = /(^|\/)app\/.+\.(ts|tsx|js|jsx)$/i;
const CLIENT_FILE_RE = /\.(tsx|jsx)$/i;

function isInClientFile(file, ast) {
  return looksLikeClientComponent(file, ast) || (CLIENT_FILE_RE.test(file.path) && /^\s*['"]use client['"]/m.test(file.content));
}

function findExportedHttpHandlers(ast) {
  const handlers = [];
  if (!ast?.program?.body) return handlers;
  const httpMethods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
  for (const node of ast.program.body) {
    if (node.type !== "ExportNamedDeclaration" || !node.declaration) continue;
    if (node.declaration.type === "FunctionDeclaration") {
      const name = node.declaration.id?.name;
      if (name && httpMethods.has(name)) {
        handlers.push({ name, node: node.declaration });
      }
    }
    if (node.declaration.type === "VariableDeclaration") {
      for (const decl of node.declaration.declarations) {
        const name = decl.id?.name;
        if (name && httpMethods.has(name) && decl.init) {
          handlers.push({ name, node: decl.init });
        }
      }
    }
  }
  return handlers;
}

function findExportedAsyncFunctions(ast) {
  const fns = [];
  if (!ast?.program?.body) return fns;
  for (const node of ast.program.body) {
    if (node.type !== "ExportNamedDeclaration" && node.type !== "ExportDefaultDeclaration") continue;
    const declaration = node.declaration;
    if (!declaration) continue;
    if (declaration.type === "FunctionDeclaration" && declaration.async) {
      fns.push({ name: declaration.id?.name || "default", node: declaration });
    }
    if (declaration.type === "VariableDeclaration") {
      for (const decl of declaration.declarations) {
        const init = decl.init;
        if (
          init &&
          (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression") &&
          init.async
        ) {
          fns.push({ name: decl.id?.name, node: init });
        }
      }
    }
    if (
      (declaration.type === "ArrowFunctionExpression" || declaration.type === "FunctionExpression") &&
      declaration.async
    ) {
      fns.push({ name: "default", node: declaration });
    }
  }
  return fns;
}

function nodeContainsCalleeMatching(node, predicate) {
  let found = false;
  const visit = (current) => {
    if (!current || typeof current !== "object" || found) return;
    if (current.type === "CallExpression" || current.type === "OptionalCallExpression") {
      const callee = getCalleeName(current.callee);
      if (callee && predicate(callee)) {
        found = true;
        return;
      }
    }
    for (const key of Object.keys(current)) {
      if (key === "loc" || key === "leadingComments" || key === "trailingComments") continue;
      const child = current[key];
      if (Array.isArray(child)) {
        for (const item of child) visit(item);
      } else if (child && typeof child === "object" && child.type) {
        visit(child);
      }
    }
  };
  visit(node);
  return found;
}

function containsAuthCheck(node) {
  return nodeContainsCalleeMatching(node, (callee) => /(^|\.)((auth|getServerSession|currentUser|getUser|getSession|requireUser|requireAuth|protectRoute|isAuthenticated|verifyToken|authenticate|verifySession)$)/.test(callee));
}

function containsOrmWrite(node) {
  return nodeContainsCalleeMatching(node, (callee) => /^(prisma|db|drizzle|knex|supabase)\.[\w.]*\.(create|update|upsert|insert|delete)/.test(callee) || /\.(insert|update|delete)\s*$/.test(callee));
}

function functionUsesFormDataDirectly(funcPath) {
  let found = null;
  funcPath.traverse({
    CallExpression(p) {
      if (found) return;
      const callee = getCalleeName(p.node.callee);
      if (!callee) return;
      // pattern: Object.fromEntries(formData) passed straight into ORM
      if (/^(prisma|db|drizzle|knex|supabase)\.[\w.]*\.(create|update|upsert|insert)$/.test(callee)) {
        const opts = p.node.arguments[0];
        if (!opts || opts.type !== "ObjectExpression") return;
        const dataProp = opts.properties.find(
          (prop) => prop.type === "ObjectProperty" && (prop.key?.name === "data" || prop.key?.value === "data")
        );
        if (!dataProp) return;
        const value = dataProp.value;
        if (!value) return;
        // Direct: data: formData / formObj / userInput
        if (value.type === "Identifier" && /^(formData|form|body|input|data)$/i.test(value.name)) {
          found = { line: p.node.loc?.start.line, ormCall: callee };
        }
        // Object.fromEntries(formData)
        if (
          value.type === "CallExpression" &&
          getCalleeName(value.callee) === "Object.fromEntries"
        ) {
          found = { line: p.node.loc?.start.line, ormCall: callee };
        }
      }
    }
  });
  return found;
}

function analyzeNextjs(file, ast, findings) {
  if (!ast) return;
  // Route handlers under app/.../route.ts
  if (NEXTJS_ROUTE_RE.test(file.path)) {
    const handlers = findExportedHttpHandlers(ast);
    for (const handler of handlers) {
      const line = handler.node.loc?.start.line || 1;
      if (isCommented(file, line)) continue;
      if (!containsAuthCheck(handler.node) && !hasAuthCallNearby(file.content)) {
        findings.push(buildFinding({
          rule: "nextjs.route_handler_no_auth",
          severity: "high",
          title: `Next.js ${handler.name} route handler has no visible auth check`,
          category: "Authentication & Authorization",
          file: file.path,
          line,
          evidence: `${file.path}:${line} export ${handler.name === "default" ? "default" : `async function ${handler.name}`}() — no recognizable auth() / getServerSession() / currentUser() call`,
          fix: "Call await auth() / await currentUser() / await getServerSession() at the top of the handler and 401 if the principal is missing. Or wrap the file in a middleware-protected segment.",
          references: ["https://nextjs.org/docs/app/building-your-application/authentication"],
          ruleType: "semantic_match",
          signal: 2
        }));
      }
    }
  }

  // "use server" files / Server Action checks
  if (looksLikeServerAction(file, ast)) {
    const fns = findExportedAsyncFunctions(ast);
    for (const fn of fns) {
      const line = fn.node.loc?.start.line || 1;
      if (isCommented(file, line)) continue;
      if (!containsAuthCheck(fn.node) && containsOrmWrite(fn.node)) {
        findings.push(buildFinding({
          rule: "nextjs.server_action_no_auth",
          severity: "critical",
          title: `Server Action "${fn.name || "default"}" writes to DB without auth check`,
          category: "Authentication & Authorization",
          file: file.path,
          line,
          evidence: `${file.path}:${line} "use server" function ${fn.name || "default"}() performs DB writes with no recognizable auth check`,
          fix: "Server Actions are publicly callable POST endpoints. Always start them with await auth() / await currentUser() and verify the principal owns the resource before mutating.",
          references: ["https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#authentication-and-authorization"],
          ruleType: "semantic_match",
          signal: 4
        }));
      }
      // Mass assignment via formData
      const ma = functionUsesFormDataDirectly({ node: fn.node, traverse: (visitor) => walkNode(fn.node, visitor) });
      if (ma) {
        findings.push(buildFinding({
          rule: "nextjs.server_action_mass_assignment",
          severity: "high",
          title: "Server Action writes raw formData into the ORM (mass assignment)",
          category: "Business Logic",
          file: file.path,
          line: ma.line || line,
          evidence: `${file.path}:${ma.line || line} ${ma.ormCall}({ data: <raw formData> })`,
          fix: "Pick allowed fields explicitly. Use zod / valibot to validate FormData, then map only known properties into the ORM call.",
          ruleType: "ast_match",
          signal: 4
        }));
      }
    }
  }

  // cookies().set without options
  traverse(ast, {
    CallExpression(path) {
      const callee = getCalleeName(path.node.callee);
      if (!callee) return;
      const line = path.node.loc?.start.line;
      if (isCommented(file, line || 0)) return;

      if (callee === "cookies.set" || callee === "cookieStore.set" || /\.cookies\.set$/.test(callee)) {
        const args = path.node.arguments;
        const optionsArg = args[2] || (args[0]?.type === "ObjectExpression" ? args[0] : null);
        const optionsObject = optionsArg?.type === "ObjectExpression" ? optionsArg : null;
        const hasHttpOnly = optionsObject?.properties.some(
          (prop) => prop.type === "ObjectProperty" && (prop.key?.name === "httpOnly" || prop.key?.value === "httpOnly")
        );
        if (!hasHttpOnly) {
          findings.push(buildFinding({
            rule: "nextjs.cookies_missing_options",
            severity: "medium",
            title: "cookies().set without httpOnly / secure / sameSite",
            category: "Authentication & Authorization",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${callee}(...) missing { httpOnly, secure, sameSite }`,
            fix: "Always pass { httpOnly: true, secure: true, sameSite: 'lax', path: '/' } to cookies().set. Otherwise the cookie is readable by document.cookie and replayable across sites.",
            ruleType: "ast_match",
            signal: 2
          }));
        }
      }

      // redirect() inside server action with no obvious sanitization
      if (callee === "redirect" || callee === "NextResponse.redirect") {
        const arg = path.node.arguments[0];
        if (arg?.type === "Identifier") {
          // covered by taint analyzer if the identifier was tainted; nothing else to add here
        }
      }
    }
  });

  // `'use client'` files that import the Supabase service role key.
  if (isInClientFile(file, ast)) {
    if (/SUPABASE_SERVICE_ROLE_KEY/.test(file.content)) {
      findings.push(buildFinding({
        rule: "supabase.service_role_client_side",
        severity: "critical",
        title: "Supabase service-role key referenced in a client component",
        category: "Data Exposure",
        file: file.path,
        line: 1,
        evidence: `${file.path} is a 'use client' component but references SUPABASE_SERVICE_ROLE_KEY`,
        fix: "The service-role key bypasses RLS and must never reach the browser. Use NEXT_PUBLIC_SUPABASE_ANON_KEY in client code and put service-role logic in a server action or route handler.",
        ruleType: "semantic_match",
        signal: 6
      }));
    }
  }
}

function walkNode(node, visitor) {
  const visit = (current) => {
    if (!current || typeof current !== "object") return;
    if (visitor[current.type]) {
      visitor[current.type]({ node: current });
    }
    for (const key of Object.keys(current)) {
      if (key === "loc" || key === "leadingComments" || key === "trailingComments") continue;
      const child = current[key];
      if (Array.isArray(child)) {
        for (const item of child) visit(item);
      } else if (child && typeof child === "object" && child.type) {
        visit(child);
      }
    }
  };
  visit(node);
}

function analyzeSupabase(file, ast, findings) {
  if (!ast) return;
  const imports = getImports(ast);
  const usesSupabase = [...imports.keys()].some((key) => key.startsWith("@supabase/")) || /\bcreateClient\s*\(/.test(file.content);
  if (!usesSupabase) return;

  traverse(ast, {
    CallExpression(path) {
      const callee = getCalleeName(path.node.callee);
      const line = path.node.loc?.start.line;
      if (isCommented(file, line || 0)) return;

      // createClient(url, SUPABASE_SERVICE_ROLE_KEY, ...) outside server-only context
      if (callee === "createClient" || callee === "createServerClient") {
        const args = path.node.arguments;
        const keyArg = args[1];
        if (keyArg?.type === "MemberExpression") {
          const memberName = getCalleeName(keyArg);
          if (memberName && /SERVICE_ROLE/.test(memberName) && isInClientFile(file, ast)) {
            findings.push(buildFinding({
              rule: "supabase.service_role_in_client_bundle",
              severity: "critical",
              title: "createClient called with service-role key in a client component",
              category: "Data Exposure",
              file: file.path,
              line,
              evidence: `${file.path}:${line} createClient(url, ${memberName})`,
              fix: "Move this call to a server-only file (route handler or server action). Use the anon key for browser code.",
              ruleType: "ast_match",
              signal: 6
            }));
          }
        }
      }

      // supabase.auth.admin.* anywhere outside an auth check
      if (callee && /^supabase\.auth\.admin\./.test(callee)) {
        findings.push(buildFinding({
          rule: "supabase.auth_admin_call",
          severity: "high",
          title: "supabase.auth.admin call — verify caller is privileged",
          category: "Authentication & Authorization",
          file: file.path,
          line,
          evidence: `${file.path}:${line} ${callee}(...)`,
          fix: "Restrict admin-API calls to authenticated administrators. Check the session user's role before invoking auth.admin.*.",
          ruleType: "ast_match",
          signal: 2
        }));
      }
    }
  });
}

function analyzeStripe(file, ast, findings) {
  if (!ast) return;
  const text = file.content;
  if (!/\bstripe\b/i.test(text)) return;

  traverse(ast, {
    CallExpression(path) {
      const callee = getCalleeName(path.node.callee);
      const line = path.node.loc?.start.line;
      if (isCommented(file, line || 0)) return;
      if (!callee) return;

      // stripe.X.create / stripe.X.update without idempotencyKey
      if (/^stripe\.(charges|paymentIntents|subscriptions|invoices|customers|refunds|setupIntents|checkout\.sessions)\.(create|update)$/.test(callee)) {
        const opts = path.node.arguments[1];
        const hasIdempotency =
          opts?.type === "ObjectExpression" &&
          opts.properties.some(
            (prop) => prop.type === "ObjectProperty" && (prop.key?.name === "idempotencyKey" || prop.key?.value === "idempotencyKey" || prop.key?.name === "idempotency_key")
          );
        if (!hasIdempotency) {
          findings.push(buildFinding({
            rule: "stripe.idempotency_missing",
            severity: "medium",
            title: `Stripe ${callee} called without an idempotencyKey`,
            category: "Business Logic",
            file: file.path,
            line,
            evidence: `${file.path}:${line} ${callee}(...) without { idempotencyKey: ... }`,
            fix: "Pass an idempotencyKey as the second arg (e.g. await stripe.X.create({...}, { idempotencyKey })). Otherwise a retry can double-charge or duplicate-create.",
            references: ["https://stripe.com/docs/api/idempotent_requests"],
            ruleType: "ast_match",
            signal: 2
          }));
        }
      }

      // stripe.webhooks.constructEvent — verify it's called before any other webhook body parsing
      if (callee === "stripe.webhooks.constructEvent" || callee === "webhooks.constructEvent") {
        // good — separate rule covers the missing case
      }
    }
  });
}

function analyzeClerk(file, ast, findings) {
  if (!ast) return;
  const imports = getImports(ast);
  const hasClerk = [...imports.keys()].some((key) => key.startsWith("@clerk/") || key === "svix");
  const filename = file.path.toLowerCase();
  const looksLikeClerkWebhook = /webhook/.test(filename) && /clerk/i.test(file.content);

  if (looksLikeClerkWebhook && !/Webhook\s*\(\s*[^)]+\)|wh\.verify\s*\(/.test(file.content)) {
    findings.push(buildFinding({
      rule: "clerk.webhook_unverified",
      severity: "critical",
      title: "Clerk webhook handler does not verify the svix signature",
      category: "API & Third-party Keys",
      file: file.path,
      line: 1,
      evidence: `${file.path} appears to handle Clerk webhooks but does not import svix or call Webhook(secret).verify(payload, headers)`,
      fix: "Read the raw request body, pull svix-id / svix-timestamp / svix-signature headers, and call new Webhook(secret).verify(rawBody, headers) before trusting any payload field.",
      references: ["https://clerk.com/docs/integrations/webhooks/sync-data#verifying-the-webhook"],
      ruleType: "semantic_match",
      signal: 5
    }));
  }

  if (!hasClerk) return;

  traverse(ast, {
    AwaitExpression(path) {
      const callExpr = path.node.argument;
      if (callExpr?.type !== "CallExpression") return;
      const callee = getCalleeName(callExpr.callee);
      if (callee !== "currentUser" && callee !== "auth") return;

      const parent = path.parentPath;
      // Look for: const user = await currentUser(); user.id  (no null check)
      if (parent.node.type === "VariableDeclarator") {
        const binding = parent.node.id?.name;
        if (!binding) return;
        const scope = parent.findParent((p) => p.isFunction()) || path.scope.getFunctionParent() || null;
        if (!scope) return;
        let nullChecked = false;
        let unsafeAccess = null;
        scope.traverse({
          IfStatement(p) {
            const test = p.node.test;
            if (test?.type === "UnaryExpression" && test.argument?.type === "Identifier" && test.argument.name === binding) {
              nullChecked = true;
            }
            if (test?.type === "Identifier" && test.name === binding) nullChecked = true;
            if (test?.type === "BinaryExpression" && test.left?.type === "Identifier" && test.left.name === binding) nullChecked = true;
          },
          MemberExpression(p) {
            if (unsafeAccess) return;
            if (
              p.node.object?.type === "Identifier" &&
              p.node.object.name === binding &&
              !p.node.optional
            ) {
              unsafeAccess = p.node.loc?.start.line;
            }
          }
        });
        if (unsafeAccess && !nullChecked) {
          findings.push(buildFinding({
            rule: "clerk.current_user_no_null_check",
            severity: "high",
            title: `await ${callee}() result accessed without a null check`,
            category: "Authentication & Authorization",
            file: file.path,
            line: unsafeAccess,
            evidence: `${file.path}:${unsafeAccess} ${binding}.<field> accessed; ${callee}() returns null for signed-out users`,
            fix: `Guard the value: if (!${binding}) return new Response('Unauthorized', { status: 401 }); — otherwise signed-out requests will crash with a TypeError that leaks paths.`,
            ruleType: "ast_match",
            signal: 3
          }));
        }
      }
    }
  });
}

function analyze(file, ast) {
  const findings = [];
  analyzeNextjs(file, ast, findings);
  analyzeSupabase(file, ast, findings);
  analyzeStripe(file, ast, findings);
  analyzeClerk(file, ast, findings);
  return findings;
}

module.exports = { analyze };
