const { buildFinding } = require("../findings");

// Project-level Supabase migration linter. Runs across every .sql file at once,
// because a table is often created in one migration and secured in a later one.

const SUPABASE_SQL_RE = /(^|\/)supabase\/.+\.sql$/i;
const USER_SCOPE_RE = /\bauth\.(uid|jwt|role)\s*\(|\bcurrent_user\b|\brequesting_user_id\s*\(/i;
const DOCS = "https://supabase.com/docs/guides/database/postgres/row-level-security";

// Split SQL into statements with their starting line, skipping comments, quoted
// strings and $tag$ bodies so semicolons inside functions don't split statements.
function splitStatements(sql) {
  const statements = [];
  let current = "";
  let line = 1;
  let startLine = null;
  let i = 0;
  const push = () => {
    const text = current.replace(/\s+/g, " ").trim();
    if (text) statements.push({ text, line: startLine || line });
    current = "";
    startLine = null;
  };
  const take = (chunk) => {
    if (startLine === null && chunk.trim()) startLine = line;
    current += chunk;
    line += (chunk.match(/\n/g) || []).length;
  };
  while (i < sql.length) {
    const rest = sql.slice(i);
    if (rest.startsWith("--")) {
      const end = sql.indexOf("\n", i);
      i = end === -1 ? sql.length : end;
      continue;
    }
    if (rest.startsWith("/*")) {
      const end = sql.indexOf("*/", i + 2);
      const stop = end === -1 ? sql.length : end + 2;
      line += (sql.slice(i, stop).match(/\n/g) || []).length;
      current += " ";
      i = stop;
      continue;
    }
    const dollar = rest.match(/^\$[A-Za-z_]*\$/);
    if (dollar) {
      const end = sql.indexOf(dollar[0], i + dollar[0].length);
      const stop = end === -1 ? sql.length : end + dollar[0].length;
      take(sql.slice(i, stop));
      i = stop;
      continue;
    }
    if (sql[i] === "'") {
      let j = i + 1;
      while (j < sql.length && !(sql[j] === "'" && sql[j + 1] !== "'")) j += sql[j] === "'" ? 2 : 1;
      take(sql.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    if (sql[i] === ";") {
      push();
      i += 1;
      continue;
    }
    take(sql[i]);
    i += 1;
  }
  push();
  return statements;
}

// "public"."Profiles" / public.profiles / profiles -> { schema: "public", name: "profiles" }
function parseName(raw) {
  const parts = raw.split(".").map((part) => part.replace(/"/g, "").trim().toLowerCase());
  return parts.length > 1 ? { schema: parts[0], name: parts[1] } : { schema: "public", name: parts[0] };
}

const IDENT = String.raw`((?:"[^"]+"|[\w$]+)(?:\s*\.\s*(?:"[^"]+"|[\w$]+))?)`;
const CREATE_TABLE_RE = new RegExp(String.raw`^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "i");
const ENABLE_RLS_RE = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${IDENT}\s+(?:enable|force)\s+row\s+level\s+security`, "i");
const CREATE_POLICY_RE = new RegExp(String.raw`^create\s+policy\s+("[^"]+"|\S+)\s+on\s+${IDENT}(.*)$`, "i");
const CREATE_VIEW_RE = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "i");
const CREATE_FUNCTION_RE = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?function\s+${IDENT}`, "i");

// Pull the parenthesised expression after USING / WITH CHECK.
function clauseExpression(text, keyword) {
  const match = new RegExp(String.raw`\b${keyword}\s*\(`, "i").exec(text);
  if (!match) return null;
  let depth = 1;
  let i = match.index + match[0].length;
  const start = i;
  while (i < text.length && depth > 0) {
    if (text[i] === "(") depth += 1;
    if (text[i] === ")") depth -= 1;
    i += 1;
  }
  return text.slice(start, i - 1).trim();
}

function parsePolicy(rest) {
  const command = (rest.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1] || "all").toLowerCase();
  const rolesMatch = rest.match(/\bto\s+([\w",\s]+?)(?=\s+(using|with\s+check)\b|$)/i);
  const roles = rolesMatch ? rolesMatch[1].split(",").map((role) => role.replace(/"/g, "").trim().toLowerCase()) : ["public"];
  const restrictive = /\bas\s+restrictive\b/i.test(rest);
  return {
    command,
    roles,
    restrictive,
    using: clauseExpression(rest, "using"),
    withCheck: clauseExpression(rest, "with\\s+check")
  };
}

function isAlwaysTrue(expression) {
  return expression != null && /^\(*\s*true\s*\)*$/i.test(expression);
}

function analyzeProject(files) {
  const sqlFiles = files.filter((file) => /\.sql$/i.test(file.path));
  if (!sqlFiles.length) return [];
  const usesSupabase =
    sqlFiles.some((file) => SUPABASE_SQL_RE.test(file.path)) ||
    files.some((file) => /(^|\/)package\.json$/.test(file.path) && file.content.includes("@supabase/"));
  if (!usesSupabase) return [];

  const findings = [];
  const tables = new Map();
  const rlsEnabled = new Set();

  for (const file of sqlFiles) {
    for (const statement of splitStatements(file.content)) {
      const { text, line } = statement;
      const loc = { file: file.path, line };

      const table = text.match(CREATE_TABLE_RE);
      if (table) {
        const { schema, name } = parseName(table[1]);
        if (schema === "public") tables.set(name, loc);
        continue;
      }

      const enable = text.match(ENABLE_RLS_RE);
      if (enable) {
        rlsEnabled.add(parseName(enable[1]).name);
        continue;
      }

      const policyMatch = text.match(CREATE_POLICY_RE);
      if (policyMatch) {
        const policyName = policyMatch[1].replace(/"/g, "");
        const target = parseName(policyMatch[2]);
        const policy = parsePolicy(policyMatch[3]);
        if (policy.restrictive) continue;
        const isWrite = policy.command !== "select";
        const anonReachable = policy.roles.some((role) => role === "anon" || role === "public");
        const expressions = [policy.using, policy.withCheck].filter((expr) => expr != null);
        const alwaysTrue = expressions.some(isAlwaysTrue);
        const userScoped = expressions.some((expr) => USER_SCOPE_RE.test(expr));
        const where = `${target.schema}.${target.name}`;

        if (isWrite && alwaysTrue) {
          findings.push(buildFinding({
            rule: "supabase.rls_policy_write_true",
            severity: anonReachable ? "critical" : "high",
            title: `RLS policy "${policyName}" lets ${anonReachable ? "anyone" : "any signed-in user"} ${policy.command} any row of ${where}`,
            category: "Database & Storage",
            ...loc,
            evidence: `${file.path}:${line} create policy "${policyName}" on ${where} for ${policy.command} … (true)`,
            fix: `Scope the policy to the row owner, e.g. using (auth.uid() = user_id) with check (auth.uid() = user_id). A (true) ${policy.command} policy means the anon key in your frontend can modify every row.`,
            references: [DOCS],
            ruleType: "ast_match",
            signal: 6
          }));
        } else if (isWrite && !userScoped && expressions.length) {
          findings.push(buildFinding({
            rule: "supabase.rls_policy_not_user_scoped",
            severity: "high",
            title: `RLS ${policy.command} policy "${policyName}" on ${where} never checks auth.uid()`,
            category: "Database & Storage",
            ...loc,
            evidence: `${file.path}:${line} create policy "${policyName}" on ${where} for ${policy.command} — no auth.uid() / auth.jwt() in USING or WITH CHECK`,
            fix: "Write policies should compare the row's owner column to auth.uid() (or a claim from auth.jwt()). Otherwise any user can modify rows that aren't theirs.",
            references: [DOCS],
            ruleType: "semantic_match",
            signal: 1
          }));
        } else if (!isWrite && alwaysTrue && anonReachable) {
          findings.push(buildFinding({
            rule: "supabase.rls_policy_public_read",
            severity: "medium",
            title: `RLS policy "${policyName}" makes every row of ${where} readable with the anon key`,
            category: "Database & Storage",
            ...loc,
            evidence: `${file.path}:${line} create policy "${policyName}" on ${where} for select using (true)`,
            fix: "Fine for genuinely public content (blog posts, product catalogue). If the table holds anything per-user — emails, billing, private notes — restrict it with using (auth.uid() = user_id).",
            references: [DOCS],
            ruleType: "ast_match",
            signal: 0
          }));
        }
        continue;
      }

      const view = text.match(CREATE_VIEW_RE);
      if (view) {
        const { schema, name } = parseName(view[1]);
        if (schema === "public" && !/security_invoker\s*=\s*(true|on)/i.test(text) && !/materialized/i.test(text.slice(0, 40))) {
          findings.push(buildFinding({
            rule: "supabase.view_bypasses_rls",
            severity: "high",
            title: `View public.${name} runs with its owner's rights and bypasses RLS`,
            category: "Database & Storage",
            ...loc,
            evidence: `${file.path}:${line} create view public.${name} without security_invoker`,
            fix: `Create it as create view public.${name} with (security_invoker = true) as … (Postgres 15+), or move it out of the exposed public schema.`,
            references: ["https://supabase.com/docs/guides/database/database-advisors?lint=0010_security_definer_view"],
            ruleType: "ast_match",
            signal: 2
          }));
        }
        continue;
      }

      const fn = text.match(CREATE_FUNCTION_RE);
      if (fn && /\bsecurity\s+definer\b/i.test(text) && !/\bset\s+search_path\b/i.test(text)) {
        const { schema, name } = parseName(fn[1]);
        findings.push(buildFinding({
          rule: "supabase.security_definer_search_path",
          severity: "medium",
          title: `SECURITY DEFINER function ${schema}.${name} has no fixed search_path`,
          category: "Database & Storage",
          ...loc,
          evidence: `${file.path}:${line} create function ${schema}.${name} … security definer (no set search_path)`,
          fix: "Add set search_path = '' (and schema-qualify every table inside), so a caller can't shadow tables and run code with the function owner's privileges.",
          references: ["https://supabase.com/docs/guides/database/database-advisors?lint=0011_function_search_path_mutable"],
          ruleType: "ast_match",
          signal: 2
        }));
      }
    }
  }

  for (const [name, loc] of tables) {
    if (rlsEnabled.has(name)) continue;
    findings.push(buildFinding({
      rule: "supabase.rls_not_enabled",
      severity: "critical",
      title: `Table public.${name} is created without row level security`,
      category: "Database & Storage",
      ...loc,
      evidence: `${loc.file}:${loc.line} create table public.${name} — no "alter table … enable row level security" in any migration`,
      fix: `Add alter table public.${name} enable row level security; and policies scoped with auth.uid(). Without RLS, anyone with your anon key (it ships in your frontend) can read and write every row.`,
      references: [DOCS],
      ruleType: "ast_match",
      signal: 6
    }));
  }

  return findings;
}

module.exports = { analyzeProject, splitStatements };
