const test = require("node:test");
const assert = require("node:assert/strict");

const { analyzeProject, splitStatements } = require("../api/_lib/analyzers/supabase-rls");

const sql = (path, content) => ({ path, content, size: content.length });
const rules = (files) => analyzeProject(files).map((f) => `${f.rule} @ ${f.file}:${f.line}`);

test("statement splitter ignores semicolons in strings, comments and $$ bodies", () => {
  const statements = splitStatements(`-- a; comment
create function f() returns void as $body$ begin perform 1; end; $body$ language plpgsql;
insert into t values ('a;b', 'it''s');
/* multi;
line */ select 1;`);
  assert.deepEqual(statements.map((s) => s.line), [2, 3, 5]);
  assert.match(statements[0].text, /^create function f\(\)/);
});

test("non-Supabase projects are not checked for RLS", () => {
  assert.deepEqual(rules([sql("db/schema.sql", "create table users (id int);")]), []);
});

test("package.json with @supabase marks SQL anywhere as Supabase", () => {
  const files = [
    { path: "package.json", content: '{"dependencies":{"@supabase/supabase-js":"2.0.0"}}' },
    sql("db/schema.sql", "create table accounts (id int);")
  ];
  assert.deepEqual(rules(files), ["supabase.rls_not_enabled @ db/schema.sql:1"]);
});

test("tables outside the public schema don't need RLS", () => {
  assert.deepEqual(rules([sql("supabase/migrations/1.sql", "create table private.audit (id int);")]), []);
});

test("RLS enabled in a later migration counts, regardless of quoting and case", () => {
  const files = [
    sql("supabase/migrations/1.sql", 'CREATE TABLE "Orders" (id int);'),
    sql("supabase/migrations/2.sql", "ALTER TABLE ONLY public.orders ENABLE ROW LEVEL SECURITY;")
  ];
  assert.deepEqual(rules(files), []);
});

test("write policies: (true) to anon is critical, user-scoped is fine, restrictive is skipped", () => {
  const files = [
    sql(
      "supabase/migrations/1.sql",
      `create table public.posts (id int, user_id uuid);
alter table public.posts enable row level security;
create policy "anon insert" on posts for insert to anon with check (true);
create policy "own update" on posts for update to authenticated using (auth.uid() = user_id);
create policy "block" on posts as restrictive for delete using (false);`
    )
  ];
  const found = analyzeProject(files);
  assert.deepEqual(found.map((f) => [f.rule, f.severity, f.line]), [["supabase.rls_policy_write_true", "critical", 3]]);
});
