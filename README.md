# VibeShield Security

A free, open-source security scanner aimed at **vibe coders** — solo founders and small teams shipping Next.js + Supabase + Stripe SaaS apps built mostly with AI assistance.

**Status: v0.4, alpha.** Useful as a pre-deploy sanity check for the Next.js + Supabase + Stripe + Clerk stack. Not a replacement for Semgrep, Snyk Code, or CodeQL.

Live demo and dashboard: <https://vibeshield-security.vercel.app>

---

## What it actually does today

| Capability | Status |
| --- | --- |
| AST-based JS/TS analysis (`@babel/parser`) | 17 core rules |
| Intra-procedural taint tracking (JS/TS) — SQL, shell, eval, redirect, fs, SSRF, XSS sinks | 7 sinks |
| Vibe-stack rule packs — Next.js App Router, Supabase, Stripe, Clerk | 11 rules |
| Python / Ruby / Go / PHP / SQL rules (regex-based, line-level) | 25 rules |
| Secret literal patterns (Stripe, GitHub, AWS, Slack, OpenAI, SendGrid, Twilio, Resend, Supabase JWT) | 11 patterns |
| `.env*` public-prefix secret detection | Yes |
| Dependency CVE matching via [osv.dev](https://osv.dev) | npm, PyPI, RubyGems, Go, Packagist, Maven |
| `.vibeshield.ignore` file + workspace-level suppression | Yes |
| Multi-tenant dashboard with auth, API keys, scan history, diff | Yes |
| PDF report export | Yes |
| GitHub App integration: private repo scans, PR comments, patch-branch PRs | Yes (when env vars set) |
| GitHub webhook (push/PR events trigger scans) | Yes (when env vars set) |
| Postgres-backed rate limiting, audit log retention, OSV cache | Yes |
| Account self-deletion (cascades across every table) | Yes |

**Total static rules: 67.** Plus dynamic CVE matches from OSV.

### Vibe-stack rules

These are the rules built specifically for the Next.js + Supabase + Stripe + Clerk stack. Each one comes from a real vibe-coded mistake.

| Rule | What it catches |
| --- | --- |
| `nextjs.route_handler_no_auth` | `app/.../route.ts` exports `GET`/`POST`/... without `auth()` / `getServerSession()` / `currentUser()` |
| `nextjs.server_action_no_auth` | `"use server"` function performs DB writes with no auth check |
| `nextjs.server_action_mass_assignment` | Server Action passes raw `formData` / `Object.fromEntries(formData)` into an ORM `update` / `create` |
| `nextjs.cookies_missing_options` | `cookies().set(...)` without `{ httpOnly, secure, sameSite }` |
| `supabase.service_role_client_side` | `"use client"` component references `SUPABASE_SERVICE_ROLE_KEY` |
| `supabase.service_role_in_client_bundle` | `createClient(url, SERVICE_ROLE_KEY)` lives in a client file |
| `supabase.auth_admin_call` | `supabase.auth.admin.*` invoked without a privilege check |
| `stripe.idempotency_missing` | `stripe.X.create()` / `update()` without `idempotencyKey` |
| `clerk.webhook_unverified` | Clerk webhook handler doesn't call `new Webhook(secret).verify(...)` (svix) |
| `clerk.current_user_no_null_check` | `await currentUser()` result dereferenced without `if (!user)` guard |
| `webhooks.unverified_signature` | Generic webhook handler reads body before signature verification |

### Taint sinks (intra-procedural, JS/TS)

We track tainted identifiers across statements within a single function. Sources include `req.body`, `request.json()`, `formData.get()`, `searchParams.get()`, Next.js `params`, and function parameters named `req`/`request`/`formData`/`params`/`searchParams`. Sinks:

| Rule | Sink |
| --- | --- |
| `taint.sql_injection` | `db.query`, `client.query`, `pool.query`, `knex.raw`, `prisma.$queryRaw`, `prisma.$executeRaw` |
| `taint.command_injection` | `exec`, `execSync`, `execFile`, `spawn`, `child_process.*` |
| `taint.code_injection` | `eval`, `Function`, `new Function` |
| `taint.open_redirect` | `redirect`, `NextResponse.redirect`, `Response.redirect`, `res.redirect` |
| `taint.path_traversal` | `fs.readFile`, `fs.writeFile`, `fs.unlink`, `fs.rm`, `fs.stat` |
| `taint.ssrf` | `fetch`, `axios.get/post`, `got.get/post` |
| `taint.xss_dangerous_html` | `dangerouslySetInnerHTML={{ __html: <tainted> }}` |

## What it does **not** do (yet)

These are honest limitations, not roadmap-marketing:

- **Intra-procedural taint only.** We follow tainted identifiers across statements within a single function, but we don't cross function boundaries. If `sanitize(x)` is in a helper, we still flag the sink.
- **No data flow across files.** A tainted value passed to an imported helper is not traced.
- **Python / Ruby / Go / PHP rules are line-by-line regex.** Variable-level reasoning is JS/TS-only.
- **No transitive dependency CVE resolution.** We read direct deps from `package.json` and a handful of lockfiles; we don't walk the full dep graph.
- **No GitHub Action yet.** CLI exists (`npx vibeshield` after `npm install`) and emits SARIF; a packaged Action is the next step.
- **Secret coverage is narrow.** Catches Stripe / GitHub / AWS / Slack / OpenAI keys. Does not catch GCP service accounts, Azure connection strings, Twilio, SendGrid, Firebase admin keys, or PostgreSQL connection URLs.
- **Webhook signature check is Stripe-shaped only.** Clerk / svix, GitHub `X-Hub-Signature-256`, Slack signing secret, Discord ed25519 — not caught yet.
- **High false positive rate on `auth.unprotected_route`.** It's keyword-based; expect to suppress some.
- **Single-maintainer project.** There is no monitored email inbox. Use [GitHub Issues](https://github.com/Anujsuthar004/vibeshield-security/issues) for everything, and [GitHub Private Vulnerability Reporting](https://github.com/Anujsuthar004/vibeshield-security/security/advisories/new) for security disclosures.

## How it compares

| Tool | Static rules | Languages | Data flow | Price | Best for |
| --- | --- | --- | --- | --- | --- |
| **VibeShield** | 67 + OSV | JS/TS (AST + intra-proc taint), Py/Rb/Go/PHP (regex) | Yes (within a function) | Free | Vibe coders, pre-deploy sanity check |
| Semgrep OSS | 2,000+ | 30+ | Limited | Free | OSS / startups |
| Semgrep Pro | 5,000+ | 30+ | Yes | $40/dev/mo | Real SAST |
| Snyk Code | proprietary, ML-trained | 20+ | Yes (taint) | $98/dev/mo | Enterprise |
| GitHub CodeQL | 1,000+ | 10 | Yes (full) | Free for OSS | Mature OSS / GitHub-first teams |
| `npm audit` | n/a | npm only | n/a | Free, built-in | First defense |

**If you already run Semgrep or Snyk, VibeShield won't beat them.** What it offers is "no setup, free, opinionated for the Next.js + Supabase + Stripe stack."

## Who this is for

- You're building a SaaS app with Cursor / Claude / v0 / Lovable, mostly in TypeScript, mostly on Vercel.
- You shipped fast and didn't think much about authentication ownership checks, RLS policies, webhook signatures, or `NEXT_PUBLIC_*` env exposure.
- You don't have time or budget for Snyk.
- You want a 60-second "is anything obvious broken" check before you put a paying customer on this.

## Who this is **not** for

- Enterprises with compliance requirements. VibeShield holds no certifications.
- Teams already running a real SAST. We don't beat them on detection.
- Anyone whose threat model includes targeted attackers. Shallow scanners miss what they go after.

---

## Quick start (local)

```bash
git clone https://github.com/Anujsuthar004/vibeshield-security.git
cd vibeshield-security
npm install
npm run dev
# open http://localhost:4173/app.html
```

The dashboard works out of the box on a file-backed JSON store in `/tmp/vibeshield-data/`. For real persistence, set `DATABASE_URL` to a Postgres connection string (Neon free tier works).

### Try a scan without an account

Open the marketing page at `http://localhost:4173`, paste a snippet of code, hit "Run quick scan." Anonymous scans don't get saved.

### CLI (no server required)

```bash
# Scan your current directory
node scripts/cli.js .

# CI-friendly SARIF output for GitHub Code Scanning
node scripts/cli.js . --sarif -o vibeshield.sarif --fail-on high

# Quiet, JSON output, no network
node scripts/cli.js . --json --no-deps --quiet
```

`vibeshield --help` lists every flag. The CLI returns exit code `1` when `--fail-on <level>` matches at least one finding, so it slots straight into a CI pipeline.

### Programmatic API

```bash
# Create an account
curl -sS -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"longpassword12","name":"You"}' \
  'http://localhost:4173/api/auth?action=signup'

# Create an API key
curl -sS -b cookies.txt -X POST 'http://localhost:4173/api/keys' \
  -H "Content-Type: application/json" -d '{"label":"local"}'

# Scan a public GitHub repo (replace <KEY>)
curl -sS -H "Authorization: Bearer <KEY>" -H "Content-Type: application/json" \
  -X POST 'http://localhost:4173/api/scans' \
  -d '{"sourceType":"github","repoUrl":"https://github.com/vercel/next.js"}'
```

## Self-hosting on Vercel

```bash
git clone https://github.com/Anujsuthar004/vibeshield-security.git
cd vibeshield-security
vercel link
vercel integration add neon --plan free
vercel deploy --prod
```

That's the entire setup. The Neon free tier covers schema + data; the schema auto-migrates on the first DB write.

### Optional environment variables

| Variable | What it unlocks |
| --- | --- |
| `DATABASE_URL` | Postgres persistence (set automatically by the Neon integration) |
| `GITHUB_APP_ID` + `GITHUB_PRIVATE_KEY` | Private repo scans |
| `GITHUB_WEBHOOK_SECRET` | `/api/webhooks?provider=github` accepts events |
| `GITHUB_INSTALLATION_ID` | Default installation if scan requests don't provide one |
| `CRON_TOKEN` | Manual cron trigger via `Authorization: Bearer <token>` |
| `AUDIT_RETENTION_DAYS` | Default 90 |
| `DISALLOW_ANONYMOUS_SCANS=true` | Forces every scan to be authenticated |

## API surface

| Endpoint | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/health` | GET | — | Service status + feature flags |
| `/api/auth?action=signup\|login\|logout\|me\|close-account` | mixed | mixed | Account flow |
| `/api/keys` | GET/POST/DELETE | session | Manage API keys |
| `/api/scans` | POST/GET | session, API key, or anonymous (paste / public GitHub) | Run + list scans |
| `/api/scans/{id}` | GET/DELETE | session/API key | Fetch / delete a scan |
| `/api/scans/{id}/diff?against=...` | GET | session/API key | Diff two scans |
| `/api/scans/{id}/suppress?finding=...` | POST | session/API key | Suppress a finding |
| `/api/suppressions` | GET/POST/DELETE | session/API key | Workspace-wide suppression rules |
| `/api/repositories` | GET/POST/DELETE | session/API key | Manage repo connections |
| `/api/reports?action=pdf` | GET | session/API key | PDF export |
| `/api/pr?action=comment\|patch` | POST | session/API key + GitHub App | PR summary / patch branch |
| `/api/webhooks?provider=github` | POST | HMAC-SHA256 | GitHub push / PR scans |
| `/api/cron` | GET/POST | Vercel cron header or `CRON_TOKEN` | Audit / session / cache purge |

API keys are passed as `Authorization: Bearer vss_...`. Session cookies are set on signup/login.

## Architecture

- **Runtime:** Vercel serverless functions, Node 20.
- **Frontend:** vanilla HTML/CSS/JS. No framework. No build step.
- **DB:** Postgres via `pg`. Schema auto-migrates on first connect. Falls back to JSON files in `/tmp` for dev.
- **Scanner:** `@babel/parser` + `@babel/traverse` for JS/TS. Per-language regex modules for Python, Ruby, Go, PHP, SQL. OSV.dev for CVE lookups (cached 24h).
- **Auth:** bcrypt-hashed passwords, SHA-256-hashed API keys, HttpOnly Secure session cookies, 14-day TTL.
- **Webhooks:** HMAC-SHA256 verification with timing-safe comparison.
- **Rate limiting:** sliding window backed by Postgres, in-memory backstop.
- **Audit:** every state-changing action logged with actor and timestamp; cron purges past `AUDIT_RETENTION_DAYS` (default 90).

## Trust posture

- Source files are processed in single-use worker directories and removed at the end of each scan.
- Stored evidence has secret-looking strings masked. Findings store fingerprints, not raw secret values.
- API keys are stored as SHA-256 hashes; the plain text key is shown once at creation and never persisted.
- Edge headers: HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, strict CSP.
- No SOC 2 / ISO 27001 claims. See [`security.html`](./security.html), [`privacy.html`](./privacy.html), [`terms.html`](./terms.html), [`dpa.html`](./dpa.html).

## Pricing

Free. Forever. No paid tier, no upsell, no "contact sales." If that ever changes you'll get 30 days warning to export and delete your data.

## Contributing

Pull requests welcome. Highest-leverage areas:

1. **New rules**, especially for the Next.js / Supabase / Stripe / Clerk stack.
2. **Intra-procedural taint tracking** for JS/TS. Track tainted identifiers across statements within a function and flag when they reach a sink.
3. **A real CLI** that emits SARIF for GitHub Code Scanning.
4. **Python / Ruby AST analyzers** via Tree-sitter or a sidecar process.
5. **Benchmarks** against vulnerable open-source apps (OWASP Juice Shop, Damn Vulnerable Node App, etc.).

See [`ROADMAP.md`](./ROADMAP.md) for what's coming next.

## License

MIT.
