# Roadmap

This is the honest list. Items at the top are committed; items near the bottom are aspirations.

## Now (v0.4 — landing this branch)

- [x] **Vibe-coder-specific rule packs.** Next.js App Router (server actions, route handlers, middleware), Supabase (service-role abuse, RLS bypass, storage), Stripe (webhook + idempotency), Clerk (svix + null checks).
- [x] **Intra-procedural taint tracking** for JS/TS. Track tainted identifiers across statements within a function and flag when they reach a sink (`db.query`, `exec`, `redirect`, `dangerouslySetInnerHTML`, etc).
- [x] **`vibeshield` CLI.** Runs the scanner against a local directory with no API server required. SARIF output for CI integration.
- [x] **Benchmark fixture.** A deliberately broken Next.js + Supabase + Stripe repo we scan to verify we catch the obvious bugs.

## Next (v0.5)

- [ ] **GitHub Action** that runs the CLI and posts PR comments without needing the GitHub App.
- [ ] **More secret patterns**: Twilio, SendGrid, Resend, Firebase admin, GCP service accounts, Azure connection strings, MongoDB / PostgreSQL connection URLs in code, Cloudinary, Mux, Algolia.
- [ ] **Webhook signature checks for Clerk (svix), Slack signing secret, GitHub `X-Hub-Signature-256`, Discord ed25519.**
- [ ] **Better dependency scanning**: parse `yarn.lock` and `pnpm-lock.yaml` content. Surface transitive vulnerabilities.
- [ ] **Pre-commit hook** via `husky` template / `lefthook` config.

## After that (v0.6+)

- [ ] **Inter-procedural taint tracking** within a file (follow values across functions in the same module).
- [ ] **Python AST analyzer** via Tree-sitter or a Python sidecar process.
- [ ] **Ruby AST analyzer** likewise.
- [ ] **Supabase RLS policy linter** for `.sql` files in `supabase/migrations/`. Detect policies that allow anon access, missing `auth.uid() =` checks, write policies with no scoping.
- [ ] **Server-rendered XSS rules** for Next.js metadata / OG image generation / `notFound()` paths.
- [ ] **Race condition detection** around Stripe charge creation, balance updates, and credit deductions.

## Aspirations (no timeline)

- [ ] **VS Code extension** that shows findings inline as you save.
- [ ] **IDE-side ignore comments** (`// vibeshield: ignore <rule>`).
- [ ] **Custom rules** authored in YAML, similar to Semgrep's rule format.
- [ ] **Recall benchmarking** against OWASP Juice Shop, Damn Vulnerable Node App, and real open-source SaaS repos.
- [ ] **Multi-language LSP server** for inline diagnostics.

## What we are explicitly **not** doing

- **Enterprise SSO, SAML, SCIM.** Not the audience.
- **Compliance certifications.** No SOC 2, ISO 27001, FedRAMP. Honest answer: no.
- **A paid tier.** Free forever. If commercial backing is ever needed it'll be transparent before any feature gets paywalled.
- **DAST / runtime / IAST.** Static-only.
- **A "VibeShield AI" upsell.** No.
