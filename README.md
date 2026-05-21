# VibeShield Security

Static security scanner for vibe-coded SaaS and AI-built applications. AST-based JS/TS analysis, language-specific rule sets for Python/Ruby/Go/PHP/SQL, dependency CVE matching via OSV, GitHub App integration with PR comments and patch branches, PDF/email reports, and a multi-tenant dashboard.

**VibeShield is free to use.** No paid tiers, no checkout, no upsell — every feature is available to every workspace.

## Quick start (local)

```bash
npm install
npm run dev
# open http://localhost:4173/app.html
```

- The dashboard works out of the box on a file-backed JSON DB in `/tmp/vibeshield-data/`.
- Public repository scans work without any GitHub configuration.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | Postgres connection string. When set, schema is auto-migrated. | unset → file-backed JSON |
| `PGSSL` | Set to `disable` to skip SSL when connecting to local Postgres. | enabled |
| `GITHUB_APP_ID` + `GITHUB_PRIVATE_KEY` | Enables private repo scans and PR integration. | unset → public only |
| `GITHUB_INSTALLATION_ID` | Default installation if requests do not pass one. | unset |
| `GITHUB_WEBHOOK_SECRET` | Required to receive `/api/webhooks?provider=github`. | unset |
| `SMTP_HOST` + `SMTP_USER` + `SMTP_PASS` (+ optional `SMTP_PORT`, `SMTP_SECURE`, `SMTP_FROM`) | Enables email delivery of PDF reports. | unset |
| `DISALLOW_ANONYMOUS_SCANS` | If `true`, every scan must be authenticated. | anonymous quick-scans allowed |
| `VIBESHIELD_DATA_DIR` | Override file-backed storage root. | OS temp dir |

Run `npm run migrate` after setting `DATABASE_URL` to confirm the schema applies cleanly.

## HTTP API

| Endpoint | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/health` | GET | — | Service feature flags and readiness. |
| `/api/auth?action=signup\|login\|logout\|me` | POST/GET | mixed | Account flow. |
| `/api/keys` | GET/POST/DELETE | session | Manage API keys. |
| `/api/scans` | POST | API key or session (anonymous allowed for public/paste) | Run a scan. |
| `/api/scans` | GET | session/API key | Workspace history. |
| `/api/scans/{id}` | GET/DELETE | session/API key | Fetch or delete a scan. |
| `/api/scans/{id}/diff?against=...` | GET | session/API key | Diff against another scan in the same workspace. |
| `/api/scans/{id}/suppress?finding=...` | POST | session/API key | Suppress a finding. |
| `/api/suppressions` | GET/POST/DELETE | session/API key | Workspace-wide suppression rules. |
| `/api/repositories` | GET/POST/DELETE | session/API key | Manage repo connections (used by the webhook handler). |
| `/api/reports?action=pdf\|email` | GET/POST | session/API key | Export PDF or email report. |
| `/api/pr?action=comment\|patch` | POST | session/API key | Post PR summary or open patch branch + PR. |
| `/api/webhooks?provider=github` | POST | HMAC | GitHub push / pull_request scans. |

All authenticated endpoints accept either `Authorization: Bearer <vss_…>` API key or the session cookie set by `/api/auth?action=login`.

## Scanner features

- **AST analysis for JS/TS** using `@babel/parser`. Detects token storage, hardcoded JWT secrets, mass assignment, predictable randomness, `dangerouslySetInnerHTML`, CORS wildcards, SQL injection via template/concat, shell exec from user input, `eval`/`Function`, webhook signature gaps, and secret literals.
- **Per-language rules** for Python, Ruby, Go, PHP, and SQL, including Django/Flask/Rails/Gin/Express patterns.
- **Dependency CVE matching** against `osv.dev` for npm, PyPI, RubyGems, Go, Packagist, Maven. No API key required.
- **Suppression** via `.vibeshield.ignore` (path/rule/finding patterns) committed in the repository, or via workspace suppression API.
- **Confidence calibration** derived from rule type (`literal_credential`, `ast_match`, `semantic_match`, `regex_match`, `dependency_cve`, `inference`) with per-rule signal adjustment.
- **PR integration** that opens an isolated `vibeshield/fixes-*` branch with fix guidance and (optionally) opens a pull request back to the default branch.
- **PDF reports** rendered with `pdfkit`. Email delivery uses `nodemailer` when SMTP is configured.

## Trust model

- Source files are processed in single-use worker directories and removed at the end of each scan.
- Findings store redacted evidence (secret-looking strings masked) and fingerprints — never raw secret values.
- API keys are stored as SHA-256 hashes; the plain text key is shown once at creation and never persisted.
- Audit logs record every state-changing action with actor and timestamp.

See `security.html`, `privacy.html`, `terms.html`, and `dpa.html` for the customer-facing documents.
