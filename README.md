# VibeShield Security

A standalone SaaS prototype for scanning vibe-coded apps and GitHub repositories against common security failures: broken access control, missing auth middleware, JWT misuse, SQL/NoSQL injection, exposed secrets, weak Supabase RLS, unsafe webhooks, open CORS, mass assignment, predictable tokens, and more.

## Run locally

```bash
cd ~/Desktop/vibeshield-security
npm run start
```

Then open:

```text
http://localhost:4173
```

No package install is required. The app uses static HTML, CSS, JavaScript, and Vercel-compatible Node API functions.

## Publish

This project is deployed on Vercel at:

```text
https://vibeshield-security.vercel.app
```

It can also be deployed as a static site on GitHub Pages, Netlify, Cloudflare Pages, or any static host.

Build check:

```bash
npm run build
```

For GitHub Pages, set the Pages source to the repository root on the default branch.

## What is included

- Secure repository intake flow with GitHub URL, upload, and paste-code modes
- Backend scanner API across auth, injection, data exposure, validation, XSS, database/storage, keys, infra, and business logic
- Findings dashboard with severity, confidence, evidence, owner, and remediation
- Trust center explaining isolation, retention, secret redaction, and least-privilege GitHub access
- Policy checklist for security controls that vibe-coded apps commonly miss
- SEO metadata, favicon, web manifest, robots.txt, sitemap.xml, 404 page, security page, privacy page, and license
- GitHub App setup guide for read-only private repository scanning
- Explicit scan result lookup and deletion endpoints

## Production backend notes

The current public build has a real deterministic backend scanner. Before accepting customer private repositories at scale, add:

- Persistent tenant/account mapping for GitHub installation IDs
- Durable scan-result storage with encryption at rest
- Customer-visible deletion controls and audit logs
- Webhook signature verification for GitHub App events
- Queue-backed workers for large repositories
- External dependency CVE provider integration
- Webhook signature verification and replay protection
