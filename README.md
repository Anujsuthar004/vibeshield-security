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

No package install is required. The app is static HTML, CSS, and JavaScript.

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
- Scan simulation across auth, injection, data exposure, validation, XSS, CSRF, database/storage, supply chain, keys, infra, and business logic
- Findings dashboard with severity, confidence, evidence, owner, and remediation
- Trust center explaining isolation, retention, secret redaction, and least-privilege GitHub access
- Policy checklist for security controls that vibe-coded apps commonly miss
- SEO metadata, favicon, web manifest, robots.txt, sitemap.xml, 404 page, security page, privacy page, and license

## Production backend notes

The current public build is a static demo. Before accepting real private repositories, add:

- GitHub App OAuth with read-only repository permissions
- Ephemeral scan workers with tenant isolation
- Secret redaction before model calls or evidence storage
- Configurable source retention and deletion controls
- Audit logs for repository access, scan exports, and patch actions
- Webhook signature verification and replay protection
