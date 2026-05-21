# Security policy

VibeShield ships a static security scanner. The project takes its own security posture seriously.

## Reporting a vulnerability

- Email: security@vibeshield.example
- PGP: ask via email and we'll send the current public key.
- Response SLA: acknowledgment within 2 business days, critical remediation target within 14 days.
- Please do not file public GitHub issues for security reports.

## Scope

In scope:

- vibeshield-security.vercel.app
- The VibeShield GitHub App
- The Node API under `/api/*`

Out of scope:

- Third-party services we depend on (Vercel, GitHub, OSV, your Postgres provider, your SMTP provider).
- Findings about your own code surfaced through normal use of the scanner — those are features, not vulnerabilities.

## Hardening posture

- Passwords are bcrypt-hashed (cost 10). API keys are stored as SHA-256 hashes.
- Sessions are HttpOnly, Secure, SameSite=Lax, 14-day TTL.
- Webhook payloads must be signed with HMAC SHA-256 using `GITHUB_WEBHOOK_SECRET`.
- Edge responses set strict CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Worker directories are removed after every scan; raw source is never persisted.

## Compliance

We do not currently hold SOC 2 or ISO 27001. The roadmap is documented honestly in `dpa.html` and `security.html`. We will not claim certifications we have not earned.
