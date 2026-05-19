# Security Policy

VibeShield is a public prototype of a security scanning product. Do not submit real private repositories or secrets to any hosted demo unless a production backend, data processing agreement, and retention controls are in place.

## Intended production safeguards

- Read-only GitHub App permissions by default
- Ephemeral per-scan workers
- Short, customer-visible source retention
- Secret detection and redaction before storage or model analysis
- Customer-visible audit logs for repository and report access
- Explicit opt-in for patch-writing permissions

## Reporting vulnerabilities

For now, use GitHub private vulnerability reporting once enabled for the repository. If unavailable, open a minimal GitHub issue that does not include exploit details or secrets, and coordinate disclosure privately before posting technical reproduction steps.
