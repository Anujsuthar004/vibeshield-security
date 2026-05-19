# GitHub App Setup

VibeShield scans private repositories through a GitHub App with read-only permissions.

## Required GitHub App permissions

Repository permissions:

- Contents: read
- Metadata: read

Optional future permissions:

- Pull requests: read and write, only if patch comments or pull request fixes are enabled
- Checks: read and write, only if scan status checks are enabled

Do not request write permissions for the default scanner flow.

## Vercel environment variables

Set these in Vercel Project Settings > Environment Variables:

```text
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
GITHUB_INSTALLATION_ID=12345678
SCAN_RETENTION_HOURS=24
```

`GITHUB_INSTALLATION_ID` may also be sent per scan if you later add multi-tenant account mapping.

## Scanner behavior

- Creates a short-lived GitHub App JWT
- Exchanges it for an installation token
- Reads repository metadata, tree entries, and text blobs
- Scans a bounded subset of text files
- Redacts secret-looking values in evidence
- Stores findings only until the retention window expires
- Deletes the per-scan worker directory after each run

## API endpoints

- `GET /api/health` checks scanner readiness
- `POST /api/scans` runs a paste or GitHub repository scan
- `GET /api/scans/:id` retrieves a retained scan result
- `DELETE /api/scans/:id` deletes a retained scan result early
