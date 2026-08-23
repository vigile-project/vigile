# Vigile web portal

Minimal admin portal (ISS-032) — a single self-contained HTML page
(no CDN, no external JavaScript, no build step) served alongside the
API. Talks to `/admin/v1/*` with a bearer token.

## Current features

- Token-based login
- Server status (health, audit entry count, chain head hash)
- Audit journal (last 50 entries, chronological)
- Chain integrity verification (calls `/admin/v1/audit/verify`)

## Serving

The page is designed to be served by `vigile-server` at the root
(`/`) alongside the API endpoints. In development, any static file
server works (the page uses `window.location.origin` for API calls).

## Full portal (DEC-06)

The production portal will be a TypeScript strict + React project
with:
- OIDC/MFA authentication
- Agent inventory browser
- Policy editor with live simulation
- Deployment ring management
- Approval workflow UI

The single-file approach is deliberate for the MVP: zero dependencies,
zero build complexity, trivially auditable. See SPRINT_8.md §ISS-032.
