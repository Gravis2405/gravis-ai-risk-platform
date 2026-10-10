# GRAVIS AI Risk Protection

GRAVIS AI is a digital-risk analyst workspace with a responsive dashboard, threat queue, case workflow, brand tracking list, analytics, workspace settings, individual member accounts, authenticated API, Socket.IO updates, and CSV export.

## Run locally

Requires Node.js 20 or newer.

1. Copy .env.example to .env. For local development, the defaults work; change secrets before exposing the app to a network.
2. Install dependencies with npm install.
3. Start with npm start.
4. Open http://localhost:5000.

Local demo sign-in: analyst@gravis.demo / GravisDemo!2026. Change this password before putting real information in the workspace.

Application data is saved in data/gravis.json. Back up this file before moving or replacing it. DATA_FILE can point to a different location.

## Member accounts

Sign in as a workspace administrator, open **Settings → Workspace members**, and create a named account for each person. Each account has its own email, password, and analyst or administrator role. New accounts can sign in immediately. Share their initial password through a secure channel; the app does not send email or perform email verification. Administrators can change roles or disable and re-enable accounts. The workspace must always retain one active administrator.

Analysts can work with the shared workspace records. This starter does not provide separate customer tenants or per-record permissions.

## Production startup configuration

Set these environment variables in the host's secret/configuration panel:

- NODE_ENV=production
- PORT to the port supplied by the host
- APP_ORIGIN=https://your-domain.example (comma-separated HTTPS origins are accepted)
- JWT_SECRET to a unique random value at least 32 characters long
- INGEST_API_KEY to a separate unique random value
- DATA_FILE to a path on the host's durable persistent disk
- INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD for first startup only, when the data file has no accounts

The first production startup creates an empty workspace and the initial administrator. Once the data file has been created and confirmed, remove the two initial-admin variables from the host configuration. Never deploy the local demo data file.

The included Dockerfile builds the app for a container host. Mount a durable writable volume at /var/lib/gravis, provide the production environment variables above, deploy a single instance, and set the exact HTTPS site origin in APP_ORIGIN. Configure the host's health check to GET /api/health. A temporary URL is only available after the host finishes building and starting the service.

This release persists data to one JSON file and is suitable only for a single Node process with durable disk attached. It cannot safely support multiple application instances or workers. Use PostgreSQL or another managed database, automated backups, and a migration before scaling or relying on the service for operational data. A hosting plan must keep the service running and retain its persistent disk to meet uptime and data-retention needs.

## Current platform scope

- Analysts can add threat records, update case statuses, write notes, track brand assets, review aggregate analytics, and export CSV.
- Administrators can manage workspace settings and member accounts.
- Passwords are hashed. API sessions use eight-hour signed tokens. Login attempts are throttled in each server process.
- Newly added and updated records are broadcast to authenticated sessions in the same workspace.

The app does not crawl the web or connect to social networks, app stores, phishing feeds, email delivery, identity verification, or an operational alerting service. Brand assets organize a tracking list only. Seeded sample URLs use the reserved .example domain. Risk scores are baseline rules and need evaluation against labeled threat data before operational decisions depend on them.

## API

- GET /api/health — service status.
- POST /api/auth/login, GET /api/auth/me, POST /api/auth/change-password — sign-in and account details.
- GET /api/users, POST /api/users, PATCH /api/users/:id — administrator-only member management.
- GET /api/dashboard/summary, GET /api/threats, GET /api/threats/:id — workspace dashboard and investigations.
- POST /api/threats, PATCH /api/threats/:id/status, POST /api/threats/:id/notes — investigation workflow.
- GET /api/brands, POST /api/brands, DELETE /api/brands/:id — workspace brand list.
- GET /api/analytics?days=30 — daily, severity, channel, and status counts.
- GET /api/settings, PATCH /api/settings — settings (admin only for updates).
- POST /api/threats/ingest — server-to-server ingestion protected by X-Ingest-Key.
- Socket.IO — authenticated with an auth token; emits new_threat_detected and threat_updated.
