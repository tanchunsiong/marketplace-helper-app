# Marketplace Helper App

Backend for a Zoom General App that requests Marketplace admin scopes and helps authorized customer accounts create, read, update, and delete Zoom Marketplace apps from MCP clients such as Claude Code and Codex.

All URLs below are paths relative to `BASE_URL`, the public URL of this service.

## OAuth Redirect

The Zoom redirect URI is `BASE_URL` + `/oauth/callback`. Set it with `ZOOM_REDIRECT_URI`. The value must match the redirect URL configured in the Zoom Marketplace app exactly.

## Public Pages

Pages served by this app:

- `/`
- `/docs`
- `/privacy`
- `/terms`
- `/support`
- `/security`

The HTML in `public/` is rendered with placeholders filled from the environment (`APP_NAME`, `SUPPORT_HOURS`,
`POLICY_EFFECTIVE_DATE`; see Configuration), so the repository contains no operator-specific text.
`/robots.txt` and `/sitemap.xml` are generated from `BASE_URL`.

The `docs/` folder is served under `/architecture`. It holds the architecture diagram (HTML, PNG, PDF) linked from
`/docs`, plus sample Marketplace listing assets: `docs/icons`, `docs/cover`, and `docs/gallery`. Replace those
with your own artwork if you reuse this project.

Support requests are submitted through `/support`, encrypted with the rest of the local application state,
and removed after 30 days or earlier when resolved.

## Deauthorization

Zoom calls `/webhooks/deauthorization` when a user removes the app. Users should never call it directly.
Configure `BASE_URL` + `/webhooks/deauthorization` as the Deauthorization Notification endpoint in the Zoom Marketplace app.

The endpoint verifies Zoom's `x-zm-signature` HMAC using `ZOOM_WEBHOOK_SECRET_TOKEN`.
Set that value to the Secret Token shown in the Zoom Marketplace app's webhook settings. A valid
`app_deauthorized` event removes the matching installation, encrypted Zoom token set, MCP access tokens,
refresh tokens, and pending authorization codes.

## Setup

Requires Node.js 20 (`package.json` allows `>=20`, but only Node 20 has been tested; an install under Node 26 was
incomplete). A build toolchain may be needed for the native SQLite dependency.

```bash
npm install
cp .env.example .env
npm start
```

The app reads `.env` from its working directory. Run it from the repository root.

## Process Management

Production runs as a PM2 process started from the repository root:

```bash
pm2 start ecosystem.config.cjs
pm2 save
```

`ecosystem.config.cjs` runs `src/server.js` as the `marketplace-helper-app` process from the repository root.
It uses whichever `node` is on the PATH, so start PM2 from a shell using Node 20.

After changing `.env`, restart the process:

```bash
pm2 restart marketplace-helper-app
```

Do not place secrets in the repository or on the PM2 command line.

## Configuration

`BASE_URL` is the public URL of this helper service and is used for OAuth and MCP discovery.
`ZOOM_API_URL` is separate and is the complete Zoom REST API base URL. Set it when
using a development API host or a host whose URL already includes `/v2`.

Required `.env` values:

- `BASE_URL`
- `ZOOM_CLIENT_ID`
- `ZOOM_CLIENT_SECRET`
- `ZOOM_AUTHORIZATION_URL`
- `ZOOM_TOKEN_URL`
- `ZOOM_API_URL` (complete Zoom REST API base, including `/v2`)
- `ZOOM_REDIRECT_URI`
- `SESSION_SECRET`
- `MCP_RESOURCE_URL` (`BASE_URL` + `/mcp`)
- `MARKETPLACE_HELPER_API_KEY`
- `ZOOM_WEBHOOK_SECRET_TOKEN` (the Zoom webhook Secret Token used to verify deauthorization events)

Optional `.env` values:

- `PORT` (defaults to `3025`)
- `APP_NAME` (name shown on the public pages; defaults to `Marketplace Helper`)
- `SUPPORT_HOURS` (sentence shown on the support page describing response times)
- `POLICY_EFFECTIVE_DATE` (shown on the privacy and terms pages; the line is omitted when unset)

Local encrypted storage values:

- `LOCAL_DB_PATH` (defaults to `data/marketplace-helper.sqlite`)
- `TOKEN_ENCRYPTION_KEY` (recommended: random 32-byte base64 or 64-character hex key)

Privacy-preserving usage audit values:

- `USAGE_AUDIT_LOG_PATH` (defaults to `logs/usage-audit.jsonl`)
- `USAGE_AUDIT_MAX_BYTES` (defaults to 10 MiB per file)
- `USAGE_AUDIT_RETAINED_FILES` (defaults to 10 rotated files)

If the legacy `TOKEN_STORE_PATH` file exists during the first startup after the encrypted-storage migration, it is
imported into the encrypted SQLite database and removed only after the encrypted write succeeds.

## Usage Audit

Each MCP tool invocation writes one JSON Lines record containing only its timestamp, tool name,
success status, latency, and upstream HTTP status. Arguments, responses, tokens, account IDs,
app IDs, and app data are never written to this audit log. Files are created with owner-only
permissions and rotate at the configured size.

Summarize retained usage by UTC date, tool, and outcome without displaying request data:

```bash
npm run usage:report
```

## OAuth Flow

Open `/oauth/start` in a browser. Zoom redirects back to `/oauth/callback`, where the app exchanges the authorization code
and stores the account token set in the encrypted local SQLite database.

## MCP Server

This service exposes a remote Streamable HTTP MCP server at `/mcp`.

An MCP client such as Claude Code or Codex discovers the OAuth metadata, registers a public PKCE client, and opens the helper
authorization flow. The helper then sends the user to Zoom. After Zoom redirects to `/oauth/callback`, the helper stores the Zoom
access and refresh tokens server-side and returns a one-time helper authorization code to the MCP client. The raw Zoom token is
never returned to the MCP client or placed in a browser URL.

OAuth discovery and authorization endpoints:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`
- `/oauth/register`
- `/oauth/authorize`
- `/oauth/token`

The MCP client callback is owned by the client and is not the Zoom redirect URI. Remote MCP servers do not require a fixed
localhost callback.

For Claude Code, add the remote server and then run `/mcp` to complete browser-based OAuth:

```bash
claude mcp add --transport http zoom-marketplace-helper <BASE_URL>/mcp
```

### Tools

- `marketplace_list_apps`
- `marketplace_create_app`
- `marketplace_get_app`
- `marketplace_delete_app`
- `marketplace_validate_manifest`
- `marketplace_export_app_manifest`
- `marketplace_update_app_manifest`

Marketplace app creation routing:

- `general` and `s2s_oauth` use `POST /v2/marketplace/apps`.
- Standalone Meeting SDK app creation is not exposed. Create a General App and configure its
  Meeting SDK capability through the manifest instead.
- Deletion uses `DELETE /v2/marketplace/apps/{appId}` and verifies that the app is no longer readable.

The protected REST wrapper follows the same routing rules. For `POST /api/marketplace/apps`,
set `app_type` in the JSON body.

### Scopes

The MCP client requests two helper scopes, plus `offline_access` for refresh tokens:

- `marketplace:read` is required by `marketplace_list_apps`, `marketplace_get_app`, `marketplace_validate_manifest`, and `marketplace_export_app_manifest`.
- `marketplace:write` is required by `marketplace_create_app`, `marketplace_delete_app`, and `marketplace_update_app_manifest`.

These helper scopes only gate access to the MCP tools. The Zoom Marketplace app itself must also be granted the
granular Zoom scopes the tools call:

- `marketplace:read:list_apps:admin`
- `marketplace:read:app:admin`
- `marketplace:write:app:admin`
- `marketplace:write:app:master`

### Errors

MCP tool failures are returned as JSON-RPC tool results with `isError: true`; the outer MCP
HTTP response can still be `200`. The result includes the upstream HTTP status when available.
Manifest validation is intentionally different: Zoom can return HTTP `200` with `ok: false`
and field-level validation errors, which the validation tool returns as data rather than a tool
transport error.

## Protected API

Every API call below requires:

```text
x-api-key: $MARKETPLACE_HELPER_API_KEY
```

If exactly one account has authorized the app, `account_id` is optional. Otherwise pass `account_id` as a query parameter or `x-zoom-account-id` header.

Supported endpoints:

- `GET /api/installations`
- `GET /api/support/requests`
- `DELETE /api/support/requests/:requestId`
- `GET /api/marketplace/apps`
- `POST /api/marketplace/apps`
- `GET /api/marketplace/apps/:appId`
- `DELETE /api/marketplace/apps/:appId`
- `POST /api/marketplace/apps/manifest/validate`
- `GET /api/marketplace/apps/:appId/manifest`
- `PUT /api/marketplace/apps/:appId/manifest`

Unauthenticated endpoints:

- `GET /api/status` returns the service name, whether it is configured, and its configured OAuth, MCP, and deauthorization URLs. It returns no secrets or account data.
- `POST /api/support/requests` accepts name, email, and issue fields from the same-origin support form. It uses a 16 KB body limit,
  honeypot and minimum-completion checks, per-source and per-email hourly/daily quotas, and a global daily cap.

## Development

```bash
npm run check          # syntax check
npm test               # unit tests
npm run security:audit # npm audit for production dependencies (run manually)
```

## Security Notes

- Do not commit `.env`, `data/`, or `logs/`.
- Set `TOKEN_ENCRYPTION_KEY` to a random 32-byte base64 or 64-character hex value and store it in deployment secrets.
- The database state is encrypted with AES-256-GCM before it is written to SQLite. The service also uses owner-only
  database file permissions (`0600`) and keeps the database outside the public web root.
- Serve this service only over HTTPS (TLS 1.2 or higher) before running OAuth.
- Rotate the API key if exposed.

## License

MIT. See [LICENSE](LICENSE).
