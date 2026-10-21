import express from 'express';
import crypto from 'crypto';
import fs from 'fs/promises';
import { handleMarketplaceMcpRequest } from './mcp.js';
import { createLocalDatabase } from './local-db.js';
import { createUsageAuditLogger } from './usage-audit.js';
import { templatedPages } from './pages.js';
import {
  assertClientRedirect,
  authorizationServerMetadata,
  clientCredentials,
  consumeAuthorizationCode,
  consumeRefreshToken,
  findAccessToken,
  getAuthorizationCode,
  getClient,
  issueTokens,
  protectedResourceMetadata,
  registerClient,
  requestedScopes,
  saveAuthorizationCode,
  verifyPkce,
} from './oauth-broker.js';

await loadDotenv();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback');
app.use((_req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  next();
});
app.use('/api/support/requests', express.json({ limit: '16kb' }));
app.use('/api/support/requests', express.urlencoded({ extended: false, limit: '16kb' }));
app.use(express.json({
  limit: '2mb',
  verify: (req, _res, buffer) => {
    req.rawBody = buffer.toString('utf8');
  },
}));
app.use((error, _req, res, next) => {
  if (error?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid_json' });
  }
  return next(error);
});
app.use(express.urlencoded({ extended: false }));
const SITEMAP_PATHS = ['/', '/docs', '/privacy', '/security', '/support', '/terms'];

app.get('/robots.txt', (_req, res) => {
  const lines = ['User-agent: *', 'Allow: /'];
  if (config.baseUrl) lines.push('', `Sitemap: ${config.baseUrl}/sitemap.xml`);
  res.type('text/plain').send(`${lines.join('\n')}\n`);
});

app.get('/sitemap.xml', (_req, res) => {
  const urls = SITEMAP_PATHS.map((path) => `  <url><loc>${config.baseUrl}${path}</loc></url>`).join('\n');
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
  );
});

app.use(templatedPages());
app.use(express.static('public', {
  extensions: ['html'],
  index: 'index.html',
}));
app.use('/architecture', express.static('docs', {
  index: false,
}));

const config = {
  port: Number(process.env.PORT || 3025),
  baseUrl: process.env.BASE_URL ? stripTrailingSlash(process.env.BASE_URL) : '',
  clientId: process.env.ZOOM_CLIENT_ID || '',
  clientSecret: process.env.ZOOM_CLIENT_SECRET || '',
  authorizationUrl: process.env.ZOOM_AUTHORIZATION_URL || '',
  tokenUrl: process.env.ZOOM_TOKEN_URL || '',
  redirectUri: process.env.ZOOM_REDIRECT_URI || '',
  apiUrl: process.env.ZOOM_API_URL ? stripTrailingSlash(process.env.ZOOM_API_URL) : '',
  sessionSecret: process.env.SESSION_SECRET || '',
  apiKey: process.env.MARKETPLACE_HELPER_API_KEY || '',
  databasePath: process.env.LOCAL_DB_PATH || 'data/marketplace-helper.sqlite',
  tokenEncryptionKey: process.env.TOKEN_ENCRYPTION_KEY || '',
  legacyTokenStorePath: process.env.TOKEN_STORE_PATH || 'data/tokens.json',
  webhookSecretToken: process.env.ZOOM_WEBHOOK_SECRET_TOKEN || '',
  mcpResource: process.env.MCP_RESOURCE_URL || '',
  usageAuditLogPath: process.env.USAGE_AUDIT_LOG_PATH || 'logs/usage-audit.jsonl',
  usageAuditMaxBytes: Number(process.env.USAGE_AUDIT_MAX_BYTES || 10 * 1024 * 1024),
  usageAuditRetainedFiles: Number(process.env.USAGE_AUDIT_RETAINED_FILES || 10),
};

const requiredConfig = [
  'baseUrl',
  'clientId',
  'clientSecret',
  'authorizationUrl',
  'tokenUrl',
  'redirectUri',
  'apiUrl',
  'sessionSecret',
  'mcpResource',
];

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, '');
}

function zoomApiBaseUrl() {
  return config.apiUrl;
}

function isZoomApplicationError(data, zoomPath) {
  if (zoomPath === '/marketplace/apps/manifest/validate') return false;
  return Boolean(
    data
    && typeof data === 'object'
    && !Array.isArray(data)
    && data.ok !== false
    && data.code !== undefined
    && typeof data.message === 'string',
  );
}

function verifyZoomWebhookSignature(req) {
  if (!config.webhookSecretToken) {
    return { ok: false, status: 503, error: 'webhook_secret_not_configured' };
  }
  const timestamp = req.get('x-zm-request-timestamp') || '';
  const signature = req.get('x-zm-signature') || '';
  const timestampSeconds = Number(timestamp);
  if (!timestamp || !signature || !req.rawBody || !Number.isSafeInteger(timestampSeconds)) {
    return { ok: false, status: 401, error: 'invalid_webhook_signature' };
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - timestampSeconds) > 5 * 60) {
    return { ok: false, status: 401, error: 'expired_webhook_signature' };
  }
  const message = `v0:${timestamp}:${req.rawBody}`;
  const digest = crypto.createHmac('sha256', config.webhookSecretToken).update(message).digest('hex');
  const expected = Buffer.from(`v0=${digest}`);
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return { ok: false, status: 401, error: 'invalid_webhook_signature' };
  }
  return { ok: true };
}

const localDatabase = createLocalDatabase({
  databasePath: config.databasePath,
  encryptionKey: config.tokenEncryptionKey,
  fallbackSecret: config.sessionSecret,
  legacyJsonPath: config.legacyTokenStorePath,
});

const usageAuditLogger = createUsageAuditLogger({
  filePath: config.usageAuditLogPath,
  maxBytes: config.usageAuditMaxBytes,
  retainedFiles: config.usageAuditRetainedFiles,
});

async function recordUsageAudit(event) {
  try {
    await usageAuditLogger.record(event);
  } catch {
    console.error('Usage audit log write failed');
  }
}

async function loadDotenv() {
  try {
    const raw = await fs.readFile('.env', 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }
      const separatorIndex = trimmed.indexOf('=');
      if (separatorIndex === -1) {
        continue;
      }
      const key = trimmed.slice(0, separatorIndex).trim();
      const value = trimmed.slice(separatorIndex + 1).trim().replace(/^["']|["']$/g, '');
      if (key && process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

function configured() {
  return requiredConfig.every((key) => Boolean(config[key]));
}

function requireConfigured(_req, res, next) {
  if (!configured()) {
    return res.status(500).json({
      error: 'server_not_configured',
      missing: requiredConfig.filter((key) => !config[key]),
    });
  }
  next();
}

function requireApiKey(req, res, next) {
  if (!config.apiKey) {
    return res.status(500).json({ error: 'api_key_not_configured' });
  }
  if (req.get('x-api-key') !== config.apiKey) {
    return res.status(401).json({ error: 'invalid_api_key' });
  }
  next();
}

const SUPPORT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const SUPPORT_HOUR_MS = 60 * 60 * 1000;
const SUPPORT_DAY_MS = 24 * SUPPORT_HOUR_MS;

function normalizedSupportInput(body = {}) {
  return {
    name: String(body.name || '').trim(),
    email: String(body.email || '').trim().toLowerCase(),
    issue: String(body.issue || '').trim(),
    website: String(body.website || '').trim(),
    startedAt: Number(body.started_at),
  };
}

function validSupportInput(input) {
  return input.name.length >= 2
    && input.name.length <= 100
    && input.email.length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email)
    && input.issue.length >= 20
    && input.issue.length <= 4000;
}

function supportHash(value) {
  return crypto.createHmac('sha256', config.sessionSecret).update(value).digest('hex');
}

function supportSource(req) {
  const forwarded = String(req.get('cf-connecting-ip') || req.get('x-forwarded-for') || req.ip || 'unknown');
  const address = forwarded.split(',')[0].trim().slice(0, 128);
  const userAgent = String(req.get('user-agent') || '').slice(0, 256);
  return supportHash(`${address}|${userAgent}`);
}

function recentSupportCount(requests, field, value, since) {
  return requests.filter((request) => request[field] === value && Date.parse(request.created_at) >= since).length;
}

function supportRateLimited(requests, sourceHash, emailHash, now) {
  const identities = [
    ['source_hash', sourceHash],
    ['email_hash', emailHash],
  ];
  return identities.some(([field, value]) => (
    recentSupportCount(requests, field, value, now - SUPPORT_HOUR_MS) >= 2
    || recentSupportCount(requests, field, value, now - SUPPORT_DAY_MS) >= 3
  )) || requests.filter((request) => Date.parse(request.created_at) >= now - SUPPORT_DAY_MS).length >= 30;
}

const supportAttemptBuckets = new Map();
let globalSupportAttempts = [];

function supportAttemptRateLimited(sourceHash, now) {
  const sourceAttempts = (supportAttemptBuckets.get(sourceHash) || []).filter(
    (timestamp) => timestamp >= now - SUPPORT_DAY_MS,
  );
  globalSupportAttempts = globalSupportAttempts.filter((timestamp) => timestamp >= now - SUPPORT_DAY_MS);
  const limited = sourceAttempts.filter((timestamp) => timestamp >= now - SUPPORT_HOUR_MS).length >= 5
    || sourceAttempts.length >= 10
    || globalSupportAttempts.length >= 120;
  if (!limited) {
    sourceAttempts.push(now);
    globalSupportAttempts.push(now);
    supportAttemptBuckets.set(sourceHash, sourceAttempts);
  }
  return limited;
}

async function pruneExpiredSupportRequests() {
  const store = await readStore();
  const before = (store.supportRequests || []).length;
  store.supportRequests = (store.supportRequests || []).filter(
    (request) => Date.parse(request.created_at) >= Date.now() - SUPPORT_RETENTION_MS,
  );
  if (store.supportRequests.length !== before) await writeStore(store);
}

function basicAuthHeader() {
  const encoded = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');
  return `Basic ${encoded}`;
}

function getBasicClientId(req) {
  const header = req.get('authorization') || '';
  if (!header.startsWith('Basic ')) return '';
  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    return decodeURIComponent(decoded.slice(0, decoded.indexOf(':')));
  } catch {
    return '';
  }
}

function redirectToMcpClient(res, statePayload, values) {
  const location = new URL(statePayload.redirectUri);
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== '') location.searchParams.set(key, String(value));
  }
  if (statePayload.originalState) location.searchParams.set('state', statePayload.originalState);
  return res.redirect(location.toString());
}

function safeZoomError(body) {
  return {
    error: typeof body?.error === 'string' ? body.error : undefined,
    error_code: body?.error_code === undefined ? undefined : String(body.error_code),
    reason: typeof body?.reason === 'string' ? body.reason : undefined,
    error_description: typeof body?.error_description === 'string' ? body.error_description : undefined,
  };
}

function oauthCors(req, res, next) {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  return next();
}

function signState(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', config.sessionSecret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyState(state) {
  if (!state || !state.includes('.')) {
    throw new Error('missing_state');
  }
  const [body, sig] = state.split('.', 2);
  const expected = crypto.createHmac('sha256', config.sessionSecret).update(body).digest('base64url');
  const sigBuffer = Buffer.from(sig);
  const expectedBuffer = Buffer.from(expected);
  if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    throw new Error('invalid_state');
  }
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!payload.nonce || !payload.createdAt || Date.now() - payload.createdAt > 10 * 60 * 1000) {
    throw new Error('expired_state');
  }
  return payload;
}

async function readStore() {
  return localDatabase.read();
}

async function writeStore(store) {
  localDatabase.write(store);
}

function installationId(tokenResponse) {
  return accountIdFromTokenResponse(tokenResponse)
    || tokenResponse.uid
    || tokenResponse.user_id
    || jwtClaim(tokenResponse.access_token, 'uid')
    || 'default';
}

function jwtClaim(token, claim) {
  try {
    const payload = String(token || '').split('.')[1];
    if (!payload) return undefined;
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))[claim];
  } catch {
    return undefined;
  }
}

function accountIdFromTokenResponse(tokenResponse) {
  return tokenResponse.account_id
    || tokenResponse.aid
    || jwtClaim(tokenResponse.access_token, 'aid');
}

async function saveInstallation(tokenResponse) {
  const store = await readStore();
  const id = installationId(tokenResponse);
  const accountId = accountIdFromTokenResponse(tokenResponse);
  const userId = tokenResponse.user_id
    || tokenResponse.uid
    || jwtClaim(tokenResponse.access_token, 'uid');
  store.installations[id] = {
    id,
    ...(accountId ? { account_id: accountId } : {}),
    ...(userId ? { user_id: userId } : {}),
    client_id: config.clientId,
    api_url: stripTrailingSlash(tokenResponse.api_url || config.apiUrl),
    access_token: tokenResponse.access_token,
    refresh_token: tokenResponse.refresh_token,
    scope: tokenResponse.scope,
    token_type: tokenResponse.token_type,
    expires_at: Date.now() + Math.max(0, Number(tokenResponse.expires_in || 3600) - 60) * 1000,
    updated_at: new Date().toISOString(),
  };
  await writeStore(store);
  return store.installations[id];
}

async function migrateInstallationIds() {
  const store = await readStore();
  const replacements = {};
  let changed = false;

  for (const [id, installation] of Object.entries(store.installations)) {
    const accountId = installation.account_id || accountIdFromTokenResponse(installation);
    if (!accountId) continue;
    if (installation.account_id !== accountId) {
      installation.account_id = accountId;
      changed = true;
    }
    if (id !== accountId && !store.installations[accountId]) {
      store.installations[accountId] = { ...installation, id: accountId };
      delete store.installations[id];
      replacements[id] = accountId;
      changed = true;
    }
  }

  if (Object.keys(replacements).length) {
    for (const token of Object.values(store.oauth.accessTokens || {})) {
      if (replacements[token.installationId]) token.installationId = replacements[token.installationId];
    }
    for (const token of Object.values(store.oauth.refreshTokens || {})) {
      if (replacements[token.installationId]) token.installationId = replacements[token.installationId];
    }
  }

  if (changed) await writeStore(store);
}

async function getInstallation(req) {
  const store = await readStore();
  const requestedId = req.get('x-zoom-account-id') || req.query.account_id;
  if (requestedId) {
    const installation = store.installations[requestedId];
    if (!installation) {
      throw Object.assign(new Error('installation_not_found'), { status: 404 });
    }
    return installation;
  }
  const installations = Object.values(store.installations);
  if (installations.length === 1) {
    return installations[0];
  }
  throw Object.assign(new Error('account_id_required'), { status: 400 });
}

async function getInstallationById(id) {
  const store = await readStore();
  const installation = store.installations[id];
  if (!installation) {
    throw Object.assign(new Error('installation_not_found'), { status: 404 });
  }
  return installation;
}

async function refreshInstallation(installation) {
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: installation.refresh_token,
  });
  const response = await fetch(`${config.tokenUrl}?${params}`, {
    method: 'POST',
    headers: {
      authorization: basicAuthHeader(),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw Object.assign(new Error('zoom_refresh_failed'), { status: response.status, body });
  }
  return saveInstallation({ ...body, account_id: installation.id, api_url: body.api_url || installation.api_url });
}

async function accessToken(req) {
  let installation = await getInstallation(req);
  if (!installation.access_token || Date.now() >= installation.expires_at) {
    installation = await refreshInstallation(installation);
  }
  return installation;
}

async function zoomApiRequest({ installationId, method = 'GET', path: zoomPath, query = {}, body, onUpstreamStatus }) {
  let installation = await getInstallationById(installationId);
  if (!installation.access_token || Date.now() >= installation.expires_at) {
    installation = await refreshInstallation(installation);
  }
  const queryString = new URLSearchParams(query).toString();
  const url = `${zoomApiBaseUrl()}${zoomPath}${queryString ? `?${queryString}` : ''}`;
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${installation.access_token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  onUpstreamStatus?.(response.status);
  const text = await response.text();
  const contentType = response.headers.get('content-type') || '';
  let data = text;
  if (text && contentType.includes('application/json')) {
    data = JSON.parse(text);
  } else if (!text) {
    data = null;
  }
  if (!response.ok) {
    throw Object.assign(new Error('zoom_api_request_failed'), {
      status: response.status,
      body: data,
    });
  }
  if (isZoomApplicationError(data, zoomPath)) {
    throw Object.assign(new Error('zoom_api_request_failed'), {
      status: 502,
      upstreamStatus: response.status,
      body: data,
    });
  }
  return data === null ? { ok: true, status: response.status } : data;
}

async function zoomRequest(req, res, zoomPath, options = {}) {
  try {
    const installation = await accessToken(req);
    const resolvedZoomPath = typeof zoomPath === 'function' ? zoomPath(installation) : zoomPath;
    const response = await fetch(`${zoomApiBaseUrl()}${resolvedZoomPath}`, {
      method: options.method || req.method,
      headers: {
        authorization: `Bearer ${installation.access_token}`,
        'content-type': 'application/json',
      },
      body: options.body === undefined ? (['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body || {})) : options.body,
    });
    const text = await response.text();
    const contentType = response.headers.get('content-type') || '';
    res.status(response.status);
    if (text && contentType.includes('application/json')) {
      return res.json(JSON.parse(text));
    }
    return res.send(text);
  } catch (error) {
    return res.status(error.status || 500).json({
      error: error.message || 'marketplace_proxy_error',
      details: error.body,
    });
  }
}

app.get('/oauth/start', requireConfigured, (req, res) => {
  const state = signState({
    nonce: crypto.randomBytes(16).toString('hex'),
    createdAt: Date.now(),
    returnTo: typeof req.query.return_to === 'string' ? req.query.return_to : '/',
  });
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    state,
  });
  res.redirect(`${config.authorizationUrl}?${params}`);
});

app.use('/oauth', oauthCors);
app.use('/.well-known', oauthCors);

app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json(protectedResourceMetadata(config));
});

app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  res.json(protectedResourceMetadata(config));
});

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json(authorizationServerMetadata(config));
});

app.post('/oauth/register', async (req, res) => {
  try {
    const result = await registerClient({ body: req.body, readStore, writeStore });
    return res.status(201).json(result);
  } catch (error) {
    return res.status(error.status || 400).json({ error: error.message || 'client_registration_failed' });
  }
});

app.get('/oauth/authorize', requireConfigured, async (req, res) => {
  try {
    const clientId = typeof req.query.client_id === 'string' ? req.query.client_id : '';
    const redirectUri = typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : '';
    const client = await getClient(clientId, readStore);
    assertClientRedirect(client, redirectUri);
    if (req.query.response_type !== 'code') {
      throw Object.assign(new Error('unsupported_response_type'), { status: 400 });
    }
    const codeChallenge = typeof req.query.code_challenge === 'string' ? req.query.code_challenge : '';
    const codeChallengeMethod = typeof req.query.code_challenge_method === 'string'
      ? req.query.code_challenge_method
      : 'S256';
    if (!codeChallenge || codeChallengeMethod !== 'S256') {
      throw Object.assign(new Error('pkce_required'), { status: 400 });
    }
    const resource = typeof req.query.resource === 'string' ? req.query.resource : config.mcpResource;
    if (resource !== config.mcpResource) {
      throw Object.assign(new Error('invalid_target_resource'), { status: 400 });
    }
    const scopes = requestedScopes(req.query.scope);
    const state = signState({
      purpose: 'mcp_authorization',
      nonce: crypto.randomBytes(16).toString('hex'),
      createdAt: Date.now(),
      clientId,
      redirectUri,
      originalState: typeof req.query.state === 'string' ? req.query.state : '',
      resource,
      scopes,
      codeChallenge,
      codeChallengeMethod,
    });
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      state,
    });
    return res.redirect(`${config.authorizationUrl}?${params}`);
  } catch (error) {
    return res.status(error.status || 400).json({ error: error.message || 'authorization_failed' });
  }
});

app.post('/oauth/token', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    const grantType = req.body?.grant_type;
    if (!['authorization_code', 'refresh_token'].includes(grantType)) {
      throw Object.assign(new Error('unsupported_grant_type'), { status: 400 });
    }
    const suppliedClientId = req.body?.client_id || getBasicClientId(req);
    const client = await getClient(suppliedClientId, readStore);
    clientCredentials(req, req.body, client);

    if (grantType === 'authorization_code') {
      const authorizationCode = typeof req.body.code === 'string' ? req.body.code : '';
      const record = await getAuthorizationCode(authorizationCode, readStore);
      if (!record || record.clientId !== client.clientId) {
        throw Object.assign(new Error('invalid_grant'), { status: 400 });
      }
      if (req.body.redirect_uri !== record.redirectUri || !verifyPkce(record.codeChallenge, record.codeChallengeMethod, req.body.code_verifier)) {
        throw Object.assign(new Error('invalid_grant'), { status: 400 });
      }
      await consumeAuthorizationCode(authorizationCode, readStore, writeStore);
      return res.json(await issueTokens({
        clientId: client.clientId,
        installationId: record.installationId,
        scopes: record.scopes,
        resource: record.resource,
        readStore,
        writeStore,
      }));
    }

    const record = await consumeRefreshToken(req.body.refresh_token, readStore, writeStore);
    if (!record || record.clientId !== client.clientId) {
      throw Object.assign(new Error('invalid_grant'), { status: 400 });
    }
    return res.json(await issueTokens({
      clientId: client.clientId,
      installationId: record.installationId,
      scopes: record.scopes,
      resource: record.resource,
      readStore,
      writeStore,
    }));
  } catch (error) {
    return res.status(error.status || 400).json({ error: error.message || 'token_request_failed' });
  }
});

async function requireMcpBearer(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    const session = await findAccessToken(token, readStore);
    if (!session || session.resource !== config.mcpResource) {
      res.set('WWW-Authenticate', `Bearer resource_metadata="${config.baseUrl}/.well-known/oauth-protected-resource"`);
      return res.status(401).json({ error: 'authorization_required' });
    }
    req.oauthSession = session;
    return next();
  } catch (error) {
    return res.status(500).json({ error: error.message || 'mcp_authorization_failed' });
  }
}

app.get('/oauth/callback', requireConfigured, async (req, res) => {
  try {
    const statePayload = verifyState(String(req.query.state || ''));
    if (typeof req.query.error === 'string') {
      if (statePayload.purpose === 'mcp_authorization') {
        return redirectToMcpClient(res, statePayload, {
          error: req.query.error,
          ...(req.query.reason ? { error_description: req.query.reason } : {}),
        });
      }
      return res.status(400).json({ error: req.query.error, reason: req.query.reason });
    }
    const code = req.query.code;
    if (typeof code !== 'string') {
      return res.status(400).json({ error: 'missing_code' });
    }
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
    });
    const response = await fetch(`${config.tokenUrl}?${params}`, {
      method: 'POST',
      headers: {
        authorization: basicAuthHeader(),
      },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const zoomError = safeZoomError(body);
      console.error('Zoom OAuth token exchange failed:', JSON.stringify({
        status: response.status,
        ...zoomError,
      }));
      if (statePayload.purpose === 'mcp_authorization') {
        return redirectToMcpClient(res, statePayload, {
          error: 'server_error',
          error_description: zoomError.reason || zoomError.error_description || 'zoom_token_exchange_failed',
          ...(zoomError.error_code ? { error_code: zoomError.error_code } : {}),
        });
      }
      return res.status(response.status).json({ error: 'zoom_token_exchange_failed', details: body });
    }
    const installation = await saveInstallation(body);
    if (statePayload.purpose === 'mcp_authorization') {
      const authorizationCode = await saveAuthorizationCode({
        record: {
          clientId: statePayload.clientId,
          redirectUri: statePayload.redirectUri,
          originalState: statePayload.originalState,
          codeChallenge: statePayload.codeChallenge,
          codeChallengeMethod: statePayload.codeChallengeMethod,
          resource: statePayload.resource,
          scopes: statePayload.scopes,
          installationId: installation.id,
        },
        readStore,
        writeStore,
      });
      return redirectToMcpClient(res, statePayload, { code: authorizationCode });
    }
    return res.json({
      ok: true,
      installation_id: installation.id,
      scope: installation.scope,
      api_url: installation.api_url,
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'oauth_callback_failed' });
  }
});

app.get('/api/installations', requireApiKey, async (_req, res) => {
  const store = await readStore();
  const installations = Object.values(store.installations).map((installation) => ({
    id: installation.id,
    api_url: installation.api_url,
    scope: installation.scope,
    expires_at: installation.expires_at,
    updated_at: installation.updated_at,
  }));
  res.json({ installations });
});

app.get('/api/status', (_req, res) => {
  res.json({
    service: 'marketplace-helper-app',
    configured: configured(),
    base_url: config.baseUrl,
    oauth_start: `${config.baseUrl}/oauth/start`,
    oauth_redirect_uri: config.redirectUri,
    oauth_authorize_url: config.authorizationUrl
      ? `${config.authorizationUrl}?${new URLSearchParams({ response_type: 'code', client_id: config.clientId, redirect_uri: config.redirectUri })}`
      : '',
    mcp_endpoint: `${config.baseUrl}/mcp`,
    mcp_protected_resource: `${config.baseUrl}/.well-known/oauth-protected-resource`,
    mcp_authorization_server: `${config.baseUrl}/.well-known/oauth-authorization-server`,
    deauthorization_endpoint: `${config.baseUrl}/webhooks/deauthorization`,
  });
});

app.post('/api/support/requests', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const now = Date.now();
  const sourceHash = supportSource(req);
  if (supportAttemptRateLimited(sourceHash, now)) {
    res.set('Retry-After', '3600');
    return res.status(429).json({ error: 'support_rate_limit_exceeded' });
  }
  const origin = req.get('origin');
  if (origin && config.baseUrl && origin !== new URL(config.baseUrl).origin) {
    return res.status(403).json({ error: 'invalid_origin' });
  }

  const input = normalizedSupportInput(req.body);
  const elapsed = Date.now() - input.startedAt;
  if (input.website || !Number.isFinite(input.startedAt) || elapsed < 3000 || elapsed > SUPPORT_HOUR_MS) {
    return res.status(400).json({ error: 'invalid_submission' });
  }
  if (!validSupportInput(input)) {
    return res.status(400).json({ error: 'invalid_support_request' });
  }

  const store = await readStore();
  store.supportRequests = (store.supportRequests || []).filter(
    (request) => Date.parse(request.created_at) >= now - SUPPORT_RETENTION_MS,
  );
  const emailHash = supportHash(input.email);
  if (supportRateLimited(store.supportRequests, sourceHash, emailHash, now)) {
    res.set('Retry-After', '3600');
    return res.status(429).json({ error: 'support_rate_limit_exceeded' });
  }

  const request = {
    id: crypto.randomUUID(),
    name: input.name,
    email: input.email,
    issue: input.issue,
    source_hash: sourceHash,
    email_hash: emailHash,
    created_at: new Date(now).toISOString(),
  };
  store.supportRequests.push(request);
  await writeStore(store);
  return res.status(201).json({ ok: true, request_id: request.id });
});

app.get('/api/support/requests', requireApiKey, async (_req, res) => {
  res.set('Cache-Control', 'no-store');
  const now = Date.now();
  const store = await readStore();
  store.supportRequests = (store.supportRequests || []).filter(
    (request) => Date.parse(request.created_at) >= now - SUPPORT_RETENTION_MS,
  );
  await writeStore(store);
  return res.json({
    requests: store.supportRequests.map(({ source_hash, email_hash, ...request }) => request),
  });
});

app.delete('/api/support/requests/:requestId', requireApiKey, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const store = await readStore();
  const before = (store.supportRequests || []).length;
  store.supportRequests = (store.supportRequests || []).filter(
    (request) => request.id !== req.params.requestId,
  );
  if (store.supportRequests.length === before) {
    return res.status(404).json({ error: 'support_request_not_found' });
  }
  await writeStore(store);
  return res.json({ ok: true, deleted: true });
});

app.post('/webhooks/deauthorization', async (req, res) => {
  const verification = verifyZoomWebhookSignature(req);
  if (!verification.ok) {
    return res.status(verification.status).json({ error: verification.error });
  }

  if (req.body?.event !== 'app_deauthorized') {
    return res.status(400).json({ error: 'unsupported_deauthorization_event' });
  }

  const payload = req.body?.payload || {};
  const accountId = payload.account_id || payload.accountId;
  const userId = payload.user_id || payload.userId;
  const clientId = payload.client_id || payload.clientId;
  if (!accountId && !userId) {
    return res.status(400).json({ error: 'deauthorization_identity_missing' });
  }
  if (clientId && config.clientId && clientId !== config.clientId) {
    return res.status(400).json({ error: 'deauthorization_client_mismatch' });
  }

  const store = await readStore();
  const accountIds = new Set([accountId].filter(Boolean));
  const userIds = new Set([userId].filter(Boolean));
  const installationIds = new Set();
  for (const [id, installation] of Object.entries(store.installations)) {
    const installationAccountIds = [id, installation.account_id].filter(Boolean);
    const installationUserIds = [id, installation.user_id, installation.uid].filter(Boolean);
    if (
      [...accountIds].some((value) => installationAccountIds.includes(value))
      || [...userIds].some((value) => installationUserIds.includes(value))
    ) {
      installationIds.add(id);
      delete store.installations[id];
    }
  }

  let deletedAccessTokens = 0;
  for (const [hash, token] of Object.entries(store.oauth.accessTokens || {})) {
    if (installationIds.has(token.installationId)) {
      delete store.oauth.accessTokens[hash];
      deletedAccessTokens += 1;
    }
  }

  let deletedRefreshTokens = 0;
  for (const [hash, token] of Object.entries(store.oauth.refreshTokens || {})) {
    if (installationIds.has(token.installationId)) {
      delete store.oauth.refreshTokens[hash];
      deletedRefreshTokens += 1;
    }
  }

  let deletedAuthorizationCodes = 0;
  for (const [hash, code] of Object.entries(store.oauth.authorizationCodes || {})) {
    if (installationIds.has(code.installationId)) {
      delete store.oauth.authorizationCodes[hash];
      deletedAuthorizationCodes += 1;
    }
  }
  await writeStore(store);
  return res.json({
    ok: true,
    event: 'app_deauthorized',
    deleted_installations: installationIds.size,
    deleted_access_tokens: deletedAccessTokens,
    deleted_refresh_tokens: deletedRefreshTokens,
    deleted_authorization_codes: deletedAuthorizationCodes,
  });
});

app.get('/api/marketplace/apps', requireApiKey, (req, res) => zoomRequest(req, res, '/marketplace/apps'));
app.post('/api/marketplace/apps', requireApiKey, (req, res) => zoomRequest(req, res, '/marketplace/apps'));
app.get('/api/marketplace/apps/:appId', requireApiKey, (req, res) => zoomRequest(req, res, `/marketplace/apps/${encodeURIComponent(req.params.appId)}`));
app.delete('/api/marketplace/apps/:appId', requireApiKey, (req, res) => zoomRequest(req, res, `/marketplace/apps/${encodeURIComponent(req.params.appId)}`));
app.post('/api/marketplace/apps/manifest/validate', requireApiKey, (req, res) => zoomRequest(req, res, '/marketplace/apps/manifest/validate'));
app.get('/api/marketplace/apps/:appId/manifest', requireApiKey, (req, res) => zoomRequest(req, res, `/marketplace/apps/${encodeURIComponent(req.params.appId)}/manifest`));
app.put('/api/marketplace/apps/:appId/manifest', requireApiKey, (req, res) => zoomRequest(req, res, `/marketplace/apps/${encodeURIComponent(req.params.appId)}/manifest`));

app.use('/mcp', (req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID');
  res.set('Access-Control-Expose-Headers', 'MCP-Session-Id, WWW-Authenticate');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  return requireMcpBearer(req, res, next);
});

app.post('/mcp', (req, res) => handleMarketplaceMcpRequest(req, res, {
  session: req.oauthSession,
  callZoom: (request) => zoomApiRequest({ ...request, installationId: req.oauthSession.installationId }),
  audit: recordUsageAudit,
}));

app.get('/mcp', (_req, res) => res.status(405).json({ error: 'method_not_allowed' }));
app.delete('/mcp', (_req, res) => res.status(405).json({ error: 'method_not_allowed' }));

await migrateInstallationIds();
await pruneExpiredSupportRequests();
const supportCleanupTimer = setInterval(() => {
  pruneExpiredSupportRequests().catch((error) => console.error('Support request cleanup failed:', error));
}, SUPPORT_HOUR_MS);
supportCleanupTimer.unref();

app.listen(config.port, () => {
  console.log(`marketplace-helper-app listening on ${config.port}`);
});
