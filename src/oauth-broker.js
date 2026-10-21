import crypto from 'crypto';

export const MCP_SCOPES = ['marketplace:read', 'marketplace:write', 'offline_access'];

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

function oauthStore(store) {
  store.oauth ||= {
    clients: {},
    authorizationCodes: {},
    accessTokens: {},
    refreshTokens: {},
  };
  return store.oauth;
}

function isAllowedRedirect(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || (
      url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    );
  } catch {
    return false;
  }
}

function sameRedirect(client, redirectUri) {
  return client.redirectUris.includes(redirectUri);
}

function timingSafeEqualText(left, right) {
  const leftBuffer = Buffer.from(left || '');
  const rightBuffer = Buffer.from(right || '');
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function protectedResourceMetadata(config) {
  return {
    resource: config.mcpResource,
    authorization_servers: [config.baseUrl],
    scopes_supported: MCP_SCOPES,
    bearer_methods_supported: ['header'],
  };
}

export function authorizationServerMetadata(config) {
  return {
    issuer: config.baseUrl,
    authorization_endpoint: `${config.baseUrl}/oauth/authorize`,
    token_endpoint: `${config.baseUrl}/oauth/token`,
    registration_endpoint: `${config.baseUrl}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    scopes_supported: MCP_SCOPES,
  };
}

export async function registerClient({ body, readStore, writeStore }) {
  const redirectUris = Array.isArray(body?.redirect_uris) ? body.redirect_uris : [];
  if (!redirectUris.length || redirectUris.some((uri) => typeof uri !== 'string' || !isAllowedRedirect(uri))) {
    throw Object.assign(new Error('redirect_uris_must_be_https_or_loopback'), { status: 400 });
  }
  const authMethod = body.token_endpoint_auth_method || 'none';
  if (!['none', 'client_secret_basic', 'client_secret_post'].includes(authMethod)) {
    throw Object.assign(new Error('unsupported_token_endpoint_auth_method'), { status: 400 });
  }
  const clientId = `mcp_${randomToken(18)}`;
  const clientSecret = authMethod === 'none' ? undefined : randomToken(32);
  const client = {
    clientId,
    clientSecretHash: clientSecret ? hashToken(clientSecret) : null,
    clientName: typeof body.client_name === 'string' ? body.client_name : 'MCP client',
    redirectUris,
    tokenEndpointAuthMethod: authMethod,
    createdAt: Date.now(),
  };
  const store = await readStore();
  oauthStore(store).clients[clientId] = client;
  await writeStore(store);
  return {
    client_id: clientId,
    ...(clientSecret ? { client_secret: clientSecret } : {}),
    client_name: client.clientName,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: authMethod,
  };
}

export async function getClient(clientId, readStore) {
  if (!clientId) return null;
  const store = await readStore();
  return oauthStore(store).clients[clientId] || null;
}

export function assertClientRedirect(client, redirectUri) {
  if (!client || !sameRedirect(client, redirectUri)) {
    throw Object.assign(new Error('invalid_redirect_uri'), { status: 400 });
  }
}

export function requestedScopes(scope) {
  const values = [...new Set(String(scope || MCP_SCOPES.join(' ')).split(/\s+/).filter(Boolean))];
  if (values.some((value) => !MCP_SCOPES.includes(value))) {
    throw Object.assign(new Error('invalid_scope'), { status: 400 });
  }
  return values;
}

export function verifyPkce(codeChallenge, codeChallengeMethod, codeVerifier) {
  if (!codeChallenge || !codeVerifier || codeChallengeMethod !== 'S256') return false;
  const actual = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return timingSafeEqualText(actual, codeChallenge);
}

export async function saveAuthorizationCode({ record, readStore, writeStore }) {
  const code = randomToken(40);
  const store = await readStore();
  oauthStore(store).authorizationCodes[hashToken(code)] = {
    ...record,
    createdAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
  await writeStore(store);
  return code;
}

export async function getAuthorizationCode(code, readStore) {
  const store = await readStore();
  const record = oauthStore(store).authorizationCodes[hashToken(code)];
  if (!record || Date.now() >= record.expiresAt) return null;
  return record;
}

export async function consumeAuthorizationCode(code, readStore, writeStore) {
  const store = await readStore();
  const key = hashToken(code);
  const record = oauthStore(store).authorizationCodes[key];
  if (!record || Date.now() >= record.expiresAt) return null;
  delete oauthStore(store).authorizationCodes[key];
  await writeStore(store);
  return record;
}

export async function issueTokens({ clientId, installationId, scopes, resource, readStore, writeStore }) {
  const accessToken = randomToken(40);
  const refreshToken = randomToken(48);
  const now = Date.now();
  const store = await readStore();
  const oauth = oauthStore(store);
  oauth.accessTokens[hashToken(accessToken)] = {
    clientId,
    installationId,
    scopes,
    resource,
    expiresAt: now + 60 * 60 * 1000,
  };
  oauth.refreshTokens[hashToken(refreshToken)] = {
    clientId,
    installationId,
    scopes,
    resource,
    expiresAt: now + 90 * 24 * 60 * 60 * 1000,
  };
  await writeStore(store);
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: scopes.join(' '),
  };
}

export async function findAccessToken(token, readStore) {
  if (!token) return null;
  const store = await readStore();
  const record = oauthStore(store).accessTokens[hashToken(token)];
  if (!record || Date.now() >= record.expiresAt) return null;
  return record;
}

export async function consumeRefreshToken(token, readStore, writeStore) {
  const store = await readStore();
  const key = hashToken(token || '');
  const oauth = oauthStore(store);
  const record = oauth.refreshTokens[key];
  if (!record || Date.now() >= record.expiresAt) return null;
  delete oauth.refreshTokens[key];
  await writeStore(store);
  return record;
}

export function clientCredentials(req, body, client) {
  let clientId = body?.client_id;
  let clientSecret = body?.client_secret;
  const header = req.get('authorization') || '';
  if (header.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      clientId = decodeURIComponent(decoded.slice(0, separator));
      clientSecret = decodeURIComponent(decoded.slice(separator + 1));
    } catch {
      clientId = undefined;
      clientSecret = undefined;
    }
  }
  if (!client || client.clientId !== clientId) {
    throw Object.assign(new Error('invalid_client'), { status: 401 });
  }
  if (client.tokenEndpointAuthMethod === 'none') return clientId;
  if (!clientSecret || !timingSafeEqualText(hashToken(clientSecret), client.clientSecretHash)) {
    throw Object.assign(new Error('invalid_client'), { status: 401 });
  }
  return clientId;
}
