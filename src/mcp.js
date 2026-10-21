import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import * as z from 'zod/v4';

const READ_SCOPE = 'marketplace:read';
const WRITE_SCOPE = 'marketplace:write';

function jsonResult(value) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  };
}

function errorResult(error) {
  const details = error?.body === undefined ? undefined : { details: error.body };
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({
        error: error?.message || 'marketplace_request_failed',
        status: error?.status,
        ...(error?.upstreamStatus === undefined ? {} : { upstream_status: error.upstreamStatus }),
        ...details,
      }, null, 2),
    }],
  };
}

function withScope(session, scope) {
  if (!session?.scopes?.includes(scope)) {
    throw Object.assign(new Error(`missing_scope:${scope}`), { status: 403 });
  }
}

export function toolHandler({ tool, session, scope, handler, audit }) {
  return async (input) => {
    const startedAt = performance.now();
    let upstreamStatus = null;
    let success = false;
    try {
      withScope(session, scope);
      const result = await handler(input, {
        setUpstreamStatus(status) {
          if (Number.isInteger(status)) upstreamStatus = status;
        },
      });
      success = true;
      return jsonResult(result);
    } catch (error) {
      upstreamStatus = error?.upstreamStatus ?? upstreamStatus;
      return errorResult(error);
    } finally {
      try {
        await audit?.({
          tool,
          success,
          latency_ms: performance.now() - startedAt,
          upstream_status: Number.isInteger(upstreamStatus) ? upstreamStatus : null,
        });
      } catch {
        // Usage logging must never change the outcome of a tool call.
      }
    }
  };
}

function pageInput() {
  return {
    page_size: z.number().int().min(1).max(300).optional(),
    next_page_token: z.string().optional(),
  };
}

function pageQuery(input) {
  const query = {};
  if (input.page_size !== undefined) query.page_size = String(input.page_size);
  if (input.next_page_token) query.next_page_token = input.next_page_token;
  return query;
}

function isAppGoneError(error) {
  return error?.status === 403 || error?.status === 404;
}

async function appIsReadable(callZoom, appId) {
  try {
    await callZoom({
      method: 'GET',
      path: `/marketplace/apps/${encodeURIComponent(appId)}`,
    });
    return true;
  } catch (error) {
    if (isAppGoneError(error)) return false;
    throw error;
  }
}

async function deleteMarketplaceApp({ callZoom, appId }) {
  const deleteResponse = await callZoom({
    method: 'DELETE',
    path: `/marketplace/apps/${encodeURIComponent(appId)}`,
  });

  if (await appIsReadable(callZoom, appId)) {
    throw Object.assign(new Error('app_delete_not_confirmed'), {
      status: 409,
      body: {
        app_id: appId,
        delete_response: deleteResponse,
      },
    });
  }

  return {
    app_id: appId,
    deleted: true,
    delete_response: deleteResponse,
  };
}

export function createMarketplaceMcpServer({ session, callZoom, audit }) {
  const server = new McpServer({
    name: 'zoom-marketplace-helper',
    version: '0.2.0',
  });

  server.registerTool('marketplace_list_apps', {
    description: 'List Zoom Marketplace apps accessible through the authorized account endpoint. This does not list every app in the developer dashboard and may not reliably include developer-owned unpublished drafts. An absent or empty apps array does not prove that the account has no apps. Retain the app_id returned by marketplace_create_app and pass it directly to marketplace_get_app, marketplace_export_app_manifest, or marketplace_delete_app to access an unpublished draft.',
    inputSchema: pageInput(),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_list_apps', session, scope: READ_SCOPE, audit, handler: (input, context) => callZoom({
    method: 'GET',
    path: '/marketplace/apps',
    query: pageQuery(input),
    onUpstreamStatus: context.setUpstreamStatus,
  }) }));

  server.registerTool('marketplace_create_app', {
    description: 'Create one Zoom Server-to-Server OAuth or General Marketplace app through the standard Marketplace endpoint. Configure Meeting SDK as a capability of a General App rather than creating the legacy standalone Meeting SDK app type. General Apps require a complete manifest; validate it first. A successful response returns the app_id and normally returns new credentials, including client secrets that cannot be fetched later by these tools; store them securely immediately. Zoom may return only an app_id in some environments. If Zoom returns an ambiguous error after submission, check the developer dashboard before retrying to avoid duplicate drafts. Treat all credentials as sensitive and never log or commit them.',
    inputSchema: {
      app_name: z.string().min(1).max(255),
      app_type: z.enum(['s2s_oauth', 'general']),
      company_name: z.string().min(1),
      contact_email: z.string().email(),
      contact_name: z.string().min(1),
      scopes: z.array(z.string()).optional(),
      active: z.boolean().optional().describe('Only valid for s2s_oauth apps.'),
      manifest: z.record(z.string(), z.unknown()).optional(),
    },
    annotations: { destructiveHint: false, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_create_app', session, scope: WRITE_SCOPE, audit, handler: (input, context) => callZoom({
    method: 'POST',
    path: '/marketplace/apps',
    body: input,
    onUpstreamStatus: context.setUpstreamStatus,
  }) }));

  server.registerTool('marketplace_get_app', {
    description: 'Get metadata, status, permissions, requirements, and scopes for one Zoom Marketplace app. This does not return client credentials or the complete manifest; use marketplace_export_app_manifest for editable manifest data.',
    inputSchema: { app_id: z.string().min(1) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_get_app', session, scope: READ_SCOPE, audit, handler: ({ app_id }, context) => callZoom({
    method: 'GET',
    path: `/marketplace/apps/${encodeURIComponent(app_id)}`,
    onUpstreamStatus: context.setUpstreamStatus,
  }) }));

  server.registerTool('marketplace_delete_app', {
    description: 'Permanently delete one Zoom Marketplace app by its exact app_id through the standard Marketplace endpoint. For an unpublished developer draft, use the app_id returned by marketplace_create_app because marketplace_list_apps may not show it and an app name cannot be used for deletion. The tool verifies deletion by reading the exact app ID; a 403 or 404 confirms deletion. Confirm the app ID and deletion intent before calling.',
    inputSchema: {
      app_id: z.string().min(1),
    },
    annotations: { destructiveHint: true, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_delete_app', session, scope: WRITE_SCOPE, audit, handler: ({ app_id }, context) => deleteMarketplaceApp({
    callZoom: (request) => callZoom({ ...request, onUpstreamStatus: context.setUpstreamStatus }),
    appId: app_id,
  }) }));

  server.registerTool('marketplace_validate_manifest', {
    description: 'Validate a complete Zoom Marketplace manifest without changing an app. Always inspect the returned ok field because validation failures may be returned as ok:false with field-level errors rather than as an HTTP or MCP error. Include app_id when validating a replacement manifest for an existing app.',
    inputSchema: {
      manifest: z.record(z.string(), z.unknown()),
      app_id: z.string().optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_validate_manifest', session, scope: READ_SCOPE, audit, handler: ({ manifest, app_id }, context) => callZoom({
    method: 'POST',
    path: '/marketplace/apps/manifest/validate',
    body: { manifest, ...(app_id ? { app_id } : {}) },
    onUpstreamStatus: context.setUpstreamStatus,
  }) }));

  server.registerTool('marketplace_export_app_manifest', {
    description: 'Export the complete normalized manifest of an existing Zoom Marketplace app for inspection, validation, or editing. The result does not include client credentials or secrets. Use this export as the base for marketplace_update_app_manifest so unchanged fields are preserved.',
    inputSchema: { app_id: z.string().min(1) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_export_app_manifest', session, scope: READ_SCOPE, audit, handler: ({ app_id }, context) => callZoom({
    method: 'GET',
    path: `/marketplace/apps/${encodeURIComponent(app_id)}/manifest`,
    onUpstreamStatus: context.setUpstreamStatus,
  }) }));

  server.registerTool('marketplace_update_app_manifest', {
    description: 'Replace the entire manifest of an existing Zoom Marketplace app. Export the current manifest first, modify only intended fields, validate the complete result with app_id, then update and export again to verify the read-back. Omitted fields are not preserved, and credentials are neither changed nor returned.',
    inputSchema: {
      app_id: z.string().min(1),
      manifest: z.record(z.string(), z.unknown()),
    },
    annotations: { destructiveHint: true, openWorldHint: false },
  }, toolHandler({ tool: 'marketplace_update_app_manifest', session, scope: WRITE_SCOPE, audit, handler: ({ app_id, manifest }, context) => callZoom({
    method: 'PUT',
    path: `/marketplace/apps/${encodeURIComponent(app_id)}/manifest`,
    body: { manifest },
    onUpstreamStatus: context.setUpstreamStatus,
  }) }));

  return server;
}

export async function handleMarketplaceMcpRequest(req, res, dependencies) {
  const server = createMarketplaceMcpServer(dependencies);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error('MCP request failed:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: 'Internal server error' },
        id: null,
      });
    }
  } finally {
    res.on('close', () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
  }
}
