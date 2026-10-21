import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { toolHandler } from '../src/mcp.js';
import { createUsageAuditLogger } from '../src/usage-audit.js';

test('audit log includes only allowlisted usage fields', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'marketplace-audit-'));
  const filePath = path.join(directory, 'usage.jsonl');
  const logger = createUsageAuditLogger({ filePath });

  await logger.record({
    tool: 'marketplace_get_app',
    success: true,
    latency_ms: 12.6,
    upstream_status: 200,
    access_token: 'must-not-be-written',
    app_id: 'must-not-be-written',
  });

  const record = JSON.parse((await fs.readFile(filePath, 'utf8')).trim());
  assert.deepEqual(Object.keys(record), [
    'timestamp',
    'tool',
    'success',
    'latency_ms',
    'upstream_status',
  ]);
  assert.equal(record.tool, 'marketplace_get_app');
  assert.equal(record.success, true);
  assert.equal(record.latency_ms, 13);
  assert.equal(record.upstream_status, 200);
  assert.equal((await fs.stat(filePath)).mode & 0o777, 0o600);
});

test('tool handler audits success and failure without inputs or outputs', async () => {
  const events = [];
  const audit = async (event) => events.push(event);
  const session = { scopes: ['marketplace:read'] };

  const successHandler = toolHandler({
    tool: 'marketplace_list_apps',
    session,
    scope: 'marketplace:read',
    audit,
    handler: async (_input, context) => {
      context.setUpstreamStatus(200);
      return { apps: [] };
    },
  });
  await successHandler({ secret_argument: 'must-not-be-audited' });

  const failureHandler = toolHandler({
    tool: 'marketplace_get_app',
    session,
    scope: 'marketplace:read',
    audit,
    handler: async (_input, context) => {
      context.setUpstreamStatus(429);
      throw Object.assign(new Error('zoom_api_request_failed'), { status: 429 });
    },
  });
  const failure = await failureHandler({ app_id: 'must-not-be-audited' });

  assert.equal(failure.isError, true);
  assert.equal(events.length, 2);
  assert.equal(events[0].success, true);
  assert.equal(events[0].upstream_status, 200);
  assert.equal(events[1].success, false);
  assert.equal(events[1].upstream_status, 429);
  assert.equal(JSON.stringify(events).includes('must-not-be-audited'), false);
});

test('an audit write failure does not change the tool result', async () => {
  const handler = toolHandler({
    tool: 'marketplace_list_apps',
    session: { scopes: ['marketplace:read'] },
    scope: 'marketplace:read',
    audit: async () => {
      throw new Error('disk unavailable');
    },
    handler: async () => ({ apps: [] }),
  });

  const result = await handler({});
  assert.deepEqual(result.structuredContent, { apps: [] });
});

test('audit log rotates at the configured size', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'marketplace-audit-'));
  const filePath = path.join(directory, 'usage.jsonl');
  const logger = createUsageAuditLogger({ filePath, maxBytes: 1, retainedFiles: 2 });

  await logger.record({ tool: 'first', success: true, latency_ms: 1, upstream_status: 200 });
  await logger.record({ tool: 'second', success: false, latency_ms: 2, upstream_status: 500 });

  assert.match(await fs.readFile(`${filePath}.1`, 'utf8'), /"tool":"first"/);
  assert.match(await fs.readFile(filePath, 'utf8'), /"tool":"second"/);
});
