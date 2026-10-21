import fs from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const DEFAULT_RETAINED_FILES = 10;

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function auditRecord(event) {
  return {
    timestamp: new Date().toISOString(),
    tool: String(event.tool),
    success: event.success === true,
    latency_ms: Math.max(0, Math.round(Number(event.latency_ms) || 0)),
    upstream_status: Number.isInteger(event.upstream_status) ? event.upstream_status : null,
  };
}

export function createUsageAuditLogger({
  filePath = 'logs/usage-audit.jsonl',
  maxBytes = DEFAULT_MAX_BYTES,
  retainedFiles = DEFAULT_RETAINED_FILES,
} = {}) {
  const resolvedPath = path.resolve(filePath);
  const byteLimit = positiveInteger(maxBytes, DEFAULT_MAX_BYTES);
  const retentionLimit = positiveInteger(retainedFiles, DEFAULT_RETAINED_FILES);
  let pending = Promise.resolve();

  async function rotateIfNeeded(incomingBytes) {
    const current = await fs.stat(resolvedPath).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (!current || current.size + incomingBytes <= byteLimit) return;

    await fs.rm(`${resolvedPath}.${retentionLimit}`, { force: true });
    for (let index = retentionLimit - 1; index >= 1; index -= 1) {
      await fs.rename(`${resolvedPath}.${index}`, `${resolvedPath}.${index + 1}`).catch((error) => {
        if (error.code !== 'ENOENT') throw error;
      });
    }
    await fs.rename(resolvedPath, `${resolvedPath}.1`);
  }

  async function append(event) {
    const line = `${JSON.stringify(auditRecord(event))}\n`;
    await fs.mkdir(path.dirname(resolvedPath), { recursive: true, mode: 0o700 });
    await rotateIfNeeded(Buffer.byteLength(line));
    await fs.appendFile(resolvedPath, line, { encoding: 'utf8', mode: 0o600 });
    await fs.chmod(resolvedPath, 0o600);
  }

  return {
    filePath: resolvedPath,
    record(event) {
      pending = pending.catch(() => {}).then(() => append(event));
      return pending;
    },
  };
}
