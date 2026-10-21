import fs from 'node:fs';
import path from 'node:path';

const configuredPath = process.argv[2] || process.env.USAGE_AUDIT_LOG_PATH || 'logs/usage-audit.jsonl';
const auditPath = path.resolve(configuredPath);
const directory = path.dirname(auditPath);
const baseName = path.basename(auditPath);

const files = fs.existsSync(directory)
  ? fs.readdirSync(directory)
    .filter((name) => name === baseName || name.startsWith(`${baseName}.`))
    .map((name) => path.join(directory, name))
  : [];

const totals = new Map();
for (const file of files) {
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const record = JSON.parse(line);
      const day = String(record.timestamp || '').slice(0, 10);
      const tool = String(record.tool || 'unknown');
      const outcome = record.success === true ? 'success' : 'failure';
      const key = `${day}\t${tool}\t${outcome}`;
      totals.set(key, (totals.get(key) || 0) + 1);
    } catch {
      // Ignore incomplete lines left by an interrupted write.
    }
  }
}

if (totals.size === 0) {
  console.log('No usage audit records.');
  process.exit(0);
}

console.log('date_utc\ttool\toutcome\tcount');
for (const [key, count] of [...totals.entries()].sort(([left], [right]) => left.localeCompare(right))) {
  console.log(`${key}\t${count}`);
}
