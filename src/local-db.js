import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const EMPTY_STORE = {
  installations: {},
  supportRequests: [],
  oauth: {
    clients: {},
    authorizationCodes: {},
    accessTokens: {},
    refreshTokens: {},
  },
};

function normalizeStore(store = {}) {
  return {
    ...store,
    installations: store.installations || {},
    supportRequests: Array.isArray(store.supportRequests) ? store.supportRequests : [],
    oauth: {
      ...EMPTY_STORE.oauth,
      ...(store.oauth || {}),
    },
  };
}

function keyFromConfig(value, fallbackSecret) {
  const configured = String(value || '').trim();
  if (configured) {
    const base64 = Buffer.from(configured, 'base64');
    if (base64.length === 32) return base64;
    if (/^[0-9a-f]{64}$/i.test(configured)) return Buffer.from(configured, 'hex');
    throw new Error('TOKEN_ENCRYPTION_KEY must be a 32-byte base64 or 64-character hex value');
  }
  if (!fallbackSecret) {
    throw new Error('TOKEN_ENCRYPTION_KEY or SESSION_SECRET is required for encrypted local storage');
  }
  return crypto.createHash('sha256').update(`marketplace-helper:${fallbackSecret}`).digest();
}

function encrypt(value, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return {
    ciphertext,
    iv,
    authTag: cipher.getAuthTag(),
  };
}

function decrypt(row, key) {
  if (row.auth_tag.length !== 16) {
    throw new Error('Invalid encrypted state authentication tag');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, row.iv, { authTagLength: 16 });
  decipher.setAuthTag(row.auth_tag);
  const plaintext = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]).toString('utf8');
  return normalizeStore(JSON.parse(plaintext));
}

function readLegacyJson(legacyJsonPath) {
  if (!legacyJsonPath || !fs.existsSync(legacyJsonPath)) return null;
  return normalizeStore(JSON.parse(fs.readFileSync(legacyJsonPath, 'utf8')));
}

export function createLocalDatabase({ databasePath, encryptionKey, fallbackSecret, legacyJsonPath }) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true, mode: 0o700 });
  const db = new Database(databasePath, { fileMustExist: false });
  db.pragma('journal_mode = DELETE');
  db.pragma('synchronous = FULL');
  db.pragma('secure_delete = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS encrypted_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      ciphertext BLOB NOT NULL,
      iv BLOB NOT NULL,
      auth_tag BLOB NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  const key = keyFromConfig(encryptionKey, fallbackSecret);
  const readRow = db.prepare('SELECT ciphertext, iv, auth_tag FROM encrypted_state WHERE id = 1');
  const writeRow = db.prepare(`
    INSERT INTO encrypted_state (id, ciphertext, iv, auth_tag, updated_at)
    VALUES (1, @ciphertext, @iv, @authTag, @updatedAt)
    ON CONFLICT(id) DO UPDATE SET
      ciphertext = excluded.ciphertext,
      iv = excluded.iv,
      auth_tag = excluded.auth_tag,
      updated_at = excluded.updated_at
  `);

  function write(store) {
    const encrypted = encrypt(normalizeStore(store), key);
    const transaction = db.transaction(() => {
      writeRow.run({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        updatedAt: new Date().toISOString(),
      });
    });
    transaction();
    fs.chmodSync(databasePath, 0o600);
  }

  function migrateLegacyStore() {
    if (!legacyJsonPath || path.resolve(legacyJsonPath) === path.resolve(databasePath)) return null;
    const legacyStore = readLegacyJson(legacyJsonPath);
    if (!legacyStore) return null;
    write(legacyStore);
    fs.unlinkSync(legacyJsonPath);
    return legacyStore;
  }

  function read() {
    const row = readRow.get();
    if (row) return decrypt(row, key);
    const migrated = migrateLegacyStore();
    if (migrated) return migrated;
    const empty = normalizeStore(EMPTY_STORE);
    write(empty);
    return empty;
  }

  return {
    read,
    write,
    close: () => db.close(),
    databasePath,
  };
}
