import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { sha256, normalizeId } from '../src/security.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(HERE, '..');
const csvPath = process.argv[2];
if (!csvPath) {
  console.error('Usage: npm run import:invites -- ./invites.csv');
  process.exit(1);
}
const envPath = path.join(root, '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (match && !(match[1] in process.env)) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
const dataDir = path.resolve(root, process.env.DATA_DIR || './data');
const dbName = fs.existsSync(path.join(dataDir, 'ctf-portal.db')) || !fs.existsSync(path.join(dataDir, 'las-week4.db')) ? 'ctf-portal.db' : 'las-week4.db';
const db = new DatabaseSync(path.join(dataDir, dbName));
const rows = fs.readFileSync(path.resolve(process.cwd(), csvPath), 'utf8').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
const header = rows.shift().toLowerCase().replace(/\s/g, '');
const validHeaders = new Set(['caas_id,activation_code,expires_at', 'participant_id,activation_code,expires_at', 'player_id,activation_code,expires_at']);
if (!validHeaders.has(header)) {
  console.error('CSV header must be: participant_id,activation_code,expires_at');
  process.exit(1);
}
const insert = db.prepare(`INSERT INTO invites (caas_id, code_hash, expires_at) VALUES (?, ?, ?)
  ON CONFLICT(caas_id) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, used_at=NULL`);
const items = rows.map((line, index) => {
  const [idRaw, codeRaw, expiresRaw] = line.split(',').map((part) => part.trim());
  const id = normalizeId(idRaw);
  const code = String(codeRaw || '');
  const expires = new Date(expiresRaw);
  if (!/^[A-Z0-9][A-Z0-9_-]{2,39}$/.test(id) || code.length < 12 || Number.isNaN(expires.getTime())) throw new Error(`Invalid row ${index + 2}`);
  return [id, sha256(code), expires.toISOString()];
});
db.exec('BEGIN IMMEDIATE');
try {
  for (const item of items) insert.run(...item);
  db.exec('COMMIT');
} catch (error) {
  try { db.exec('ROLLBACK'); } catch {}
  throw error;
}
console.log(`Imported ${items.length} activation invite(s). Codes are not printed.`);
db.close();
