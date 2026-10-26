import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';

const ROOT = path.resolve(import.meta.dirname, '..');

test('invite importer uses a node:sqlite-compatible atomic transaction', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'las-w4-invites-'));
  const dataDir = path.join(temp, 'data');
  fs.mkdirSync(dataDir);
  const dbPath = path.join(dataDir, 'las-week4.db');
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caas_id TEXT NOT NULL UNIQUE,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  db.close();

  const csv = path.join(temp, 'invites.csv');
  fs.writeFileSync(csv, 'caas_id,activation_code,expires_at\nCAAS-TEST-01,abcdefghijklmnop,2026-09-02T09:00:00+07:00\n');
  const result = spawnSync(process.execPath, ['--experimental-sqlite', path.join(ROOT, 'scripts', 'import-invites.mjs'), csv], {
    cwd: ROOT,
    env: { ...process.env, DATA_DIR: dataDir },
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Imported 1 activation invite/);

  const verify = new DatabaseSync(dbPath);
  const invite = verify.prepare('SELECT caas_id,code_hash FROM invites').get();
  verify.close();
  assert.equal(invite.caas_id, 'CAAS-TEST-01');
  assert.notEqual(invite.code_hash, 'abcdefghijklmnop');
  try {
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {}
});
