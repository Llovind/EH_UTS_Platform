import fs from 'node:fs';
import crypto from 'node:crypto';
import { normalizeId } from '../src/security.mjs';

const idsPath = process.argv[2];
const expiresAt = process.argv[3] || '2026-09-02T09:00:00+07:00';
if (!idsPath) {
  console.error('Usage: node scripts/generate-invites.mjs caas-ids.txt [expires_at] > invites.csv');
  process.exit(1);
}
const ids = [...new Set(fs.readFileSync(idsPath, 'utf8').split(/\r?\n/).map(normalizeId).filter(Boolean))];
if (!ids.length || ids.length > 100) throw new Error('Provide between 1 and 100 CaAs IDs.');
if (Number.isNaN(new Date(expiresAt).getTime())) throw new Error('Invalid expiry date.');
console.log('caas_id,activation_code,expires_at');
for (const id of ids) {
  if (!/^[A-Z0-9][A-Z0-9_-]{2,39}$/.test(id)) throw new Error(`Invalid CaAs ID: ${id}`);
  console.log(`${id},${crypto.randomBytes(18).toString('base64url')},${expiresAt}`);
}
