import fs from 'node:fs';
import crypto from 'node:crypto';
import { normalizeId } from '../src/security.mjs';

const idsPath = process.argv[2];
const expiresAt = process.argv[3] || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
if (!idsPath) {
  console.error('Usage: node scripts/generate-invites.mjs participant-ids.txt [expires_at] > invites.csv');
  process.exit(1);
}
const ids = [...new Set(fs.readFileSync(idsPath, 'utf8').split(/\r?\n/).map(normalizeId).filter(Boolean))];
if (!ids.length || ids.length > 100) throw new Error('Provide between 1 and 100 Participant IDs.');
if (Number.isNaN(new Date(expiresAt).getTime())) throw new Error('Invalid expiry date.');
console.log('participant_id,activation_code,expires_at');
for (const id of ids) {
  if (!/^[A-Z0-9][A-Z0-9_-]{2,39}$/.test(id)) throw new Error(`Invalid Participant ID: ${id}`);
  console.log(`${id},${crypto.randomBytes(18).toString('base64url')},${expiresAt}`);
}
