import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { hashPassword, verifyPassword, encryptSecret, decryptSecret, isInCidr, validTargetIp, validFlag } from '../src/security.mjs';
import { scoreForSolved, isOpen, isLocked } from '../src/game.mjs';

const KEY = crypto.randomBytes(32).toString('base64');

test('password hashes verify and do not equal plaintext', () => {
  const encoded = hashPassword('correct horse battery staple');
  assert.notEqual(encoded, 'correct horse battery staple');
  assert.equal(verifyPassword('correct horse battery staple', encoded), true);
  assert.equal(verifyPassword('wrong password', encoded), false);
});

test('mentor secrets round-trip through authenticated encryption', () => {
  const encoded = encryptSecret('MBC{private-flag}', KEY);
  assert.equal(decryptSecret(encoded, KEY), 'MBC{private-flag}');
  assert.throws(() => decryptSecret(encoded, crypto.randomBytes(32).toString('base64')));
});

test('WireGuard and target ranges are enforced', () => {
  assert.equal(isInCidr('10.77.4.17', '10.77.4.0/24'), true);
  assert.equal(isInCidr('10.77.5.17', '10.77.4.0/24'), false);
  assert.equal(validTargetIp('10.77.4.100'), true);
  assert.equal(validTargetIp('10.77.4.99'), false);
  assert.equal(validTargetIp('10.77.4.130'), false);
  assert.equal(validTargetIp('203.0.113.10'), false);
});

test('flag format is strict and case-sensitive', () => {
  assert.equal(validFlag('MBC{path_01}'), true);
  assert.equal(validFlag('mbc{path_01}'), false);
  assert.equal(validFlag('MBC{too short}'), false);
});

test('event gates and equal-point scoring are deterministic', () => {
  assert.equal(isOpen('2026-09-02T10:59:59+07:00', '2026-09-02T11:00:00+07:00'), false);
  assert.equal(isOpen('2026-09-02T11:00:00+07:00', '2026-09-02T11:00:00+07:00'), true);
  assert.equal(isLocked('2026-09-04T17:59:59+07:00', '2026-09-04T18:00:00+07:00'), false);
  assert.deepEqual(scoreForSolved([{ correct: 1, first_blood: 1, submitted_at: '2026-09-02T04:00:00Z' }, { correct: 1, first_blood: 0, submitted_at: '2026-09-02T05:00:00Z' }]), { points: 210, solved: 2, firstReachedAt: '2026-09-02T05:00:00Z' });
});
