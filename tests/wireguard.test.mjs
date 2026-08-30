import test from 'node:test';
import assert from 'node:assert/strict';
import { buildConfig } from '../src/config.mjs';
import {
  addressInPeerPool,
  allocatePeerAddress,
  enrollmentExpiry,
  parsePeerPool,
  peerType,
  tokenState,
  validateEnrollment,
} from '../src/wireguard.mjs';
import { eventPhase } from '../src/game.mjs';

test('configuration keeps attacker and target pools independently overridable', () => {
  const config = buildConfig({
    APP_ORIGIN: 'https://las.example.test/',
    DATA_DIR: './runtime-data',
    WG_ATTACKER_START: '10.90.0.10',
    WG_ATTACKER_END: '10.90.0.19',
    WG_TARGET_START: '10.90.0.100',
    WG_TARGET_END: '10.90.0.109',
    SKIP_NETWORK_CHECKS: 'false',
    NODE_ENV: 'production',
  }, 'C:/portal');
  assert.equal(config.origin, 'https://las.example.test');
  assert.equal(config.dataDir, 'C:\\portal\\runtime-data');
  assert.equal(config.attackerStart, '10.90.0.10');
  assert.equal(config.targetStart, '10.90.0.100');
  assert.equal(config.skipNetworkChecks, false);
  assert.equal(config.wgHelperDryRun, false);
  assert.equal(config.healthBackgroundIntervalMs, 600_000);
  assert.equal(config.production, true);
  assert.equal(buildConfig({ NODE_ENV: 'test' }).wgHelperDryRun, true);
});

test('peer pool parsing validates type and range', () => {
  const pool = parsePeerPool('attacker', '10.77.4.10', '10.77.4.12');
  assert.equal(pool.type, 'attacker');
  assert.equal(Object.isFrozen(pool), true);
  assert.equal(addressInPeerPool(pool, '10.77.4.10'), true);
  assert.equal(addressInPeerPool(pool, '10.77.4.12'), true);
  assert.equal(addressInPeerPool(pool, '10.77.4.13'), false);
  assert.equal(peerType(' TARGET '), 'target');
  assert.equal(peerType('admin'), null);
  assert.throws(() => parsePeerPool('admin', '10.77.4.1', '10.77.4.2'), /INVALID_PEER_TYPE/);
  assert.throws(() => parsePeerPool('target', '10.77.4.5', '10.77.4.4'), /INVALID_PEER_POOL/);
});

test('peer allocation is deterministic and reports exhaustion', () => {
  const pool = parsePeerPool('target', '10.77.4.100', '10.77.4.102');
  assert.equal(allocatePeerAddress(pool), '10.77.4.100');
  assert.equal(allocatePeerAddress(pool, ['10.77.4.100']), '10.77.4.101');
  assert.equal(allocatePeerAddress(pool, ['10.77.4.100', '10.77.4.101']), '10.77.4.102');
  assert.throws(() => allocatePeerAddress(pool, ['10.77.4.100', '10.77.4.101', '10.77.4.102']), /POOL_EXHAUSTED/);
});

test('enrollment expiry is deterministic and rejects invalid clock/ttl inputs', () => {
  assert.equal(enrollmentExpiry('2026-08-31T00:00:00.000Z', 60_000), '2026-08-31T00:01:00.000Z');
  assert.throws(() => enrollmentExpiry('not-a-date'), /INVALID_TOKEN_EXPIRY/);
  assert.throws(() => enrollmentExpiry(Date.now(), 0), /INVALID_TOKEN_EXPIRY/);
});

const validRecord = {
  token_hash: 'hash-only',
  user_id: 7,
  peer_id: 12,
  peer_type: 'attacker',
  expires_at: '2026-09-01T00:10:00.000Z',
  used_at: null,
};

test('token lifecycle distinguishes missing, used, expired, and valid records', () => {
  const now = '2026-09-01T00:00:00.000Z';
  assert.deepEqual(tokenState(null, now), { ok: false, code: 'TOKEN_INVALID' });
  assert.deepEqual(tokenState({ ...validRecord, used_at: now }, now), { ok: false, code: 'TOKEN_USED' });
  assert.deepEqual(tokenState({ ...validRecord, expires_at: now }, now), { ok: false, code: 'TOKEN_EXPIRED' });
  assert.deepEqual(tokenState(validRecord, now), { ok: true, code: 'TOKEN_OK' });
});

test('enrollment binds the token to account, peer, and peer type', () => {
  const now = '2026-09-01T00:00:00.000Z';
  assert.deepEqual(validateEnrollment({ record: validRecord, userId: 7, peerId: 12, peerType: 'attacker', now }), { ok: true, code: 'ENROLLMENT_OK' });
  assert.equal(validateEnrollment({ record: validRecord, userId: 8, peerId: 12, peerType: 'attacker', now }).code, 'TOKEN_OWNER_MISMATCH');
  assert.equal(validateEnrollment({ record: validRecord, userId: 7, peerId: 13, peerType: 'attacker', now }).code, 'TOKEN_PEER_MISMATCH');
  assert.equal(validateEnrollment({ record: validRecord, userId: 7, peerId: 12, peerType: 'target', now }).code, 'TOKEN_TYPE_MISMATCH');
  assert.equal(validateEnrollment({ record: { ...validRecord, expires_at: now }, userId: 7, peerId: 12, peerType: 'attacker', now }).code, 'TOKEN_EXPIRED');
});

test('event phase boundaries are server-enforceable', () => {
  const build = '2026-09-02T02:00:00.000Z';
  const open = '2026-09-02T04:00:00.000Z';
  const lock = '2026-09-04T11:00:00.000Z';
  assert.equal(eventPhase('2026-09-02T01:59:59.999Z', build, open, lock), 'BUILDING');
  assert.equal(eventPhase(build, build, open, lock), 'REVIEW');
  assert.equal(eventPhase(open, build, open, lock), 'LIVE');
  assert.equal(eventPhase(lock, build, open, lock), 'LOCKED');
});
