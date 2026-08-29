import { ipv4ToNumber, numberToIpv4 } from './security.mjs';

const PEER_TYPES = new Set(['attacker', 'target']);

/**
 * Build an immutable address pool from configuration values.
 * This module deliberately has no database or process-global state so that
 * allocation and enrollment rules can be tested independently of Express.
 */
export function parsePeerPool(type, startIp, endIp) {
  if (!PEER_TYPES.has(type)) throw new Error('INVALID_PEER_TYPE');
  const start = ipv4ToNumber(startIp);
  const end = ipv4ToNumber(endIp);
  if (start === null || end === null || end < start) throw new Error('INVALID_PEER_POOL');
  return Object.freeze({ type, startIp: String(startIp).trim(), endIp: String(endIp).trim(), start, end });
}
export function peerType(value) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return PEER_TYPES.has(normalized) ? normalized : null;
}

export function addressInPeerPool(pool, address) {
  const value = ipv4ToNumber(address);
  return value !== null && value >= pool.start && value <= pool.end;
}

/** Return the lowest free address, keeping assignments deterministic. */
export function allocatePeerAddress(pool, usedAddresses = []) {
  const used = new Set(Array.from(usedAddresses, (address) => String(address).trim()));
  for (let value = pool.start; value <= pool.end; value += 1) {
    const address = numberToIpv4(value);
    if (!used.has(address)) return address;
  }
  throw new Error('POOL_EXHAUSTED');
}

export function enrollmentExpiry(now = Date.now(), ttlMs = 10 * 60 * 1000) {
  const stamp = new Date(now).getTime();
  if (!Number.isFinite(stamp) || !Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error('INVALID_TOKEN_EXPIRY');
  return new Date(stamp + ttlMs).toISOString();
}

/** Validate database-independent token lifecycle state. */
export function tokenState(record, now = Date.now()) {
  if (!record || !record.token_hash) return { ok: false, code: 'TOKEN_INVALID' };
  if (record.used_at) return { ok: false, code: 'TOKEN_USED' };
  const expiresAt = new Date(record.expires_at).getTime();
  const current = new Date(now).getTime();
  if (!Number.isFinite(expiresAt) || !Number.isFinite(current) || expiresAt <= current) return { ok: false, code: 'TOKEN_EXPIRED' };
  return { ok: true, code: 'TOKEN_OK' };
}

/** Validate token ownership and peer binding after the token hash matched. */
export function validateEnrollment({ record, userId, peerId, peerType: requestedType, now = Date.now() }) {
  const state = tokenState(record, now);
  if (!state.ok) return state;
  if (String(record.user_id) !== String(userId)) return { ok: false, code: 'TOKEN_OWNER_MISMATCH' };
  if (String(record.peer_id) !== String(peerId)) return { ok: false, code: 'TOKEN_PEER_MISMATCH' };
  if (peerType(requestedType) === null || peerType(record.peer_type) !== peerType(requestedType)) return { ok: false, code: 'TOKEN_TYPE_MISMATCH' };
  return { ok: true, code: 'ENROLLMENT_OK' };
}
