import test from 'node:test';
import assert from 'node:assert/strict';
import { handshakeIsStale, hasConsecutiveProbeFailures, healthDecision, shouldMarkDegraded } from '../src/health.mjs';

const now = new Date('2026-09-04T12:00:00.000Z');
const check = (secondsAgo, status = 'fail') => ({ check_type: 'target_reachability', status, created_at: new Date(now.getTime() - secondsAgo * 1000).toISOString() });

test('health requires a fresh WireGuard handshake for a non-degraded target', () => {
  assert.equal(handshakeIsStale(new Date(now.getTime() - 179_000), now, 180_000), false);
  assert.equal(handshakeIsStale(new Date(now.getTime() - 181_000), now, 180_000), true);
});

test('probe streak requires three failures spaced by the configured interval and resets after a pass', () => {
  assert.equal(hasConsecutiveProbeFailures([check(60), check(40), check(20)], 3, 20_000), true);
  assert.equal(hasConsecutiveProbeFailures([check(60), check(50), check(20)], 3, 20_000), false);
  assert.equal(hasConsecutiveProbeFailures([check(80), check(60), check(40, 'pass'), check(20)], 3, 20_000), false);
});

test('degraded decision needs both stale handshake and the complete failure streak', () => {
  assert.equal(shouldMarkDegraded({ lastHandshakeAt: new Date(now.getTime() - 181_000), checks: [check(60), check(40), check(20)], now, handshakeMaxAgeMs: 180_000, requiredFailures: 3, probeIntervalMs: 20_000 }), true);
  assert.equal(shouldMarkDegraded({ lastHandshakeAt: new Date(now.getTime() - 30_000), checks: [check(60), check(40), check(20)], now, handshakeMaxAgeMs: 180_000, requiredFailures: 3, probeIntervalMs: 20_000 }), false);
  assert.deepEqual(healthDecision({ currentStatus: 'healthy', probeOk: false, lastHandshakeAt: new Date(now.getTime() - 30_000), checks: [check(60)], now }), { status: 'healthy', reason: 'WAITING_FOR_HEALTH_THRESHOLD' });
});
