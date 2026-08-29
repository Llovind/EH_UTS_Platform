const DEFAULT_HANDSHAKE_MAX_AGE_MS = 3 * 60 * 1000;
const DEFAULT_PROBE_INTERVAL_MS = 20 * 1000;
const DEFAULT_REQUIRED_FAILURES = 3;

function timeValue(value) {
  const stamp = new Date(value).getTime();
  return Number.isFinite(stamp) ? stamp : null;
}

export function handshakeIsStale(lastHandshakeAt, now = Date.now(), maxAgeMs = DEFAULT_HANDSHAKE_MAX_AGE_MS) {
  const handshake = timeValue(lastHandshakeAt);
  const current = timeValue(now);
  return handshake === null || current === null || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0 || current - handshake > maxAgeMs;
}

/**
 * A failure streak is only valid when the newest checks are all failures and
 * every attempt is separated by the configured minimum interval. A successful
 * check resets the streak, which prevents one transient packet loss from
 * changing the published health state.
 */
export function hasConsecutiveProbeFailures(checks = [], requiredFailures = DEFAULT_REQUIRED_FAILURES, minIntervalMs = DEFAULT_PROBE_INTERVAL_MS) {
  const required = Number(requiredFailures);
  const interval = Number(minIntervalMs);
  if (!Number.isInteger(required) || required < 1 || !Number.isFinite(interval) || interval < 0) return false;
  const ordered = checks
    .filter((check) => check && check.check_type === 'target_reachability')
    .map((check) => ({ ...check, stamp: timeValue(check.created_at) }))
    .filter((check) => check.stamp !== null)
    .sort((left, right) => left.stamp - right.stamp);
  let trailingFailures = 0;
  for (let index = ordered.length - 1; index >= 0 && ordered[index].status === 'fail'; index -= 1) trailingFailures += 1;
  if (trailingFailures < required) return false;
  const streak = ordered.slice(-trailingFailures).slice(-required);
  for (let index = 1; index < streak.length; index += 1) {
    if (streak[index].stamp - streak[index - 1].stamp < interval) return false;
  }
  return true;
}

export function shouldMarkDegraded({ lastHandshakeAt, checks = [], now = Date.now(), handshakeMaxAgeMs = DEFAULT_HANDSHAKE_MAX_AGE_MS, requiredFailures = DEFAULT_REQUIRED_FAILURES, probeIntervalMs = DEFAULT_PROBE_INTERVAL_MS } = {}) {
  return handshakeIsStale(lastHandshakeAt, now, handshakeMaxAgeMs) && hasConsecutiveProbeFailures(checks, requiredFailures, probeIntervalMs);
}

export function healthDecision({ currentStatus = 'unknown', probeOk, lastHandshakeAt, checks = [], now = Date.now(), handshakeMaxAgeMs = DEFAULT_HANDSHAKE_MAX_AGE_MS, requiredFailures = DEFAULT_REQUIRED_FAILURES, probeIntervalMs = DEFAULT_PROBE_INTERVAL_MS } = {}) {
  if (probeOk === true) return { status: 'healthy', reason: 'TARGET_REACHABLE' };
  if (shouldMarkDegraded({ lastHandshakeAt, checks, now, handshakeMaxAgeMs, requiredFailures, probeIntervalMs })) {
    return { status: 'degraded', reason: 'HANDSHAKE_STALE_AND_PROBE_FAILURE_STREAK' };
  }
  return { status: currentStatus === 'disabled' ? 'disabled' : currentStatus, reason: 'WAITING_FOR_HEALTH_THRESHOLD' };
}
