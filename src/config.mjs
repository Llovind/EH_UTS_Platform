import path from 'node:path';
import { normalizeId } from './security.mjs';

const value = (env, key, fallback) => env[key] === undefined || env[key] === '' ? fallback : env[key];

/**
 * Read runtime configuration without mutating process.env. Keeping this
 * boundary separate makes development, tests, and deployment use the same
 * defaults while allowing the WireGuard pools to be configured independently.
 */
export function buildConfig(env = {}, baseDir = process.cwd()) {
  const production = value(env, 'NODE_ENV', '') === 'production';
  return Object.freeze({
    port: Number(value(env, 'PORT', 3000)),
    bindHost: String(value(env, 'APP_BIND_HOST', '127.0.0.1')),
    origin: String(value(env, 'APP_ORIGIN', 'http://localhost:3000')).replace(/\/+$/, ''),
    dataDir: path.resolve(baseDir, value(env, 'DATA_DIR', './data')),
    appKey: String(value(env, 'APP_KEY_BASE64', '')),
    adminId: normalizeId(value(env, 'ADMIN_ID', 'MBC-ADMIN')),
    adminPassword: String(value(env, 'ADMIN_PASSWORD', '')),
    adminTotp: String(value(env, 'ADMIN_TOTP_SECRET', '')),
    buildDeadlineAt: String(value(env, 'BUILD_DEADLINE_AT', '2026-09-02T09:00:00+07:00')),
    portalOpenAt: String(value(env, 'PORTAL_OPEN_AT', '2026-09-02T11:00:00+07:00')),
    submissionDeadlineAt: String(value(env, 'SUBMISSION_DEADLINE_AT', '2026-09-04T15:00:00+07:00')),
    gameLockAt: String(value(env, 'GAME_LOCK_AT', '2026-09-04T18:00:00+07:00')),
    wgCidr: String(value(env, 'WG_CIDR', value(env, 'WIREGUARD_CIDR', '10.77.4.0/24'))),
    wgHubIp: String(value(env, 'WG_HUB_IP', '10.77.4.1')),
    attackerStart: String(value(env, 'WG_ATTACKER_START', '10.77.4.10')),
    attackerEnd: String(value(env, 'WG_ATTACKER_END', '10.77.4.39')),
    targetStart: String(value(env, 'WG_TARGET_START', '10.77.4.100')),
    targetEnd: String(value(env, 'WG_TARGET_END', '10.77.4.129')),
    wgEndpoint: String(value(env, 'WG_ENDPOINT', 'ctf.example.org:51820')),
    wgServerPublicKey: String(value(env, 'WG_SERVER_PUBLIC_KEY', 'HUB_PUBLIC_KEY')),
    wgVerifyUrl: String(value(env, 'WG_VERIFY_URL', 'https://portal.example.org/internal/verify')),
    wgInterface: String(value(env, 'WG_INTERFACE', 'mbc-las-w4')),
    wgHelperPath: String(value(env, 'WG_HELPER_PATH', '/usr/local/sbin/mbc-las-wg-peer')),
    wgSudoPath: String(value(env, 'WG_SUDO_PATH', '/usr/bin/sudo')),
    healthHandshakeMaxAgeMs: Number(value(env, 'WG_HEALTH_HANDSHAKE_MAX_AGE_SECONDS', 180)) * 1000,
    healthProbeIntervalMs: Number(value(env, 'WG_HEALTH_PROBE_INTERVAL_SECONDS', 20)) * 1000,
    healthRequiredFailures: Number(value(env, 'WG_HEALTH_REQUIRED_FAILURES', 3)),
    wgHelperDryRun: value(env, 'WG_HELPER_DRY_RUN', production ? 'false' : 'true') === 'true',
    trustedProxyIps: String(value(env, 'TRUSTED_PROXY_IPS', '127.0.0.1,::1')).split(',').map((ip) => ip.trim()).filter(Boolean),
    skipNetworkChecks: value(env, 'SKIP_NETWORK_CHECKS', production ? 'false' : 'true') === 'true' || !production,
    production,
  });
}

export function wireguardPools(config) {
  return Object.freeze({
    attacker: Object.freeze({ startIp: config.attackerStart, endIp: config.attackerEnd }),
    target: Object.freeze({ startIp: config.targetStart, endIp: config.targetEnd }),
  });
}
