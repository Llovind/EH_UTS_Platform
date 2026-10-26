import path from 'node:path';
import { normalizeId } from './security.mjs';

const value = (env, key, fallback) => env[key] === undefined || env[key] === '' ? fallback : env[key];

/**
 * Read runtime configuration without mutating process.env.
 * Stripped to CTF-portal essentials: no WireGuard peer pools or health probes.
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
    portalOpenAt: String(value(env, 'PORTAL_OPEN_AT', '2026-09-02T11:00:00+07:00')),
    gameLockAt: String(value(env, 'GAME_LOCK_AT', '2026-09-04T18:00:00+07:00')),
    trustedProxyIps: String(value(env, 'TRUSTED_PROXY_IPS', '127.0.0.1,::1')).split(',').map((ip) => ip.trim()).filter(Boolean),
    vulnMachineUrl: String(value(env, 'VULN_MACHINE_URL', 'https://drive.google.com/drive/folders/1VmJFkHvxpfF5WYlh1-3pttyZJUyviEXN')).trim(),
    production,
  });
}
