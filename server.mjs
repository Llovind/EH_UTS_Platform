import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { DatabaseSync } from 'node:sqlite';
import {
  encryptSecret,
  decryptSecret,
  hashPassword,
  verifyPassword,
  randomToken,
  sha256,
  normalizeId,
  isStrongPassword,
  isInCidr,
  validFlag,
  ipv4InRange,
  validWireguardPublicKey,
} from './src/security.mjs';
import { eventPhase, isBefore, scoreForSolved } from './src/game.mjs';
import { buildConfig } from './src/config.mjs';
import { allocatePeerAddress, enrollmentExpiry, parsePeerPool, validateEnrollment } from './src/wireguard.mjs';
import { handshakeIsStale, healthDecision } from './src/health.mjs';
import { learnTracks, learnModules } from './src/learn-content.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function loadEnv(file = path.join(HERE, '.env')) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!match || match[1] in process.env) continue;
    process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}

loadEnv();

const cfg = buildConfig(process.env, HERE);

const appKeyBytes = Buffer.from(cfg.appKey || '', 'base64');
if (!cfg.appKey || appKeyBytes.length !== 32) {
  console.error('APP_KEY_BASE64 is required. Copy .env.example to .env and set a random 32-byte key.');
  process.exit(1);
}
if (cfg.production && (!cfg.adminPassword || cfg.adminPassword.length < 16)) {
  console.error('ADMIN_PASSWORD (16+ chars) is required in production.');
  process.exit(1);
}
if (cfg.production && (!validWireguardPublicKey(cfg.wgServerPublicKey) || cfg.wgServerPublicKey === 'HUB_PUBLIC_KEY')) {
  console.error('WG_SERVER_PUBLIC_KEY must contain the real WireGuard hub public key in production.');
  process.exit(1);
}
if (cfg.production && !/^https:\/\//i.test(cfg.origin)) {
  console.error('APP_ORIGIN must use HTTPS in production.');
  process.exit(1);
}
if (cfg.production && (cfg.wgHelperDryRun || cfg.skipNetworkChecks)) {
  console.error('WG_HELPER_DRY_RUN and SKIP_NETWORK_CHECKS must be disabled in production.');
  process.exit(1);
}
try {
  parsePeerPool('attacker', cfg.attackerStart, cfg.attackerEnd);
  parsePeerPool('target', cfg.targetStart, cfg.targetEnd);
} catch {
  console.error('WG_ATTACKER_* and WG_TARGET_* must contain valid ascending IPv4 ranges.');
  process.exit(1);
}
if (!/^[A-Za-z0-9_.-]{1,15}$/.test(cfg.wgInterface) || !/^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12]\d|3[0-2])$/.test(cfg.wgCidr) || !isInCidr(cfg.wgHubIp, cfg.wgCidr) || /[\r\n]/.test(cfg.wgEndpoint)) {
  console.error('WireGuard interface, CIDR, hub IP, or endpoint configuration is invalid.');
  process.exit(1);
}
if (!Number.isFinite(cfg.healthHandshakeMaxAgeMs) || cfg.healthHandshakeMaxAgeMs <= 0 || !Number.isFinite(cfg.healthProbeIntervalMs) || cfg.healthProbeIntervalMs < 0 || !Number.isInteger(cfg.healthRequiredFailures) || cfg.healthRequiredFailures < 1) {
  console.error('WG_HEALTH_* settings must contain positive numeric values.');
  process.exit(1);
}

fs.mkdirSync(cfg.dataDir, { recursive: true, mode: 0o700 });
try { fs.chmodSync(cfg.dataDir, 0o700); } catch {}
const db = new DatabaseSync(path.join(cfg.dataDir, 'las-week4.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');

db.exec(
  'CREATE TABLE IF NOT EXISTS users (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'caas_id TEXT NOT NULL UNIQUE,' +
  'password_hash TEXT NOT NULL,' +
  "role TEXT NOT NULL CHECK(role IN ('participant','admin')) DEFAULT 'participant'," +
  'is_visitor INTEGER NOT NULL DEFAULT 0,' +
  'is_test INTEGER NOT NULL DEFAULT 0,' +
  'active INTEGER NOT NULL DEFAULT 1,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'last_login_at TEXT' +
  ');' +
  'CREATE TABLE IF NOT EXISTS invites (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'caas_id TEXT NOT NULL UNIQUE,' +
  'code_hash TEXT NOT NULL,' +
  'expires_at TEXT NOT NULL,' +
  'used_at TEXT,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +
  'CREATE TABLE IF NOT EXISTS sessions (' +
  'token_hash TEXT PRIMARY KEY,' +
  'user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,' +
  'csrf_token TEXT NOT NULL,' +
  'ip TEXT,' +
  'user_agent TEXT,' +
  'expires_at TEXT NOT NULL,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +
  'CREATE TABLE IF NOT EXISTS wireguard_peers (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,' +
  "peer_type TEXT NOT NULL CHECK(peer_type IN ('attacker','target'))," +
  'assigned_ip TEXT NOT NULL,' +
  'public_key TEXT,' +
  "status TEXT NOT NULL CHECK(status IN ('allocated','enrolled','connected','revoked')) DEFAULT 'allocated'," +
  'client_os TEXT,' +
  'client_hostname TEXT,' +
  'verify_nonce_hash TEXT,' +
  'verify_nonce_expires_at TEXT,' +
  'issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'enrolled_at TEXT,' +
  'last_verified_at TEXT,' +
  'last_handshake_at TEXT,' +
  'revoked_at TEXT' +
  ');' +
  'CREATE TABLE IF NOT EXISTS enrollment_tokens (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'token_hash TEXT NOT NULL UNIQUE,' +
  'user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,' +
  'peer_id INTEGER NOT NULL REFERENCES wireguard_peers(id) ON DELETE CASCADE,' +
  "peer_type TEXT NOT NULL CHECK(peer_type IN ('attacker','target'))," +
  'expires_at TEXT NOT NULL,' +
  'used_at TEXT,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +
  'CREATE TABLE IF NOT EXISTS connectivity_checks (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'peer_id INTEGER REFERENCES wireguard_peers(id) ON DELETE CASCADE,' +
  'challenge_id INTEGER,' +
  'check_type TEXT NOT NULL,' +
  "status TEXT NOT NULL CHECK(status IN ('pass','fail'))," +
  'observed_ip TEXT,' +
  'latency_ms INTEGER,' +
  'detail_code TEXT,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +
  'CREATE TABLE IF NOT EXISTS challenges (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'owner_user_id INTEGER NOT NULL REFERENCES users(id),' +
  'target_peer_id INTEGER REFERENCES wireguard_peers(id),' +
  'title TEXT NOT NULL,' +
  'target_ip TEXT NOT NULL,' +
  'target_ports TEXT NOT NULL,' +
  'services TEXT NOT NULL,' +
  'description TEXT NOT NULL,' +
  'initial_hint TEXT NOT NULL,' +
  "learning_objective TEXT NOT NULL DEFAULT ''," +
  "initial_foothold_summary TEXT NOT NULL DEFAULT ''," +
  "enumeration_clue TEXT NOT NULL DEFAULT ''," +
  "pe_technique TEXT NOT NULL DEFAULT ''," +
  "intended_path TEXT NOT NULL DEFAULT ''," +
  "flag_location_summary TEXT NOT NULL DEFAULT ''," +
  'flag_hash TEXT NOT NULL,' +
  'flag_encrypted TEXT NOT NULL,' +
  'recovery_encrypted TEXT,' +
  'reset_encrypted TEXT,' +
  "status TEXT NOT NULL CHECK(status IN ('draft','pending_review','approved','locked')) DEFAULT 'draft'," +
  "validation_status TEXT NOT NULL DEFAULT 'not_run'," +
  "health_status TEXT NOT NULL DEFAULT 'unknown'," +
  'health_detail TEXT,' +
  'reviewer_note TEXT,' +
  'last_reachable_at TEXT,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'approved_at TEXT,' +
  'published_at TEXT,' +
  'locked_at TEXT' +
  ');' +
  'CREATE TABLE IF NOT EXISTS submissions (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'user_id INTEGER NOT NULL REFERENCES users(id),' +
  'challenge_id INTEGER NOT NULL REFERENCES challenges(id),' +
  'submitted_flag_hash TEXT NOT NULL,' +
  'correct INTEGER NOT NULL DEFAULT 0,' +
  'first_blood INTEGER NOT NULL DEFAULT 0,' +
  'submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +
  'CREATE TABLE IF NOT EXISTS lab_issue_reports (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,' +
  'reporter_id INTEGER NOT NULL REFERENCES users(id),' +
  'reason TEXT NOT NULL,' +
  "status TEXT NOT NULL CHECK(status IN ('open','confirmed','resolved','dismissed')) DEFAULT 'open'," +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'resolved_at TEXT' +
  ');' +
  'CREATE TABLE IF NOT EXISTS audit_logs (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'user_id INTEGER REFERENCES users(id),' +
  'action TEXT NOT NULL,' +
  'target_type TEXT,' +
  'target_id TEXT,' +
  'ip TEXT,' +
  'details TEXT,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +
  'CREATE TABLE IF NOT EXISTS event_settings (' +
  'key TEXT PRIMARY KEY,' +
  'value TEXT NOT NULL,' +
  'updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');'
);

function tableColumns(table) {
  if (!/^[A-Za-z0-9_]+$/.test(table)) throw new Error('Invalid table name');
  return new Set(db.prepare('PRAGMA table_info(' + table + ')').all().map((row) => row.name));
}
function addColumn(table, name, definition) {
  if (!tableColumns(table).has(name)) db.exec('ALTER TABLE ' + table + ' ADD COLUMN ' + name + ' ' + definition);
}
addColumn('challenges', 'target_peer_id', 'INTEGER REFERENCES wireguard_peers(id)');
addColumn('challenges', 'learning_objective', "TEXT NOT NULL DEFAULT ''");
addColumn('challenges', 'initial_foothold_summary', "TEXT NOT NULL DEFAULT ''");
addColumn('challenges', 'enumeration_clue', "TEXT NOT NULL DEFAULT ''");
addColumn('challenges', 'pe_technique', "TEXT NOT NULL DEFAULT ''");
addColumn('challenges', 'intended_path', "TEXT NOT NULL DEFAULT ''");
addColumn('challenges', 'flag_location_summary', "TEXT NOT NULL DEFAULT ''");
addColumn('challenges', 'validation_status', "TEXT NOT NULL DEFAULT 'not_run'");
addColumn('challenges', 'health_status', "TEXT NOT NULL DEFAULT 'unknown'");
addColumn('challenges', 'health_detail', 'TEXT');
addColumn('challenges', 'last_reachable_at', 'TEXT');
addColumn('challenges', 'published_at', 'TEXT');
addColumn('challenges', 'locked_at', 'TEXT');
addColumn('wireguard_peers', 'last_handshake_at', 'TEXT');
addColumn('users', 'is_visitor', 'INTEGER NOT NULL DEFAULT 0');
addColumn('users', 'is_test', 'INTEGER NOT NULL DEFAULT 0');
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS active_peer_user_type ON wireguard_peers(user_id, peer_type) WHERE status <> 'revoked';");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS active_peer_ip ON wireguard_peers(assigned_ip) WHERE status <> 'revoked';");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS active_peer_public_key ON wireguard_peers(public_key) WHERE public_key IS NOT NULL AND status <> 'revoked';");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS active_enrollment_token_peer ON enrollment_tokens(peer_id) WHERE used_at IS NULL;");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS active_target_challenge ON challenges(target_peer_id) WHERE target_peer_id IS NOT NULL AND status <> 'locked';");
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS one_correct_solve ON submissions(user_id, challenge_id) WHERE correct = 1;');
db.exec('CREATE INDEX IF NOT EXISTS submissions_challenge_idx ON submissions(challenge_id, correct, submitted_at);');
db.exec('CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at);');

function nowIso() { return new Date().toISOString(); }
function esc(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}
function nl2br(value) { return esc(value).replace(/\r?\n/g, '<br>'); }
function sameHash(a, b) {
  const left = Buffer.from(String(a ?? ''));
  const right = Buffer.from(String(b ?? ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function clientIp(req) { return String(req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, ''); }
function input(req, key) { return String(req.body?.[key] ?? '').trim(); }
function asArray(value) { return Array.isArray(value) ? value : value == null ? [] : [value]; }
function formatWhen(value) {
  return new Intl.DateTimeFormat('id-ID', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Jakarta' }).format(new Date(value)) + ' WIB';
}
function withTransaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  }
}
function setting(key) { return db.prepare('SELECT value FROM event_settings WHERE key=?').get(key)?.value || ''; }
function setSetting(key, value) {
  db.prepare('INSERT INTO event_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at').run(key, value, nowIso());
}
function currentPhase() {
  const forced = setting('forced_phase');
  const scheduled = eventPhase(Date.now(), cfg.buildDeadlineAt, cfg.portalOpenAt, cfg.gameLockAt);
  if (scheduled === 'LOCKED' || forced === 'LOCKED') return 'LOCKED';
  if (forced === 'LIVE') return 'LIVE';
  return scheduled;
}
function syncLockState() {
  if (currentPhase() !== 'LOCKED') return;
  db.prepare("UPDATE challenges SET status='locked', locked_at=COALESCE(locked_at,?), updated_at=? WHERE status <> 'locked'").run(nowIso(), nowIso());
}
function writeAudit(req, userId, action, targetType = null, targetId = null, details = null) {
  db.prepare('INSERT INTO audit_logs(user_id,action,target_type,target_id,ip,details) VALUES(?,?,?,?,?,?)').run(
    userId || null, action, targetType, targetId == null ? null : String(targetId), clientIp(req), details ? JSON.stringify(details) : null,
  );
}
function logEvent(req, action, targetType = null, targetId = null, details = null) {
  writeAudit(req, req.user?.id || null, action, targetType, targetId, details);
}
function logEventForUser(req, userId, action, targetType = null, targetId = null, details = null) {
  writeAudit(req, userId, action, targetType, targetId, details);
}

function setSessionCookie(res, token, maxAge) {
  const parts = ['mbc_las_sid=' + encodeURIComponent(token), 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=' + Math.floor(maxAge / 1000)];
  if (cfg.production) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearSessionCookie(res) {
  const parts = ['mbc_las_sid=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (cfg.production) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function cookieValue(req, name) {
  const raw = req.headers.cookie?.split(';').map((value) => value.trim()).find((value) => value.startsWith(name + '='));
  if (!raw) return '';
  try { return decodeURIComponent(raw.slice(name.length + 1)); } catch { return ''; }
}
function createSession(req, userId) {
  const token = randomToken(32);
  const csrf = randomToken(24);
  db.prepare('INSERT INTO sessions(token_hash,user_id,csrf_token,ip,user_agent,expires_at) VALUES(?,?,?,?,?,?)').run(
    sha256(token), userId, csrf, clientIp(req), String(req.get('user-agent') || '').slice(0, 300), new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
  );
  setSessionCookie(req.res, token, 12 * 60 * 60 * 1000);
  return csrf;
}
function clearSession(req) {
  const token = cookieValue(req, 'mbc_las_sid');
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(token));
  clearSessionCookie(req.res);
}
function attachSession(req, res, next) {
  req.session = null;
  req.user = null;
  const token = cookieValue(req, 'mbc_las_sid');
  if (token) {
    const row = db.prepare('SELECT s.*,u.caas_id,u.role,u.active,u.is_visitor,u.is_test FROM sessions s LEFT JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(sha256(token), nowIso());
    if (row && (row.user_id == null || row.active)) {
      req.session = row;
      if (row.user_id != null) req.user = { id: row.user_id, caasId: row.caas_id, role: row.role, isVisitor: Boolean(row.is_visitor), isTest: Boolean(row.is_test) };
    }
  }
  next();
}
function ensureSession(req) {
  if (req.session) return req.session.csrf_token;
  const token = randomToken(32);
  const csrf = randomToken(24);
  db.prepare('INSERT INTO sessions(token_hash,user_id,csrf_token,ip,user_agent,expires_at) VALUES(?,?,?,?,?,?)').run(
    sha256(token), null, csrf, clientIp(req), String(req.get('user-agent') || '').slice(0, 300), new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  );
  setSessionCookie(req.res, token, 60 * 60 * 1000);
  req.session = { token_hash: sha256(token), csrf_token: csrf, user_id: null };
  return csrf;
}
function csrfField(req) { return '<input type="hidden" name="_csrf" value="' + esc(ensureSession(req)) + '">'; }
function requireCsrf(req, res, next) {
  if (!req.session?.csrf_token || !sameHash(req.session.csrf_token, req.body?._csrf || '')) {
    return res.status(403).send(renderPage('Request rejected', notice('Request rejected', 'Form token missing or expired. Refresh the page and try again.', 'bad'), req));
  }
  next();
}
function confirmationMatches(req, expected) {
  return sameHash(input(req, 'confirmation').toUpperCase(), expected);
}
function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}
function requireWriteAccess(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.isVisitor) return res.status(403).send(renderPage('Read-only account', notice('Read-only account', 'This visitor account can view the portal but cannot change event data.', 'info'), req));
  next();
}
function requireCurrentPassword(req, res, next) {
  const password = String(req.body?.current_password || '');
  const user = db.prepare('SELECT password_hash FROM users WHERE id=? AND active=1').get(req.user.id);
  if (!password || !user || !verifyPassword(password, user.password_hash)) {
    return res.status(403).send(renderPage('Confirmation required', notice('Confirmation required', 'The account password is incorrect.', 'bad'), req));
  }
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(404).send(renderPage('Not found', notice('Not found', 'This resource does not exist.', 'bad'), req));
  if (!isInCidr(clientIp(req), cfg.wgCidr) && !isInCidr(clientIp(req), cfg.tailscaleCidr)) return res.status(403).send(renderPage('Private route', notice('Private route', 'Admin access is available only from the WireGuard or Tailscale network.', 'bad'), req));
  next();
}
function phaseError(req, title, text) { return renderPage(title, notice(title, text, 'info'), req); }
function requireBuilderWrite(req, res, next) {
  if (currentPhase() === 'LOCKED' || !isBefore(Date.now(), cfg.submissionDeadlineAt)) return res.status(403).send(phaseError(req, 'Builder closed', 'Portal editing closed at ' + formatWhen(cfg.submissionDeadlineAt) + '.'));
  const challenge = ownChallenge(req.user.id);
  if (challenge?.status === 'approved') return res.status(403).send(phaseError(req, 'Approved lab', 'Approved labs are read-only. Ask a mentor to return the lab before editing.'));
  next();
}
function requireLive(req, res, next) {
  if (currentPhase() !== 'LIVE') return res.status(403).send(phaseError(req, currentPhase() === 'LOCKED' ? 'Game locked' : 'Lab Space closed', currentPhase() === 'LOCKED' ? 'Flag submission and leaderboard are frozen.' : 'Lab Space opens at ' + formatWhen(cfg.portalOpenAt) + '.'));
  next();
}

function notice(title, body, kind = 'info') {
  return '<section class="notice ' + esc(kind) + '"><span class="kicker">STATUS</span><h1>' + esc(title) + '</h1><p>' + esc(body) + '</p></section>';
}
function statusBadge(value) {
  const safe = String(value || 'unknown').replace(/_/g, ' ');
  return '<span class="status ' + esc(value || 'unknown') + '">' + esc(safe) + '</span>';
}
function commandBlock(value) {
  return '<pre class="command"><code>' + esc(value) + '</code><button type="button" class="copy-button" data-copy="' + esc(value) + '">COPY</button></pre>';
}
function formButton(label, kind = 'primary') { return '<button class="button ' + kind + '" type="submit">' + esc(label) + '</button>'; }
function confirmationField(label, expected) {
  return '<label class="confirm-field">' + esc(label) + '<input name="confirmation" required maxlength="20" autocomplete="off" placeholder="Type ' + esc(expected) + '"></label>';
}
function renderPage(title, content, req) {
  const user = req.user;
  const documentLanguage = 'en';
  const currentPath = req.path;
  const navLink = (href, label, active) => '<a' + (active ? ' class="is-active" aria-current="page"' : '') + ' href="' + href + '">' + label + '</a>';
  const nav = user
    ? navLink('/setup', 'Lab Config', currentPath.startsWith('/setup')) + navLink('/learn', 'Learn', currentPath.startsWith('/learn')) + navLink('/build', 'Build', currentPath.startsWith('/build')) + navLink('/lab-space', 'Lab Space', currentPath.startsWith('/lab-space')) + navLink('/scoreboard', 'Scoreboard', currentPath.startsWith('/scoreboard')) +
      (user.role === 'admin' ? navLink('/admin', 'Admin', currentPath.startsWith('/admin')) : '') +
      '<span class="account-chip"><span>ACCOUNT</span><strong>' + esc(req.user.caasId) + '</strong></span><form class="nav-form" method="post" action="/logout">' + csrfField(req) + '<button type="submit">Sign out</button></form>'
    : navLink('/scoreboard', 'Scoreboard', currentPath.startsWith('/scoreboard')) + '<a class="nav-cta' + (currentPath === '/login' ? ' is-active' : '') + '" href="/login"' + (currentPath === '/login' ? ' aria-current="page"' : '') + '>Sign in</a>';
  return '<!doctype html><html lang="' + documentLanguage + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="MBC LAS Week 4 portal"><title>' +
    esc(title) + ' · MBC LAS W4</title><link rel="icon" href="/logo.png"><link rel="stylesheet" href="/styles.css?v=20260830-learn-v2"><script src="/app.js?v=20260830-learn-v2" defer></script></head><body><a class="skip-link" href="#main-content">SKIP TO CONTENT</a><header class="site-header"><a class="brand" href="/"><img src="/logo.png" alt="MBC Laboratory"><span>LAS / WEEK 04</span></a><nav aria-label="Primary navigation">' +
    nav + '</nav></header><main class="shell" id="main-content">' + content + '</main><footer class="site-footer"><span>MBC LABORATORY · CYBER SECURITY DIVISION</span><span>AUTHORIZED TRAINING NETWORK · ' + esc(cfg.wgCidr) + '</span></footer></body></html>';
}
function pageHead(kicker, title, subtitle = '') {
  return '<section class="page-head"><div><span class="kicker">' + esc(kicker) + '</span><h1>' + esc(title) + '</h1>' + (subtitle ? '<p class="muted">' + esc(subtitle) + '</p>' : '') + '</div></section>';
}
function stat(label, value, note = '') {
  return '<div class="stat"><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong>' + (note ? '<small>' + esc(note) + '</small>' : '') + '</div>';
}

function peerRange(type) {
  return type === 'attacker' ? [cfg.attackerStart, cfg.attackerEnd] : [cfg.targetStart, cfg.targetEnd];
}
function validPeerType(type) { return type === 'attacker' || type === 'target'; }
function requirePeerTypeParam(req, res, next) {
  if (!validPeerType(req.params.type)) return res.status(404).type('text/plain').send('NOT_FOUND');
  next();
}
function peerForUser(userId, type) {
  return db.prepare("SELECT * FROM wireguard_peers WHERE user_id=? AND peer_type=? AND status<>'revoked' ORDER BY id DESC LIMIT 1").get(userId, type);
}
function peerForId(id) { return db.prepare('SELECT * FROM wireguard_peers WHERE id=?').get(Number(id)); }
function allocatePeer(userId, type) {
  return withTransaction(() => {
    const existing = peerForUser(userId, type);
    if (existing) return existing;
    const [startText, endText] = peerRange(type);
    const pool = parsePeerPool(type, startText, endText);
    const used = db.prepare("SELECT assigned_ip FROM wireguard_peers WHERE status<>'revoked'").all().map((row) => row.assigned_ip);
    const ip = allocatePeerAddress(pool, used);
    const result = db.prepare("INSERT INTO wireguard_peers(user_id,peer_type,assigned_ip,status) VALUES(?,?,?,'allocated')").run(userId, type, ip);
    return peerForId(result.lastInsertRowid);
  });
}
function issueEnrollmentToken(userId, type) {
  const peer = allocatePeer(userId, type);
  db.prepare('UPDATE enrollment_tokens SET used_at=COALESCE(used_at,?) WHERE peer_id=? AND used_at IS NULL').run(nowIso(), peer.id);
  const token = randomToken(16);
  db.prepare('INSERT INTO enrollment_tokens(token_hash,user_id,peer_id,peer_type,expires_at) VALUES(?,?,?,?,?)').run(
    sha256(token), userId, peer.id, type, enrollmentExpiry(),
  );
  return { token, peer };
}
function helperAction(action, peer, publicKey = peer.public_key) {
  if (!['add', 'replace', 'revoke', 'status'].includes(action)) return { ok: false, code: 'INVALID_HELPER_ACTION' };
  if (!peer || !validPeerType(peer.peer_type)) return { ok: false, code: 'INVALID_PEER_TYPE' };
  if (!ipv4InRange(peer.assigned_ip, ...peerRange(peer.peer_type))) return { ok: false, code: 'INVALID_ASSIGNED_IP' };
  if (action !== 'status' && !validWireguardPublicKey(publicKey || '')) return { ok: false, code: 'INVALID_PUBLIC_KEY' };
  if (cfg.wgHelperDryRun) return { ok: true, simulated: true };
  if (!fs.existsSync(cfg.wgHelperPath)) {
    if (cfg.production) return { ok: false, code: 'HELPER_UNAVAILABLE' };
    return { ok: true, simulated: true };
  }
  const helperArgs = [action, peer.peer_type, peer.assigned_ip];
  if (action !== 'status') helperArgs.push(publicKey);
  const command = cfg.production ? cfg.wgSudoPath : cfg.wgHelperPath;
  const args = cfg.production ? ['-n', cfg.wgHelperPath, ...helperArgs] : helperArgs;
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: 8000,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) return { ok: false, code: 'HELPER_FAILED' };
  return { ok: true, output: String(result.stdout || '') };
}
function peerHandshake(peer) {
  if (!peer) return { known: false, stale: true, source: 'NO_PEER' };
  if (cfg.skipNetworkChecks && peer.last_verified_at) {
    return { known: true, stale: handshakeIsStale(peer.last_verified_at, Date.now(), cfg.healthHandshakeMaxAgeMs), source: 'LAST_VERIFIED_DEV_APPROXIMATION', timestamp: peer.last_verified_at };
  }
  if (!peer.public_key) return { known: false, stale: true, source: 'NO_PUBLIC_KEY' };
  const result = helperAction('status', peer);
  if (!result.ok || result.simulated) return { known: false, stale: true, source: result.code || 'HELPER_UNAVAILABLE' };
  const line = String(result.output || '').split(/\r?\n/).map((value) => value.split('\t')).find((fields) => fields[0] === peer.public_key);
  const epoch = line ? Number(line[4]) : 0;
  if (!Number.isFinite(epoch) || epoch <= 0) return { known: true, stale: true, source: 'NO_HANDSHAKE' };
  const timestamp = new Date(epoch * 1000).toISOString();
  return { known: true, stale: handshakeIsStale(timestamp, Date.now(), cfg.healthHandshakeMaxAgeMs), source: 'WIREGUARD_DUMP', timestamp };
}
function setupCommand(token) {
  const tls = cfg.production ? "--proto '=https' --tlsv1.2 " : '';
  return 'curl -fsSL ' + tls + cfg.origin + '/s/' + encodeURIComponent(token) + ' | sudo bash';
}
function installerBootstrap(token) {
  const tls = cfg.production ? "--proto '=https' --tlsv1.2 " : '';
  return [
    '#!/usr/bin/env bash',
    'set -Eeuo pipefail',
    'printf "[INFO] Downloading the official MBC LAS Week 4 WireGuard installer.\\n"',
    'curl -fsSL ' + tls + cfg.origin + '/setup/linux.sh | bash -s -- ' + shellQuote(token),
    '',
  ].join('\n');
}
function setupPage(req, type, token = '', error = '') {
  const peer = peerForUser(req.user.id, type);
  const readOnly = Boolean(req.user?.isVisitor);
  const title = type === 'attacker' ? 'Setup attacker' : 'Setup target';
  const osText = type === 'attacker' ? 'Kali Linux VM or Kali Linux WSL' : 'Ubuntu target VM or VPS';
  const initialStatus = peer?.status || 'not_started';
  let body = pageHead('SETUP / ' + type.toUpperCase(), title, osText);
  body += '<div class="notice compact" data-setup-status data-peer-type="' + esc(type) + '" data-status="' + esc(initialStatus) + '"><strong data-status-value>' + (readOnly ? 'READ-ONLY' : peer?.status === 'connected' ? 'CONNECTED' : 'NOT CONNECTED') + '</strong><p>' +
    (readOnly ? 'Visitor accounts can view setup guidance but cannot create or change peers.' : 'One ' + type + ' peer is assigned to this account.') + '</p><small>IP: <code data-status-ip>' + esc(peer?.assigned_ip || 'NOT ASSIGNED') + '</code> · Last verified: <span data-status-verified>' + esc(peer?.last_verified_at || 'NOT VERIFIED') + '</span></small></div>';
  if (error) body += '<div class="flash bad">' + esc(error) + '</div>';
  if (!readOnly) {
    body += '<section class="step-panel"><div class="step-number">01</div><div><h2>Generate setup command</h2><p class="muted">The token expires in 10 minutes and can be used only once.</p><form method="post" action="/api/setup/' + type + '/token">' + csrfField(req) + formButton('GENERATE COMMAND') + '</form></div></section>';
    if (token) {
      body += '<section class="step-panel"><div class="step-number">02</div><div><h2>Run in ' + esc(type === 'attacker' ? 'Kali' : 'Ubuntu') + '</h2>' + commandBlock(setupCommand(token)) +
        '<p class="muted">The private key is created on your local machine. Never share command output or the configuration file.</p></div></section>';
    } else {
      body += '<section class="step-panel is-locked"><div class="step-number">02</div><div><h2>Run setup command</h2><p class="muted">Generate the command in step 01 to unlock the one-time installer.</p></div></section>';
    }
    body += '<section class="step-panel"><div class="step-number">03</div><div><h2>Verify</h2><p class="muted">Status updates automatically after the script completes internal verification.</p><a class="button ghost" href="/setup/' + type + '">CHECK STATUS</a></div></section>';
    if (peer) {
      body += '<section class="step-panel"><div class="step-number">04</div><div><h2>Peer controls</h2><p class="muted">Revoke or regenerate to disconnect the old peer. Confirm with your account password.</p>' +
        '<form method="post" action="/api/setup/' + type + '/revoke" class="inline-form"><input name="current_password" type="password" autocomplete="current-password" placeholder="Account password" required>' + csrfField(req) + formButton('REVOKE PEER', 'danger') + '</form>' +
        '<form method="post" action="/api/setup/' + type + '/regenerate" class="inline-form"><input name="current_password" type="password" autocomplete="current-password" placeholder="Account password" required>' + csrfField(req) + formButton('REGENERATE PEER', 'ghost') + '</form></div></section>';
    }
  } else if (readOnly) {
    body += '<section class="callout"><strong>VIEW ONLY</strong><p>Setup commands and peer controls are disabled for this account.</p></section>';
  }
  body += '<a class="button back" href="/setup">← BACK TO SETUP</a>';
  return renderPage(title, body, req);
}

function shellQuote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }
function installerScript() {
  const api = shellQuote(cfg.origin + '/api/enroll');
  const interfaceName = shellQuote(cfg.wgInterface);
  const allowedIps = String(cfg.wgCidr);
  return [
    '#!/usr/bin/env bash',
    'set -Eeuo pipefail',
    'umask 077',
    'info() { printf "[INFO] %s\\n" "$1"; }',
    'info "MBC LAS Week 4 WireGuard setup started."',
    'TOKEN="${1:-}"',
    'info "Validating the one-time enrollment token."',
    'if [[ -z "$TOKEN" ]]; then echo "TOKEN_INVALID" >&2; exit 10; fi',
    'if [[ "${EUID:-0}" -ne 0 ]]; then echo "RUN_AS_ROOT" >&2; exit 11; fi',
    'info "Checking supported operating system and package manager."',
    'if [[ ! -r /etc/os-release ]]; then echo "UNSUPPORTED_OS" >&2; exit 12; fi',
    '. /etc/os-release',
    'case "${ID:-}" in kali|ubuntu) ;; *) echo "UNSUPPORTED_OS: use Kali Linux or Ubuntu" >&2; exit 12 ;; esac',
    'command -v apt-get >/dev/null 2>&1 || { echo "UNSUPPORTED_OS" >&2; exit 12; }',
    'export DEBIAN_FRONTEND=noninteractive',
    'info "Installing or checking WireGuard tools and curl."',
    'apt-get update -qq || { echo "INSTALL_FAILED" >&2; exit 13; }',
    'apt-get install -y -qq wireguard wireguard-tools curl || { echo "INSTALL_FAILED" >&2; exit 13; }',
    'command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 || { echo "INSTALL_FAILED" >&2; exit 13; }',
    'CONFIG_DIR=/etc/wireguard',
    'INTERFACE=' + interfaceName,
    'CONFIG_PATH="$CONFIG_DIR/$INTERFACE.conf"',
    'info "Preparing the local WireGuard configuration directory."',
    'install -d -m 0700 "$CONFIG_DIR"',
    'info "Generating the private key locally; it will not be uploaded."',
    'PRIVATE_KEY="$(wg genkey)" || { echo "KEYGEN_FAILED" >&2; exit 14; }',
    'PUBLIC_KEY="$(printf "%s" "$PRIVATE_KEY" | wg pubkey)" || { echo "KEYGEN_FAILED" >&2; exit 14; }',
    'CLIENT_OS="linux"',
    'CLIENT_HOSTNAME="$(hostname 2>/dev/null || printf unknown)"',
    'CLIENT_HOSTNAME="${CLIENT_HOSTNAME//[^A-Za-z0-9_.-]/}"',
    'CLIENT_HOSTNAME="${CLIENT_HOSTNAME:0:64}"',
    'API_URL=' + api,
    'CURL_TLS=()',
    'if [[ "$API_URL" == https://* ]]; then CURL_TLS=(--proto \'=https\' --tlsv1.2); fi',
    'info "Registering this peer with the MBC portal using the one-time token."',
    'RESPONSE="$(curl "${CURL_TLS[@]}" --fail --silent --show-error --max-time 20 -X POST "$API_URL" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "token=$TOKEN" --data-urlencode "public_key=$PUBLIC_KEY" --data-urlencode "client_os=$CLIENT_OS" --data-urlencode "hostname=$CLIENT_HOSTNAME")" || { echo "ENROLL_FAILED" >&2; exit 15; }',
    'get_value() { printf "%s\\n" "$RESPONSE" | sed -n "s/^$1=//p" | head -n 1; }',
    '[[ "$(get_value MBC_STATUS)" == "OK" ]] || { echo "ENROLL_FAILED" >&2; exit 16; }',
    'PEER_TYPE="$(get_value MBC_PEER_TYPE)"',
    'ASSIGNED_IP="$(get_value MBC_ASSIGNED_IP)"',
    'SERVER_PUBLIC_KEY="$(get_value MBC_SERVER_PUBLIC_KEY)"',
    'ENDPOINT="$(get_value MBC_ENDPOINT)"',
    'HUB_IP=' + shellQuote(cfg.wgHubIp),
    'VERIFY_URL="$(get_value MBC_VERIFY_URL)"',
    'VERIFY_NONCE="$(get_value MBC_VERIFY_NONCE)"',
    '[[ "$PEER_TYPE" == attacker || "$PEER_TYPE" == target ]] || { echo "ENROLL_FAILED" >&2; exit 16; }',
    '[[ "$ASSIGNED_IP" =~ ^([0-9]{1,3}\\.){3}[0-9]{1,3}$ ]] || { echo "IP_MISMATCH" >&2; exit 17; }',
    '[[ "$SERVER_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || { echo "ENROLL_FAILED" >&2; exit 16; }',
    '[[ "$ENDPOINT" =~ ^[^[:space:]]+:[0-9]{1,5}$ ]] || { echo "ENROLL_FAILED" >&2; exit 16; }',
    '[[ "$VERIFY_URL" =~ ^https?://[^[:space:]]+$ ]] || { echo "VERIFY_FAILED" >&2; exit 19; }',
    '[[ -n "$VERIFY_NONCE" ]] || { echo "VERIFY_FAILED" >&2; exit 19; }',
    'VERIFY_TLS=()',
    'VERIFY_RESOLVE=()',
    'info "Enrollment accepted; preparing the assigned peer settings."',
    'VERIFY_AUTHORITY="${VERIFY_URL#*://}"',
    'VERIFY_AUTHORITY="${VERIFY_AUTHORITY%%/*}"',
    'VERIFY_HOST="${VERIFY_AUTHORITY%%:*}"',
    'VERIFY_PORT=80',
    'if [[ "$VERIFY_URL" == https://* ]]; then VERIFY_TLS=(--proto \'=https\' --tlsv1.2); VERIFY_PORT=443; fi',
    '[[ -n "$VERIFY_HOST" ]] || { echo "VERIFY_FAILED" >&2; exit 19; }',
    'VERIFY_RESOLVE=(--resolve "$VERIFY_HOST:$VERIFY_PORT:' + cfg.wgHubIp + '")',
    'TMP_PATH="$(mktemp "$CONFIG_DIR/.$INTERFACE.XXXXXX")" || { echo "CONFIG_WRITE_FAILED" >&2; exit 18; }',
    'cleanup() { rm -f "$TMP_PATH"; unset PRIVATE_KEY TOKEN RESPONSE VERIFY_NONCE; }',
    'trap cleanup EXIT',
    'chmod 0600 "$TMP_PATH"',
    'cat > "$TMP_PATH" <<EOF',
    '[Interface]',
    'PrivateKey = $PRIVATE_KEY',
    'Address = $ASSIGNED_IP/32',
    '',
    '[Peer]',
    'PublicKey = $SERVER_PUBLIC_KEY',
    'Endpoint = $ENDPOINT',
    'AllowedIPs = ' + allowedIps,
    'PersistentKeepalive = 25',
    'EOF',
    'info "Installing the local WireGuard configuration with mode 0600."',
    'mv -f "$TMP_PATH" "$CONFIG_PATH"',
    'info "Activating the WireGuard interface: $INTERFACE."',
    'WG_UP_OK=0',
    'if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then',
    '  if systemctl enable "wg-quick@$INTERFACE" >/dev/null 2>&1 && systemctl restart "wg-quick@$INTERFACE"; then',
    '    WG_UP_OK=1',
    '  else',
    '    info "systemd activation failed; trying direct wg-quick fallback."',
    '    systemctl stop "wg-quick@$INTERFACE" >/dev/null 2>&1 || true',
    '  fi',
    'fi',
    'if [[ "$WG_UP_OK" -ne 1 ]]; then',
    '  wg-quick down "$CONFIG_PATH" >/dev/null 2>&1 || true',
    '  wg-quick up "$CONFIG_PATH" || { echo "WG_UP_FAILED" >&2; exit 18; }',
    'fi',
    'command -v ip >/dev/null 2>&1 && ip -4 addr show dev "$INTERFACE" | grep -Eq "inet[[:space:]]+$ASSIGNED_IP/" || { echo "IP_MISMATCH" >&2; exit 17; }',
    'info "Verifying the WireGuard tunnel through the private MBC endpoint."',
    'curl "${VERIFY_TLS[@]}" "${VERIFY_RESOLVE[@]}" --fail --silent --show-error --max-time 10 -X POST "$VERIFY_URL" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "nonce=$VERIFY_NONCE" --data-urlencode "client_os=$CLIENT_OS" >/dev/null || { echo "VERIFY_FAILED" >&2; exit 19; }',
    'info "Running final local tunnel checks."',
    "if wg show \"$INTERFACE\" latest-handshakes 2>/dev/null | awk '$2 > 0 { found=1 } END { exit(found ? 0 : 1) }'; then",
    '  info "WireGuard handshake confirmed."',
    'else',
    '  info "Handshake timestamp is not available yet; internal portal verification already passed."',
    'fi',
    'if command -v ping >/dev/null 2>&1 && ping -c 1 -W 2 "$HUB_IP" >/dev/null 2>&1; then',
    '  info "WireGuard gateway $HUB_IP is reachable."',
    'else',
    '  info "Gateway ping is unavailable; the encrypted tunnel remains verified by the portal."',
    'fi',
    'info "WireGuard setup and verification completed successfully."',
    'echo "CONNECTED: WireGuard peer $INTERFACE is active at $ASSIGNED_IP"',
  ].join('\n') + '\n';
}

async function probeTargetIp(ip) {
  if (cfg.skipNetworkChecks) return { ok: true, skipped: true, detail: 'network checks skipped in development' };
  const args = process.platform === 'win32' ? ['-n', '1', '-w', '1800', ip] : ['-c', '1', '-W', '2', ip];
  return new Promise((resolve) => {
    const child = spawn('ping', args, { stdio: 'ignore', windowsHide: true });
    const timer = setTimeout(() => { child.kill('SIGKILL'); resolve({ ok: false, detail: 'TARGET_UNREACHABLE' }); }, 4000);
    child.on('error', () => { clearTimeout(timer); resolve({ ok: false, detail: 'PROBE_UNAVAILABLE' }); });
    child.on('exit', (code) => { clearTimeout(timer); resolve({ ok: code === 0, detail: code === 0 ? 'TARGET_REACHABLE' : 'TARGET_UNREACHABLE' }); });
  });
}

async function recordTargetHealth(challenge, peer, source = 'manual_recheck') {
  if (!challenge || !peer || peer.status === 'revoked') return { checked: false, throttled: false, probe: { ok: false, detail: 'TARGET_PEER_UNAVAILABLE' }, handshake: { known: false, stale: true, source: 'NO_PEER' }, decision: { status: challenge?.health_status || 'unknown', reason: 'TARGET_PEER_UNAVAILABLE' } };
  const latest = db.prepare("SELECT * FROM connectivity_checks WHERE challenge_id=? AND check_type='target_reachability' ORDER BY id DESC LIMIT 1").get(challenge.id);
  const lastStamp = latest ? new Date(latest.created_at).getTime() : null;
  if (lastStamp !== null && Number.isFinite(lastStamp) && Date.now() - lastStamp < cfg.healthProbeIntervalMs) {
    return { checked: false, throttled: true, probe: { ok: latest.status === 'pass', detail: 'PROBE_THROTTLED' }, handshake: peerHandshake(peer), decision: { status: challenge.health_status, reason: 'PROBE_THROTTLED' }, latest };
  }
  const handshake = peerHandshake(peer);
  const probe = await probeTargetIp(challenge.target_ip);
  const checkedAt = nowIso();
  db.prepare('INSERT INTO connectivity_checks(peer_id,challenge_id,check_type,status,observed_ip,detail_code,created_at) VALUES(?,?,?,?,?,?,?)').run(peer.id, challenge.id, 'target_reachability', probe.ok ? 'pass' : 'fail', challenge.target_ip, probe.detail, checkedAt);
  if (handshake.timestamp) db.prepare('UPDATE wireguard_peers SET last_handshake_at=? WHERE id=?').run(handshake.timestamp, peer.id);
  const checks = db.prepare("SELECT check_type,status,created_at FROM connectivity_checks WHERE challenge_id=? AND check_type='target_reachability' ORDER BY created_at DESC LIMIT 12").all(challenge.id);
  const decision = challenge.health_status === 'disabled'
    ? { status: 'disabled', reason: 'ADMIN_DISABLED' }
    : probe.ok
      ? { status: 'healthy', reason: 'TARGET_REACHABLE' }
      : !handshake.known
        ? { status: challenge.health_status, reason: 'HANDSHAKE_UNAVAILABLE' }
        : healthDecision({ currentStatus: challenge.health_status, probeOk: probe.ok, lastHandshakeAt: handshake.timestamp, checks, now: checkedAt, handshakeMaxAgeMs: cfg.healthHandshakeMaxAgeMs, requiredFailures: cfg.healthRequiredFailures, probeIntervalMs: cfg.healthProbeIntervalMs });
  const detail = decision.reason + (source ? ' via ' + source : '');
  if (decision.status !== challenge.health_status || probe.ok) {
    db.prepare('UPDATE challenges SET health_status=?,health_detail=?,last_reachable_at=CASE WHEN ? THEN ? ELSE last_reachable_at END,updated_at=? WHERE id=?').run(
      decision.status, detail, probe.ok ? 1 : 0, probe.ok ? checkedAt : null, checkedAt, challenge.id,
    );
  } else {
    db.prepare('UPDATE challenges SET health_detail=?,updated_at=? WHERE id=?').run(detail, checkedAt, challenge.id);
  }
  return { checked: true, throttled: false, probe, handshake, decision, latest: { status: probe.ok ? 'pass' : 'fail', created_at: checkedAt } };
}

function parseServices(req) {
  const ports = asArray(req.body?.service_port);
  const protocols = asArray(req.body?.service_protocol);
  const labels = asArray(req.body?.service_label);
  const notes = asArray(req.body?.service_note);
  const length = Math.max(ports.length, protocols.length, labels.length);
  const services = [];
  for (let i = 0; i < length; i += 1) services.push({
    port: String(ports[i] || '').trim(),
    protocol: String(protocols[i] || 'tcp').trim().toLowerCase(),
    label: String(labels[i] || '').trim(),
    note: String(notes[i] || '').trim(),
  });
  return services.filter((service) => service.port || service.label);
}
function parseStoredServices(value) {
  try {
    const parsed = JSON.parse(String(value || '[]'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return String(value || '').split(',').map((label) => label.trim()).filter(Boolean).map((label) => ({ port: '', protocol: 'tcp', label, note: '' }));
  }
}

const BUILDER_DEFAULTS = Object.freeze({
  learning_objective: 'Practice evidence-led enumeration and privilege escalation.',
  initial_hint: 'Start with service discovery and record each finding.',
  initial_foothold_summary: 'Use one declared service to obtain a controlled non-root foothold.',
  enumeration_clue: 'Enumerate exposed services, identities, permissions, and writable paths.',
  pe_technique: 'To be confirmed during mentor review.',
  flag_location_summary: 'Place the flag at the end of the intended path and record its location for review.',
  intended_path: 'Document the intended enumeration-to-privilege-escalation path and the evidence a solver should collect.',
});

function builderValues(req, challenge = null) {
  const postedServiceFields = ['service_port', 'service_protocol', 'service_label', 'service_note']
    .some((field) => Object.prototype.hasOwnProperty.call(req.body || {}, field));
  const postedMentorNotes = Object.prototype.hasOwnProperty.call(req.body || {}, 'mentor_notes');
  const services = postedServiceFields ? parseServices(req) : challenge ? parseStoredServices(challenge.services) : parseServices(req);
  const postedValue = (key, stored = BUILDER_DEFAULTS[key] || '') => Object.prototype.hasOwnProperty.call(req.body || {}, key) ? input(req, key) : stored;
  const intendedPath = postedMentorNotes ? input(req, 'mentor_notes') : postedValue('intended_path', challenge?.intended_path || '');
  return {
    title: postedValue('title', challenge?.title || ''),
    description: postedValue('description', challenge?.description || ''),
    learning_objective: postedValue('learning_objective', challenge?.learning_objective || BUILDER_DEFAULTS.learning_objective),
    initial_hint: postedValue('initial_hint', challenge?.initial_hint || BUILDER_DEFAULTS.initial_hint),
    initial_foothold_summary: postedValue('initial_foothold_summary', challenge?.initial_foothold_summary || BUILDER_DEFAULTS.initial_foothold_summary),
    enumeration_clue: postedValue('enumeration_clue', challenge?.enumeration_clue || BUILDER_DEFAULTS.enumeration_clue),
    pe_technique: postedValue('pe_technique', challenge?.pe_technique || BUILDER_DEFAULTS.pe_technique),
    intended_path: intendedPath,
    flag_location_summary: postedValue('flag_location_summary', challenge?.flag_location_summary || BUILDER_DEFAULTS.flag_location_summary),
    flag: postedValue('flag', challenge?.flag_encrypted ? decryptSecret(challenge.flag_encrypted, cfg.appKey) : ''),
    services,
  };
}
function validateBuilder(values, peer) {
  const errors = [];
  if (!peer || peer.peer_type !== 'target' || peer.status !== 'connected') errors.push('The target peer must be connected first.');
  if (values.title.length < 3 || values.title.length > 100) errors.push('The title must be 3-100 characters.');
  if (values.description.length < 20 || values.description.length > 1200) errors.push('The description must be 20-1200 characters.');
  if (values.learning_objective.length > 300) errors.push('The learning objective must be 300 characters or fewer.');
  if (values.initial_hint.length > 400) errors.push('The initial hint must be 400 characters or fewer.');
  if (values.initial_foothold_summary.length > 700 || values.enumeration_clue.length > 700 || values.pe_technique.length > 200 || values.flag_location_summary.length > 500) errors.push('Generated mentor metadata exceeds its storage limit.');
  if (values.intended_path.length < 10 || values.intended_path.length > 1400) errors.push('Add mentor solution/path notes in 10-1400 characters.');
  if (!validFlag(values.flag)) errors.push('The flag must use the case-sensitive MBC{...} format.');
  if (values.services.length < 3) errors.push('List at least three services.');
  const seen = new Set();
  for (const service of values.services) {
    const port = Number(service.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('Each port must be a number from 1 to 65535.');
    if (!['tcp', 'udp'].includes(service.protocol)) errors.push('Protocol must be tcp or udp.');
    if (service.label.length < 2 || service.label.length > 80) errors.push('Service labels must be 2-80 characters.');
    if (service.note.length > 160) errors.push('Service notes must be 160 characters or fewer.');
    const key = service.port + '/' + service.protocol;
    if (seen.has(key)) errors.push('Port/protocol combinations must be unique.');
    seen.add(key);
  }
  return errors;
}
function builderForm(req, values = {}, errors = [], result = null) {
  const peer = peerForUser(req.user.id, 'target');
  const services = values.services?.length ? values.services : [{ port: '', protocol: 'tcp', label: '', note: '' }, { port: '', protocol: 'tcp', label: '', note: '' }, { port: '', protocol: 'tcp', label: '', note: '' }];
  let body = pageHead('BUILD / CHALLENGE', 'Build your lab', 'Provide the essentials. Review metadata is filled with safe defaults automatically.');
  body += '<div class="builder-meta"><span>TARGET PEER</span><strong>' + esc(peer?.assigned_ip || 'NOT ASSIGNED') + '</strong>' + statusBadge(peer?.status || 'not_started') + '</div>';
  if (errors.length) body += '<div class="flash bad"><strong>Review these items:</strong><ul>' + errors.map((error) => '<li>' + esc(error) + '</li>').join('') + '</ul></div>';
  if (result) body += '<div class="flash ' + (result.ok ? 'good' : 'bad') + '"><strong>' + esc(result.title) + '</strong><ul>' + result.items.map((item) => '<li>' + esc(item) + '</li>').join('') + '</ul></div>';
  body += '<form method="post" action="/build/challenge/save" class="builder-form">' + csrfField(req) +
    '<fieldset><legend>01 / CHALLENGE</legend><label>Challenge title<input name="title" maxlength="100" required value="' + esc(values.title) + '" placeholder="The Quiet Backup"></label><label>Player-facing description<textarea name="description" maxlength="1200" required>' + esc(values.description) + '</textarea><p class="muted">Keep this text solver-facing. Do not include owner identity or the solution.</p></fieldset>' +
    '<fieldset><legend>02 / SERVICES</legend><p class="muted">Declare at least three exposed services. Port, protocol, and label are enough.</p><div class="service-list">';
  services.forEach((service) => {
    body += '<div class="service-row"><input name="service_port" inputmode="numeric" maxlength="5" required value="' + esc(service.port) + '" placeholder="22"><select name="service_protocol"><option value="tcp"' + (service.protocol === 'tcp' ? ' selected' : '') + '>TCP</option><option value="udp"' + (service.protocol === 'udp' ? ' selected' : '') + '>UDP</option></select><input name="service_label" maxlength="80" required value="' + esc(service.label) + '" placeholder="SSH"></div>';
  });
  body += '</div></fieldset>' +
    '<fieldset><legend>03 / MENTOR NOTES <span class="legend-note">MENTOR ONLY</span></legend><label>Solution / path notes<textarea name="mentor_notes" maxlength="1400" required placeholder="Example: enumerate the web service, obtain a non-root shell, then exploit the writable SUID helper to read the flag.">' + esc(values.intended_path) + '</textarea><p class="muted">One short note is enough. The portal fills the remaining review metadata and player hint automatically.</p></fieldset>' +
    '<fieldset><legend>04 / FLAG</legend><label>Flag<input name="flag" maxlength="120" required value="' + esc(values.flag) + '" placeholder="MBC{...}"></label><p class="muted">The flag is encrypted at rest and never shown to other players.</p></fieldset>' +
    '<div class="form-actions"><div class="action-group action-group-primary">' + formButton('SAVE DRAFT', 'ghost') + '<button class="button ghost" type="submit" formaction="/build/challenge/check">RUN LIGHT CHECK</button><button class="button primary" type="submit" formaction="/build/challenge/submit">SUBMIT FOR REVIEW</button></div><div class="action-group action-group-navigation"><a class="button ghost" href="/build/challenge/preview">PLAYER PREVIEW</a><a class="button back" href="/build">← BACK TO BUILD</a></div></div></form>';
  return renderPage('Build your lab', body, req);
}
function playerPreview(req, challenge, peer) {
  const services = parseStoredServices(challenge.services);
  let body = pageHead('BUILD / PLAYER PREVIEW', challenge.title, 'This preview shows only what solvers will see.');
  body += '<div class="preview-stack">';
  body += '<div class="target-banner"><span class="kicker">TARGET IP</span><strong>' + esc(peer.assigned_ip) + '</strong><span class="status ' + esc(challenge.health_status) + '">' + esc(challenge.health_status) + '</span></div>';
  body += '<section class="card"><h2>Services</h2><div class="service-table">' + services.map((service) => '<div><code>' + esc(service.port + '/' + service.protocol) + '</code><strong>' + esc(service.label) + '</strong><span>' + esc(service.note || '') + '</span></div>').join('') + '</div></section>';
  body += '<section class="card"><h2>Challenge</h2><p>' + nl2br(challenge.description) + '</p><details><summary>INITIAL HINT</summary><p>' + nl2br(challenge.initial_hint) + '</p></details></section>';
  body += '</div><div class="preview-actions"><a class="button back" href="/build/challenge">← BACK TO BUILDER</a></div>';
  return renderPage('Player preview', body, req);
}
function ownChallenge(userId) {
  return db.prepare("SELECT * FROM challenges WHERE owner_user_id=? AND status<>'locked' ORDER BY id DESC LIMIT 1").get(userId);
}
function saveChallenge(req, values) {
  const peer = peerForUser(req.user.id, 'target');
  const errors = validateBuilder(values, peer);
  if (errors.length) return { errors, peer };
  const servicesJson = JSON.stringify(values.services.map((service) => ({ port: Number(service.port), protocol: service.protocol, label: service.label, note: service.note })));
  const existing = ownChallenge(req.user.id);
  const flagEncrypted = encryptSecret(values.flag, cfg.appKey);
  if (existing) {
    db.prepare("UPDATE challenges SET target_peer_id=?,target_ip=?,target_ports=?,services=?,title=?,description=?,learning_objective=?,initial_foothold_summary=?,enumeration_clue=?,pe_technique=?,intended_path=?,flag_location_summary=?,initial_hint=?,flag_hash=?,flag_encrypted=?,status='draft',validation_status='not_run',health_status=CASE WHEN health_status='degraded' THEN health_status ELSE 'unknown' END,updated_at=? WHERE id=? AND owner_user_id=?").run(
      peer.id, peer.assigned_ip, values.services.map((service) => service.port + '/' + service.protocol).join(', '), servicesJson,
      values.title, values.description, values.learning_objective, values.initial_foothold_summary, values.enumeration_clue,
      values.pe_technique, values.intended_path, values.flag_location_summary, values.initial_hint,
      sha256(values.flag), flagEncrypted, nowIso(), existing.id, req.user.id,
    );
    return { challenge: db.prepare('SELECT * FROM challenges WHERE id=?').get(existing.id), peer };
  }
  const info = db.prepare("INSERT INTO challenges(owner_user_id,target_peer_id,title,target_ip,target_ports,services,description,initial_hint,learning_objective,initial_foothold_summary,enumeration_clue,pe_technique,intended_path,flag_location_summary,flag_hash,flag_encrypted,status,validation_status,health_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'draft','not_run','unknown')").run(
    req.user.id, peer.id, values.title, peer.assigned_ip, values.services.map((service) => service.port + '/' + service.protocol).join(', '), servicesJson,
    values.description, values.initial_hint, values.learning_objective, values.initial_foothold_summary, values.enumeration_clue,
    values.pe_technique, values.intended_path, values.flag_location_summary, sha256(values.flag), flagEncrypted,
  );
  return { challenge: db.prepare('SELECT * FROM challenges WHERE id=?').get(info.lastInsertRowid), peer };
}
async function runLightCheck(challenge, peer) {
  const failures = [];
  if (!peer || peer.status !== 'connected') failures.push('The target peer must be connected first.');
  if (!peer || Number(challenge.target_peer_id) !== Number(peer.id) || Number(challenge.owner_user_id) !== Number(peer.user_id)) failures.push('Challenge ownership and target peer do not match.');
  if (!isInCidr(challenge.target_ip, cfg.wgCidr) || !ipv4InRange(challenge.target_ip, cfg.targetStart, cfg.targetEnd)) failures.push('The target IP is outside the target pool.');
  const probe = await probeTargetIp(challenge.target_ip);
  if (!probe.ok) failures.push('The target IP is unreachable: ' + probe.detail + '.');
  const services = parseStoredServices(challenge.services);
  if (services.length < 3) failures.push('At least three services are required.');
  const result = { ok: failures.length === 0, failures, probe };
  db.prepare('INSERT INTO connectivity_checks(peer_id,challenge_id,check_type,status,observed_ip,detail_code) VALUES(?,?,?,?,?,?)').run(peer?.id || null, challenge.id, 'light_check', result.ok ? 'pass' : 'fail', challenge.target_ip, probe.detail);
  if (result.ok) {
    db.prepare("UPDATE challenges SET validation_status='passed',health_status='healthy',health_detail=?,last_reachable_at=?,updated_at=? WHERE id=?").run(probe.detail, nowIso(), nowIso(), challenge.id);
  } else {
    db.prepare("UPDATE challenges SET validation_status='failed',health_detail=?,updated_at=? WHERE id=?").run(failures.join(' '), nowIso(), challenge.id);
  }
  return result;
}

function assignmentBrief() {
  return '<section class="card assignment-card"><span class="kicker">WEEK 4 / DELIVERABLE</span><h2>Build one controlled lab</h2><p class="muted">A public Ubuntu 24.04 VPS is required for this assignment. Local desktop or WSL-only targets are not accepted because other participants must reach your lab through the WireGuard network.</p>' +
    '<div class="assignment-grid"><div><h3>Required outcome</h3><ul><li>At least three services that can be enumerated.</li><li>An initial foothold as a non-root user.</li><li>One demonstrable Linux privilege-escalation path.</li><li>One case-sensitive flag in <code>MBC{...}</code> format.</li><li>Submit all challenge details directly in <strong>BUILD</strong>; do not send credentials to the mentor.</li></ul></div>' +
    '<div><h3>Recommended VPS baseline</h3><ul><li>Ubuntu 24.04 LTS, 1 vCPU, and 1–2 GB RAM.</li><li>At least 20 GB disk and one public IPv4 address.</li><li>WireGuard is the only path for the vulnerable lab services.</li><li>Keep SSH restricted to your administration source.</li></ul></div></div>' +
    '<div class="assignment-callout"><h3>No-cost starting points</h3><p class="muted">Free plans change and may require identity or payment verification. Check the provider terms and set a spending alert before creating a VM.</p><ul class="link-list"><li><a href="https://docs.oracle.com/iaas/Content/FreeTier/freetier.htm" target="_blank" rel="noopener noreferrer">Oracle Cloud Always Free</a><span>Always Free compute in your home region, subject to capacity and eligibility.</span></li><li><a href="https://aws.amazon.com/ec2/getting-started/" target="_blank" rel="noopener noreferrer">AWS EC2 Free Tier</a><span>Free-plan or credit eligibility varies by account age and usage; monitor billing.</span></li><li><a href="https://cloud.google.com/free" target="_blank" rel="noopener noreferrer">Google Cloud Free Program</a><span>New-account credits plus an eligible monthly free tier; quotas and regions apply.</span></li><li><a href="https://azure.microsoft.com/en-us/free/students/" target="_blank" rel="noopener noreferrer">Azure for Students</a><span>Use only if your active student account is eligible for the offer.</span></li></ul></div>' +
    '<p class="muted assignment-footnote">Provision the VPS first, connect the Target peer, then complete BUILD. The portal checks reachability before you submit for mentor review.</p></section>';
}

const app = express();
app.disable('x-powered-by');
const trustedProxySet = new Set(cfg.trustedProxyIps.map((ip) => ip.replace(/^::ffff:/, '')));
app.set('trust proxy', (ip) => trustedProxySet.has(String(ip).replace(/^::ffff:/, '')));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  referrerPolicy: { policy: 'same-origin' },
}));
app.use(express.json({ limit: '8kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.static(path.join(HERE, 'public'), { maxAge: cfg.production ? '1h' : 0 }));
app.use(attachSession);
app.use((req, res, next) => { syncLockState(); next(); });

const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const enrollmentLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const submitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 80, standardHeaders: true, legacyHeaders: false });
app.use(generalLimiter);

const existingAdmin = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (!existingAdmin) {
  if (!cfg.adminPassword) {
    console.error('ADMIN_PASSWORD is required to bootstrap the first admin.');
    process.exit(1);
  }
  db.prepare("INSERT INTO users(caas_id,password_hash,role) VALUES(?,?, 'admin')").run(cfg.adminId, hashPassword(cfg.adminPassword));
}

app.get('/', (req, res) => {
  const phase = currentPhase();
  const count = db.prepare("SELECT COUNT(*) AS count FROM challenges WHERE status='approved' AND health_status<>'disabled'").get().count;
  const content = '<section class="hero-compact"><span class="kicker">MBC LABORATORY / CYBER SECURITY</span><h1>LAS WEEK 04<br><em>BUILD. FIND. PROVE.</em></h1><p>Operational portal for WireGuard setup, lab creation, and peer-to-peer challenge testing.</p><div class="hero-actions"><a class="button primary" href="' + (req.user ? '/workspace' : '/login') + '">' + (req.user ? 'OPEN WORKSPACE' : 'SIGN IN') + '</a><a class="button ghost" href="/scoreboard">SCOREBOARD</a></div><div class="hero-meta"><span><strong>' + esc(phase) + '</strong><small>EVENT STATE</small></span><span><strong>' + esc(count) + '</strong><small>APPROVED LABS</small></span><span><strong>' + esc(cfg.wgCidr) + '</strong><small>PRIVATE TARGET NETWORK</small></span></div></section>';
  res.send(renderPage('LAS Week 4', content, req));
});

app.get('/register', (req, res) => {
  const content = pageHead('ACCOUNT / ACTIVATE', 'Activate account', 'Use your CaAs ID and the one-time activation code issued by your mentor.') +
    '<form method="post" action="/register" class="form-card">' + csrfField(req) +
    '<label>CaAs ID<input name="caas_id" autocomplete="username" maxlength="40" required placeholder="CAAS-001"></label>' +
    '<label>Activation code<input name="activation_code" autocomplete="one-time-code" maxlength="100" required></label>' +
    '<label>Password<input name="password" type="password" autocomplete="new-password" minlength="12" required><small>Minimum 12 characters.</small></label>' +
    '<label>Confirm password<input name="password_confirm" type="password" autocomplete="new-password" minlength="12" required></label>' +
    formButton('ACTIVATE ACCOUNT') + '</form>';
  res.send(renderPage('Activate account', content, req));
});
app.post('/register', authLimiter, requireCsrf, (req, res) => {
  const caasId = normalizeId(input(req, 'caas_id'));
  const password = input(req, 'password');
  const code = input(req, 'activation_code');
  if (!/^[A-Z0-9][A-Z0-9_-]{2,39}$/.test(caasId) || !isStrongPassword(password) || password !== input(req, 'password_confirm')) {
    return res.status(400).send(renderPage('Activation failed', notice('Activation failed', 'Check the ID, use a password of at least 12 characters, and confirm it correctly.', 'bad'), req));
  }
  const invite = db.prepare('SELECT * FROM invites WHERE caas_id=? AND used_at IS NULL AND expires_at>?').get(caasId, nowIso());
  if (!invite || !sameHash(invite.code_hash, sha256(code))) return res.status(400).send(renderPage('Activation failed', notice('Activation failed', 'The ID or activation code is invalid, expired, or already used.', 'bad'), req));
  try {
    const userId = withTransaction(() => {
      const info = db.prepare("INSERT INTO users(caas_id,password_hash,role) VALUES(?,?, 'participant')").run(caasId, hashPassword(password));
      db.prepare('UPDATE invites SET used_at=? WHERE id=?').run(nowIso(), invite.id);
      return info.lastInsertRowid;
    });
    clearSession(req);
    req.user = { id: userId, caasId, role: 'participant', isVisitor: false, isTest: false };
    createSession(req, userId);
    logEvent(req, 'account_activated', 'user', userId);
    res.redirect('/workspace');
  } catch {
    res.status(400).send(renderPage('Activation failed', notice('Activation failed', 'This CaAs ID is already active. Contact your mentor.', 'bad'), req));
  }
});

function loginForm(req, error = '', caasId = '') {
  const message = error ? '<div class="flash bad"><strong>Sign in failed</strong><p>' + esc(error) + '</p></div>' : '';
  return pageHead('ACCOUNT / SIGN IN', 'Sign in', 'Use your CaAs ID and password.') + message +
    '<form method="post" action="/login" class="form-card">' + csrfField(req) +
    '<label>CaAs ID<input name="caas_id" autocomplete="username" maxlength="40" required value="' + esc(caasId) + '"></label>' +
    '<label>Password<input name="password" type="password" autocomplete="current-password" required></label>' +
    formButton('SIGN IN') + '</form><p class="form-foot">Not activated yet? <a href="/register">Activate account</a></p>';
}
app.get('/login', (req, res) => {
  if (req.user) return res.redirect(req.user.role === 'admin' ? '/admin' : '/workspace');
  res.send(renderPage('Sign in', loginForm(req), req));
});
app.post('/login', authLimiter, requireCsrf, (req, res) => {
  const caasId = normalizeId(input(req, 'caas_id'));
  const user = db.prepare('SELECT * FROM users WHERE caas_id=? AND active=1').get(caasId);
  const passwordOk = Boolean(user && verifyPassword(input(req, 'password'), user.password_hash));
  if (!passwordOk) {
    logEvent(req, 'login_failed', 'user', user?.id || null);
    return res.status(401).send(renderPage('Sign in', loginForm(req, 'The credentials are invalid.', caasId), req));
  }
  clearSession(req);
  req.user = { id: user.id, caasId: user.caas_id, role: user.role, isVisitor: Boolean(user.is_visitor), isTest: Boolean(user.is_test) };
  createSession(req, user.id);
  db.prepare('UPDATE users SET last_login_at=? WHERE id=?').run(nowIso(), user.id);
  logEvent(req, 'login_success', 'user', user.id);
  res.redirect(user.role === 'admin' ? '/admin' : '/workspace');
});
app.post('/logout', requireCsrf, (req, res) => { logEvent(req, 'logout'); clearSession(req); res.redirect('/'); });

function setupStatus(userId) {
  return { attacker: peerForUser(userId, 'attacker'), target: peerForUser(userId, 'target') };
}
function stepCard(number, title, state, text, href) {
  return '<article class="step-card"><div class="step-number">' + esc(number) + '</div><div class="step-content"><div class="step-top"><span class="kicker">' + esc(title) + '</span>' + statusBadge(state) + '</div><p>' + esc(text) + '</p>' + (href ? '<a class="button primary small" href="' + esc(href) + '">OPEN</a>' : '') + '</div></article>';
}
function workspace(req, res) {
  const status = setupStatus(req.user.id);
  const challenge = ownChallenge(req.user.id);
  const phase = currentPhase();
  const targetReady = status.target?.status === 'connected';
  const buildState = challenge?.status || (targetReady ? 'not_started' : 'locked');
  const labState = phase === 'LIVE' || phase === 'LOCKED' ? phase.toLowerCase() : 'closed';
  const score = scoreForSolved(db.prepare('SELECT * FROM submissions WHERE user_id=? AND correct=1').all(req.user.id));
  let content = pageHead('WORKSPACE / ' + req.user.caasId, 'Next action', 'Complete the steps from top to bottom.');
  content += '<div class="stats">' + stat('Event', phase, 'WIB schedule') + stat('Your score', String(score.points), score.solved + ' solved') + stat('Own lab', challenge?.status || 'not started', 'owner ID admin-only') + '</div>';
  content += '<section class="step-list">' +
    stepCard('01', 'LAB CONFIGURATION', 'ready', 'Review network rules and the setup order before connecting a peer.', '/setup') +
    stepCard('02', 'SETUP TARGET', status.target?.status || 'not_started', 'Ubuntu target. This is the lab host and should be connected first.', '/setup/target') +
    stepCard('03', 'BUILD YOUR LAB', buildState, 'Create the challenge in the portal, then run Light Check.', targetReady ? '/build' : '') +
    stepCard('04', 'SETUP ATTACKER', status.attacker?.status || 'not_started', 'Kali VM or Kali WSL. Use the tunnel to test peer labs.', '/setup/attacker') +
    stepCard('05', 'LAB SPACE', labState, 'Open peer labs, review targets, and submit flags.', phase === 'LIVE' || phase === 'LOCKED' ? '/lab-space' : '') +
    '</section>';
  content += '<div class="inline-actions"><a class="button ghost small" href="/learn">OPEN LEARN MODULES</a></div>';
  content += '<section class="timeline"><span class="kicker">SCHEDULE</span><div><strong>BUILD</strong><span>Until ' + esc(formatWhen(cfg.buildDeadlineAt)) + '</span></div><div><strong>LIVE</strong><span>' + esc(formatWhen(cfg.portalOpenAt)) + '</span></div><div><strong>LOCK</strong><span>' + esc(formatWhen(cfg.gameLockAt)) + '</span></div></section>';
  res.send(renderPage('Workspace', content, req));
}
app.get('/workspace', requireAuth, workspace);
app.get('/dashboard', requireAuth, (req, res) => res.redirect('/workspace'));

app.get('/setup', requireAuth, (req, res) => {
  const status = setupStatus(req.user.id);
  const content = pageHead('SETUP / WIREGUARD', 'Connect the lab network', 'One attacker peer and one target peer are assigned to each CaAs account.') +
    '<section class="callout"><strong>01 / LAB CONFIGURATION</strong><p>Portal access may be public. Target IPs and vulnerable services are reachable only through WireGuard. Keep the generated private key on its own machine.</p></section>' +
    '<div class="step-list">' +
    stepCard('02', 'TARGET', status.target?.status || 'not_started', 'Ubuntu VM or optional VPS. Connect the lab host before testing.', '/setup/target') +
    stepCard('03', 'ATTACKER', status.attacker?.status || 'not_started', 'Kali VM or Kali WSL. Connect after the lab is configured.', '/setup/attacker') +
    '</div><section class="callout"><strong>NETWORK RULE</strong><p>The portal may be public. Target IPs are reachable only through WireGuard.</p></section>' +
    (req.user.isVisitor ? '<section class="notice compact"><strong>READ-ONLY VISITOR</strong><p>Setup actions are disabled for this account.</p></section>' : '') +
    '<a class="button back" href="/workspace">← BACK TO WORKSPACE</a>';
  res.send(renderPage('Setup', content, req));
});
app.get('/setup/linux.sh', (req, res) => {
  res.type('text/plain').set('Cache-Control', 'no-store').set('Content-Disposition', 'inline; filename="mbc-las-w4-setup.sh"').send(installerScript());
});
app.get('/s/:token', (req, res) => {
  const token = String(req.params.token || '').trim();
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) return res.status(404).type('text/plain').send('SETUP_LINK_INVALID');
  const candidate = db.prepare('SELECT id FROM enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?').get(sha256(token), nowIso());
  if (!candidate) return res.status(404).type('text/plain').send('SETUP_LINK_INVALID');
  res.type('text/plain').set('Cache-Control', 'no-store').set('Content-Disposition', 'inline; filename="mbc-las-w4-setup-short.sh"').send(installerBootstrap(token));
});
app.get('/setup/:type', requireAuth, requirePeerTypeParam, (req, res) => res.set('Cache-Control', 'no-store').send(setupPage(req, req.params.type)));
app.post('/api/setup/:type/token', requireAuth, requireWriteAccess, requirePeerTypeParam, requireCsrf, enrollmentLimiter, (req, res) => {
  const type = req.params.type;
  if (currentPhase() === 'LOCKED') return res.status(403).send(phaseError(req, 'Event locked', 'New peer enrollment is closed after the global lock.'));
  try {
    const result = issueEnrollmentToken(req.user.id, type);
    logEvent(req, 'enrollment_token_issued', 'peer', result.peer.id, { peerType: type });
    res.set('Cache-Control', 'no-store').send(setupPage(req, type, result.token));
  } catch (error) {
    res.status(503).set('Cache-Control', 'no-store').send(setupPage(req, type, '', error.message));
  }
});
app.get('/api/setup/status', requireAuth, (req, res) => {
  const status = setupStatus(req.user.id);
  res.set('Cache-Control', 'no-store');
  res.json({
    attacker: status.attacker ? { type: 'attacker', ip: status.attacker.assigned_ip, status: status.attacker.status, lastVerifiedAt: status.attacker.last_verified_at } : null,
    target: status.target ? { type: 'target', ip: status.target.assigned_ip, status: status.target.status, lastVerifiedAt: status.target.last_verified_at } : null,
    phase: currentPhase(),
  });
});
app.post('/api/setup/:type/revoke', requireAuth, requireWriteAccess, requirePeerTypeParam, requireCsrf, requireCurrentPassword, (req, res) => {
  const peer = peerForUser(req.user.id, req.params.type);
  if (!peer) return res.redirect('/setup/' + req.params.type);
  if (peer.public_key) {
    const helper = helperAction('revoke', peer);
    if (!helper.ok) return res.status(503).set('Cache-Control', 'no-store').send(setupPage(req, req.params.type, '', helper.code));
  }
  db.prepare("UPDATE wireguard_peers SET status='revoked',revoked_at=? WHERE id=? AND user_id=?").run(nowIso(), peer.id, req.user.id);
  db.prepare('UPDATE enrollment_tokens SET used_at=COALESCE(used_at,?) WHERE peer_id=?').run(nowIso(), peer.id);
  logEvent(req, 'peer_revoked', 'peer', peer.id, { peerType: peer.peer_type });
  res.redirect('/setup/' + req.params.type);
});
app.post('/api/setup/:type/regenerate', requireAuth, requireWriteAccess, requirePeerTypeParam, requireCsrf, requireCurrentPassword, (req, res) => {
  if (currentPhase() === 'LOCKED') return res.status(403).send(phaseError(req, 'Event locked', 'Peer regeneration is closed after the global lock.'));
  const peer = peerForUser(req.user.id, req.params.type);
  if (peer) {
    if (peer.public_key) {
      const helper = helperAction('revoke', peer);
      if (!helper.ok) return res.status(503).set('Cache-Control', 'no-store').send(setupPage(req, req.params.type, '', helper.code));
    }
    db.prepare("UPDATE wireguard_peers SET status='revoked',revoked_at=? WHERE id=? AND user_id=?").run(nowIso(), peer.id, req.user.id);
  }
  try {
    const result = issueEnrollmentToken(req.user.id, req.params.type);
    logEvent(req, 'peer_regeneration_started', 'peer', result.peer.id, { peerType: req.params.type });
    res.set('Cache-Control', 'no-store').send(setupPage(req, req.params.type, result.token));
  } catch (error) {
    res.status(503).set('Cache-Control', 'no-store').send(setupPage(req, req.params.type, '', error.message));
  }
});

app.post('/api/enroll', enrollmentLimiter, (req, res) => {
  if (currentPhase() === 'LOCKED') return res.status(403).type('text/plain').send('EVENT_LOCKED');
  const token = String(req.body?.token || '').trim();
  const publicKey = String(req.body?.public_key || '').trim();
  if (!token || !validWireguardPublicKey(publicKey)) return res.status(400).type('text/plain').send('ENROLL_FAILED');
  let row;
  try {
    row = withTransaction(() => {
      const candidate = db.prepare('SELECT e.*,p.assigned_ip,p.status AS peer_status,u.active FROM enrollment_tokens e JOIN wireguard_peers p ON p.id=e.peer_id JOIN users u ON u.id=e.user_id WHERE e.token_hash=?').get(sha256(token));
      if (!candidate || !candidate.active || candidate.peer_status === 'revoked') throw new Error('TOKEN_INVALID');
      const enrollment = validateEnrollment({ record: candidate, userId: candidate.user_id, peerId: candidate.peer_id, peerType: candidate.peer_type });
      if (!enrollment.ok) throw new Error(enrollment.code);
      const duplicate = db.prepare("SELECT id FROM wireguard_peers WHERE public_key=? AND status<>'revoked' AND id<>?").get(publicKey, candidate.peer_id);
      if (duplicate) throw new Error('PUBLIC_KEY_IN_USE');
      const consumed = db.prepare('UPDATE enrollment_tokens SET used_at=? WHERE id=? AND used_at IS NULL AND expires_at>?').run(nowIso(), candidate.id, nowIso());
      if (consumed.changes !== 1) throw new Error('TOKEN_INVALID');
      return candidate;
    });
  } catch (error) {
    const code = ['TOKEN_INVALID', 'TOKEN_USED', 'TOKEN_EXPIRED', 'TOKEN_OWNER_MISMATCH', 'TOKEN_PEER_MISMATCH', 'TOKEN_TYPE_MISMATCH', 'PUBLIC_KEY_IN_USE'].includes(error.message) ? error.message : 'TOKEN_INVALID';
    return res.status(code === 'PUBLIC_KEY_IN_USE' ? 409 : 401).type('text/plain').send(code);
  }
  const peer = peerForId(row.peer_id);
  const nonce = randomToken(32);
  const helper = helperAction('add', peer, publicKey);
  if (!helper.ok) {
    logEventForUser(req, row.user_id, 'peer_enrollment_failed', 'peer', peer.id, { code: helper.code });
    return res.status(503).type('text/plain').send(helper.code);
  }
  try {
    withTransaction(() => {
      db.prepare("UPDATE wireguard_peers SET public_key=?,status='enrolled',client_os=?,client_hostname=?,verify_nonce_hash=?,verify_nonce_expires_at=?,enrolled_at=? WHERE id=?").run(
        publicKey,
        String(req.body?.client_os || 'linux').slice(0, 40),
        String(req.body?.hostname || 'unknown').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 64) || 'unknown',
        sha256(nonce),
        new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        nowIso(),
        row.peer_id,
      );
    });
  } catch {
    helperAction('revoke', { ...peer, public_key: publicKey });
    logEventForUser(req, row.user_id, 'peer_enrollment_failed', 'peer', peer.id, { code: 'DATABASE_UPDATE_FAILED' });
    return res.status(500).type('text/plain').send('ENROLL_FAILED');
  }
  logEventForUser(req, row.user_id, 'peer_enrolled', 'peer', peer.id, { peerType: row.peer_type, clientOs: String(req.body?.client_os || 'linux').slice(0, 40) });
  const lines = [
    'MBC_STATUS=OK',
    'MBC_PEER_TYPE=' + row.peer_type,
    'MBC_ASSIGNED_IP=' + row.assigned_ip,
    'MBC_SERVER_PUBLIC_KEY=' + cfg.wgServerPublicKey,
    'MBC_ENDPOINT=' + cfg.wgEndpoint,
    'MBC_VERIFY_URL=' + cfg.wgVerifyUrl,
    'MBC_VERIFY_NONCE=' + nonce,
  ];
  res.type('text/plain').set('Cache-Control', 'no-store').send(lines.join('\n') + '\n');
});
app.post('/internal/verify', enrollmentLimiter, (req, res) => {
  const source = clientIp(req);
  if (!isInCidr(source, cfg.wgCidr)) return res.status(403).json({ ok: false, code: 'WIREGUARD_ONLY' });
  const nonce = String(req.body?.nonce || '').trim();
  const peer = db.prepare("SELECT * FROM wireguard_peers WHERE assigned_ip=? AND status IN ('enrolled','connected')").get(source);
  if (!peer || !nonce || !peer.verify_nonce_expires_at || new Date(peer.verify_nonce_expires_at).getTime() < Date.now() || !sameHash(peer.verify_nonce_hash, sha256(nonce))) {
    if (peer) db.prepare('INSERT INTO connectivity_checks(peer_id,check_type,status,observed_ip,detail_code) VALUES(?,?,?,?,?)').run(peer.id, 'internal_verify', 'fail', source, 'VERIFY_FAILED');
    return res.status(403).json({ ok: false, code: 'VERIFY_FAILED' });
  }
  const verifiedAt = nowIso();
  const updated = db.prepare("UPDATE wireguard_peers SET status='connected',last_verified_at=?,last_handshake_at=?,client_os=COALESCE(?,client_os),verify_nonce_hash=NULL,verify_nonce_expires_at=NULL WHERE id=? AND status IN ('enrolled','connected') AND verify_nonce_hash=?").run(
    verifiedAt, verifiedAt, String(req.body?.client_os || '').slice(0, 40) || null, peer.id, peer.verify_nonce_hash,
  );
  if (updated.changes !== 1) return res.status(403).json({ ok: false, code: 'VERIFY_FAILED' });
  db.prepare('INSERT INTO connectivity_checks(peer_id,check_type,status,observed_ip,detail_code) VALUES(?,?,?,?,?)').run(peer.id, 'internal_verify', 'pass', source, 'CONNECTED');
  res.json({ ok: true, peerType: peer.peer_type, assignedIp: peer.assigned_ip });
});

function reviewChallenge(id) {
  return db.prepare("SELECT c.*,u.caas_id,p.status AS target_status,p.assigned_ip AS peer_ip FROM challenges c JOIN users u ON u.id=c.owner_user_id LEFT JOIN wireguard_peers p ON p.id=c.target_peer_id WHERE c.id=?").get(Number(id));
}
function reviewServices(value) {
  return parseStoredServices(value).map((service) => '<div><code>' + esc(service.port + '/' + service.protocol) + '</code><strong>' + esc(service.label) + '</strong><span>' + esc(service.note || '') + '</span></div>').join('');
}
function reviewAvailabilityActions(req, challenge) {
  if (challenge.health_status === 'disabled') {
    return '<form method="post" action="/admin/challenges/' + challenge.id + '/enable">' + csrfField(req) + formButton('ENABLE LAB', 'ghost') + '</form>';
  }
  return '<form method="post" action="/admin/challenges/' + challenge.id + '/disable" class="note-form">' + csrfField(req) + confirmationField('Type DISABLE', 'DISABLE') + '<input name="reason" maxlength="300" placeholder="Reason (optional)">' + '<button class="button danger" type="submit">DISABLE LAB</button></form>';
}
function reviewDetail(req, challenge, noticeText = '') {
  let body = pageHead('ADMIN / REVIEW', 'Review lab ' + String(challenge.id).padStart(2, '0'), 'Owner identity and mentor-only path are visible only inside this admin route.');
  if (noticeText) body += '<div class="flash bad">' + esc(noticeText) + '</div>';
  body += '<div class="stats review-stats">' + stat('Owner', challenge.caas_id, challenge.status) + stat('Target', challenge.peer_ip || challenge.target_ip, challenge.target_status || 'not assigned') + stat('Light check', challenge.validation_status, challenge.health_status) + '</div>';
  body += '<div class="review-content">';
  body += '<section class="card review-card review-player"><span class="kicker">PLAYER-FACING</span><h2>' + esc(challenge.title) + '</h2><p>' + nl2br(challenge.description) + '</p><p><strong>Initial hint:</strong> ' + nl2br(challenge.initial_hint) + '</p><div class="service-table">' + reviewServices(challenge.services) + '</div></section>';
  body += '<section class="card review-card review-mentor"><span class="kicker">MENTOR-ONLY</span><h2>Mentor notes</h2><p class="review-mentor-notes">' + nl2br(challenge.intended_path) + '</p></section>';
  body += '<section class="card review-card review-decision"><span class="kicker">DECISION</span><div class="review-state-row"><span><small>STATUS</small>' + statusBadge(challenge.status) + '</span><span><small>VALIDATION</small>' + statusBadge(challenge.validation_status) + '</span><span><small>HEALTH</small>' + statusBadge(challenge.health_status) + '</span></div><div class="review-actions"><div class="review-actions-primary"><form method="post" action="/admin/review/' + challenge.id + '/recheck">' + csrfField(req) + formButton('RECHECK TARGET', 'ghost') + '</form><form method="post" action="/admin/review/' + challenge.id + '/approve">' + csrfField(req) + '<input type="hidden" name="reviewer_note" value="Approved by mentor.">' + formButton('APPROVE / PUBLISH') + '</form><form method="post" action="/admin/review/' + challenge.id + '/return" class="note-form">' + csrfField(req) + '<input name="reviewer_note" maxlength="1000" required placeholder="Required revision note"><button class="button danger" type="submit">RETURN TO AUTHOR</button></form></div><div class="review-actions-availability">' + reviewAvailabilityActions(req, challenge) + '</div></div></section>';
  body += '</div><a class="button back review-back" href="/admin/review">← BACK TO REVIEW QUEUE</a>';
  return renderPage('Admin review', body, req);
}

app.get('/admin', requireAdmin, (req, res) => {
  const pending = db.prepare("SELECT COUNT(*) AS count FROM challenges WHERE status='pending_review'").get().count;
  const approved = db.prepare("SELECT COUNT(*) AS count FROM challenges WHERE status='approved'").get().count;
  const degraded = db.prepare("SELECT COUNT(*) AS count FROM challenges WHERE health_status='degraded'").get().count;
  const content = pageHead('ADMIN / OPERATIONS', 'Review queue', 'Approve only labs that pass the deterministic Light Check.') +
    '<div class="stats">' + stat('Pending review', String(pending), 'needs mentor decision') + stat('Approved', String(approved), 'published when live') + stat('Degraded', String(degraded), 'target IP unreachable') + '</div>' +
    '<div class="admin-actions"><a class="button primary" href="/admin/review">OPEN REVIEW QUEUE</a><a class="button ghost" href="/admin/peers">PEERS</a><a class="button ghost" href="/admin/health">HEALTH</a><a class="button ghost" href="/admin/event">EVENT</a><a class="button ghost" href="/admin/audit">AUDIT</a></div><div class="security-callout"><strong>PRIVATE ROUTE</strong><span>Admin access requires the admin account and a source inside the WireGuard or Tailscale network.</span></div><a class="button ghost" href="/learn">OPEN LEARN</a>';
  res.send(renderPage('Admin', content, req));
});
app.get('/admin/review', requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT c.id,c.title,c.status,c.validation_status,c.health_status,c.updated_at,u.caas_id FROM challenges c JOIN users u ON u.id=c.owner_user_id WHERE c.status='pending_review' ORDER BY c.updated_at ASC").all();
  let content = pageHead('ADMIN / REVIEW', 'Pending labs', 'Review the owner, target status, player view, and intended path.');
  content += rows.length ? '<div class="admin-list">' + rows.map((row) => '<article class="admin-card"><div class="step-top"><span class="kicker">LAB ' + String(row.id).padStart(2, '0') + '</span>' + statusBadge(row.validation_status) + '</div><h2>' + esc(row.title) + '</h2><p>Owner: <strong>' + esc(row.caas_id) + '</strong></p><div class="admin-grid"><span><small>STATUS</small>' + statusBadge(row.status) + '</span><span><small>HEALTH</small>' + statusBadge(row.health_status) + '</span></div><a class="button primary small" href="/admin/review/' + row.id + '">OPEN REVIEW</a></article>').join('') + '</div>' : '<div class="empty"><h2>Queue empty</h2><p>No pending challenge requires a decision.</p></div>';
  content += '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Review queue', content, req));
});
app.get('/admin/review/:id', requireAdmin, (req, res) => {
  const challenge = reviewChallenge(req.params.id);
  if (!challenge) return res.status(404).send(renderPage('Not found', notice('Not found', 'Challenge not found.', 'bad'), req));
  res.send(reviewDetail(req, challenge));
});
async function adminHealthRecheck(req, res) {
  const challenge = reviewChallenge(req.params.id);
  if (!challenge) return res.status(404).send('NOT_FOUND');
  const peer = peerForId(challenge.target_peer_id);
  const result = await recordTargetHealth(challenge, peer, 'admin_recheck');
  logEvent(req, 'challenge_admin_recheck', 'challenge', challenge.id, { ok: result.probe.ok, throttled: result.throttled, health: result.decision.status });
  res.redirect('/admin/review/' + challenge.id);
}
app.post('/admin/review/:id/recheck', requireAdmin, requireCsrf, adminHealthRecheck);
app.post('/admin/challenges/:id/recheck', requireAdmin, requireCsrf, adminHealthRecheck);
app.post('/admin/review/:id/approve', requireAdmin, requireCsrf, (req, res) => {
  const challenge = reviewChallenge(req.params.id);
  if (!challenge) return res.status(404).send('NOT_FOUND');
  if (currentPhase() === 'LOCKED') return res.status(403).send(reviewDetail(req, challenge, 'The event is locked. Approval is no longer available.'));
  if (challenge.status !== 'pending_review' || challenge.validation_status !== 'passed' || challenge.health_status !== 'healthy') return res.status(400).send(reviewDetail(req, challenge, 'The challenge must be pending review and pass Light Check before approval.'));
  db.prepare("UPDATE challenges SET status='approved',reviewer_note=?,approved_at=?,published_at=?,updated_at=? WHERE id=? AND status='pending_review'").run(input(req, 'reviewer_note') || 'Approved by mentor.', nowIso(), nowIso(), nowIso(), challenge.id);
  logEvent(req, 'challenge_approved', 'challenge', challenge.id);
  res.redirect('/admin/review');
});
app.post('/admin/review/:id/return', requireAdmin, requireCsrf, (req, res) => {
  const challenge = reviewChallenge(req.params.id);
  const note = input(req, 'reviewer_note');
  if (!challenge) return res.status(404).send('NOT_FOUND');
  if (currentPhase() === 'LOCKED') return res.status(403).send(reviewDetail(req, challenge, 'The event is locked.'));
  if (challenge.status !== 'pending_review' || note.length < 5) return res.status(400).send(reviewDetail(req, challenge, 'The challenge must be pending review, and the revision note must contain at least 5 characters.'));
  db.prepare("UPDATE challenges SET status='draft',validation_status='needs_revision',reviewer_note=?,updated_at=? WHERE id=? AND status='pending_review'").run(note.slice(0, 1000), nowIso(), challenge.id);
  logEvent(req, 'challenge_returned', 'challenge', challenge.id, { noteLength: note.length });
  res.redirect('/admin/review');
});
app.post('/admin/challenges/:id/disable', requireAdmin, requireCsrf, (req, res) => {
  const challenge = reviewChallenge(req.params.id);
  if (!challenge) return res.status(404).send('NOT_FOUND');
  if (!confirmationMatches(req, 'DISABLE')) return res.status(400).send(reviewDetail(req, challenge, 'Type DISABLE to confirm this destructive action.'));
  if (challenge.health_status === 'disabled') return res.redirect('/admin/review/' + challenge.id);
  const reason = input(req, 'reason').slice(0, 300) || 'Disabled by mentor.';
  db.prepare("UPDATE challenges SET health_status='disabled',health_detail=?,updated_at=? WHERE id=?").run(reason, nowIso(), challenge.id);
  logEvent(req, 'challenge_disabled', 'challenge', challenge.id, { reasonLength: reason.length });
  res.redirect('/admin/review/' + challenge.id);
});
app.post('/admin/challenges/:id/enable', requireAdmin, requireCsrf, (req, res) => {
  const challenge = reviewChallenge(req.params.id);
  if (!challenge) return res.status(404).send('NOT_FOUND');
  if (challenge.status === 'locked') return res.status(403).send(reviewDetail(req, challenge, 'Locked challenges remain read-only.'));
  if (challenge.health_status !== 'disabled') return res.redirect('/admin/review/' + challenge.id);
  db.prepare("UPDATE challenges SET health_status='unknown',health_detail='Re-enabled; health check required.',updated_at=? WHERE id=?").run(nowIso(), challenge.id);
  logEvent(req, 'challenge_enabled', 'challenge', challenge.id);
  res.redirect('/admin/review/' + challenge.id);
});

app.get('/admin/peers', requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT p.*,u.caas_id FROM wireguard_peers p JOIN users u ON u.id=p.user_id ORDER BY p.peer_type,p.assigned_ip,p.id").all();
  let content = pageHead('ADMIN / PEERS', 'Peer inventory', 'Review allocations and revoke a compromised peer. Public keys are never private keys.');
  content += rows.length ? '<div class="ops-table"><div class="ops-row ops-head"><span>PEER</span><span>OWNER</span><span>IP</span><span>STATUS</span><span>VERIFIED</span><span>ACTION</span></div>' + rows.map((row) => '<div class="ops-row"><span><strong>' + esc(row.peer_type.toUpperCase()) + '</strong><small>' + esc(row.id) + '</small></span><span>' + esc(row.caas_id) + '</span><code>' + esc(row.assigned_ip) + '</code><span>' + statusBadge(row.status) + '</span><span>' + esc(row.last_verified_at || 'NOT VERIFIED') + '</span><span>' + (row.status === 'revoked' ? '<span class="muted">REVOKED</span>' : '<form method="post" action="/admin/peers/' + row.id + '/revoke" class="inline-form">' + csrfField(req) + confirmationField('Type REVOKE', 'REVOKE') + formButton('REVOKE', 'danger') + '</form>') + '</span></div>').join('') + '</div>' : '<div class="empty"><h2>No peers</h2><p>Peer allocations appear after participant setup.</p></div>';
  content += '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Peer inventory', content, req));
});
app.post('/admin/peers/:id/revoke', requireAdmin, requireCsrf, (req, res) => {
  const peer = db.prepare('SELECT * FROM wireguard_peers WHERE id=?').get(Number(req.params.id));
  if (!peer) return res.status(404).send('NOT_FOUND');
  if (!confirmationMatches(req, 'REVOKE')) return res.status(400).send(renderPage('Peer inventory', notice('Confirmation required', 'Type REVOKE to revoke this peer.', 'bad'), req));
  if (peer.status !== 'revoked' && peer.public_key) {
    const helper = helperAction('revoke', peer);
    if (!helper.ok) return res.status(503).send(renderPage('Peer inventory', notice('Revoke failed', helper.code, 'bad'), req));
  }
  db.prepare("UPDATE wireguard_peers SET status='revoked',revoked_at=? WHERE id=? AND status<>'revoked'").run(nowIso(), peer.id);
  db.prepare('UPDATE enrollment_tokens SET used_at=COALESCE(used_at,?) WHERE peer_id=?').run(nowIso(), peer.id);
  logEvent(req, 'admin_peer_revoked', 'peer', peer.id, { peerType: peer.peer_type });
  res.redirect('/admin/peers');
});

app.get('/admin/health', requireAdmin, async (req, res) => {
  const candidates = db.prepare("SELECT c.*,u.caas_id,p.id AS peer_id,p.peer_type AS peer_type,p.assigned_ip AS peer_assigned_ip,p.status AS peer_status,p.public_key AS peer_public_key,p.last_verified_at AS peer_last_verified_at,p.last_handshake_at AS peer_last_handshake_at FROM challenges c JOIN users u ON u.id=c.owner_user_id LEFT JOIN wireguard_peers p ON p.id=c.target_peer_id WHERE c.status IN ('approved','locked') ORDER BY c.id").all();
  const results = await Promise.all(candidates.map((challenge) => recordTargetHealth(challenge, challenge.peer_id ? { id: challenge.peer_id, peer_type: challenge.peer_type, assigned_ip: challenge.peer_assigned_ip, status: challenge.peer_status, public_key: challenge.peer_public_key, last_verified_at: challenge.peer_last_verified_at, last_handshake_at: challenge.peer_last_handshake_at } : null, 'health_overview')));
  const rows = candidates.map((challenge, index) => {
    const latest = db.prepare("SELECT status,detail_code,created_at FROM connectivity_checks WHERE challenge_id=? AND check_type='target_reachability' ORDER BY id DESC LIMIT 1").get(challenge.id);
    const current = db.prepare('SELECT health_status,health_detail FROM challenges WHERE id=?').get(challenge.id);
    return { ...challenge, ...current, health: results[index], latest };
  });
  let content = pageHead('ADMIN / HEALTH', 'Target health', 'Only target-IP reachability can change a lab to DEGRADED: stale handshake plus three spaced probe failures.');
  content += '<div class="stats">' + stat('Targets', String(rows.length), 'approved or locked labs') + stat('Degraded', String(rows.filter((row) => row.health_status === 'degraded').length), 'threshold reached') + stat('Checks', String(rows.filter((row) => row.health?.checked).length), 'new checks this visit') + '</div>';
  content += rows.length ? '<div class="ops-table"><div class="ops-row ops-head"><span>LAB</span><span>OWNER</span><span>TARGET</span><span>HEALTH</span><span>LAST PROBE</span><span>ACTION</span></div>' + rows.map((row) => '<div class="ops-row"><span><strong>' + esc(row.title) + '</strong><small>' + esc(row.id) + '</small></span><span>' + esc(row.caas_id) + '</span><code>' + esc(row.peer_assigned_ip || row.target_ip) + '</code><span>' + statusBadge(row.health_status) + '<small>' + esc(row.health_detail || 'NO DETAIL') + '</small></span><span>' + esc(row.latest ? row.latest.status.toUpperCase() + ' · ' + row.latest.created_at : 'NOT CHECKED') + '</span><span><form method="post" action="/admin/challenges/' + row.id + '/recheck" class="inline-form">' + csrfField(req) + formButton('RECHECK', 'ghost') + '</form><a class="button ghost small" href="/admin/review/' + row.id + '">REVIEW</a></span></div>').join('') + '</div>' : '<div class="empty"><h2>No target labs</h2><p>Approved labs will appear here.</p></div>';
  content += '<p class="score-note">' + esc(cfg.skipNetworkChecks ? 'Development mode: target probe is a safe pass-through; production must set SKIP_NETWORK_CHECKS=false and provide helper status.' : 'Probe attempts are throttled to the configured interval. Service-port failures never mark a lab degraded.') + '</p><a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Target health', content, req));
});

app.get('/admin/event', requireAdmin, (req, res) => {
  const forced = setting('forced_phase') || 'AUTO';
  const phase = currentPhase();
  let content = pageHead('ADMIN / EVENT', 'Event controls', 'Server-enforced phase gates. Lock is global and cannot be undone from the portal.');
  content += '<div class="stats">' + stat('Current phase', phase, forced === 'AUTO' ? 'schedule' : 'forced: ' + forced) + stat('Portal open', formatWhen(cfg.portalOpenAt), 'Lab Space') + stat('Game lock', formatWhen(cfg.gameLockAt), 'flags + scoreboard') + '</div>';
  content += '<section class="card"><h2>Schedule</h2><dl><dt>Build cutoff</dt><dd>' + esc(formatWhen(cfg.buildDeadlineAt)) + '</dd><dt>Submission deadline</dt><dd>' + esc(formatWhen(cfg.submissionDeadlineAt)) + '</dd><dt>Portal open</dt><dd>' + esc(formatWhen(cfg.portalOpenAt)) + '</dd><dt>Lock</dt><dd>' + esc(formatWhen(cfg.gameLockAt)) + '</dd></dl></section>';
  content += '<section class="card"><h2>Authority actions</h2><div class="admin-actions"><form method="post" action="/admin/event/open">' + csrfField(req) + confirmationField('Type OPEN', 'OPEN') + formButton('OPEN LAB SPACE') + '</form><form method="post" action="/admin/event/lock">' + csrfField(req) + confirmationField('Type LOCK', 'LOCK') + formButton('LOCK EVENT', 'danger') + '</form></div></section><a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Event controls', content, req));
});
app.post('/admin/event/open', requireAdmin, requireCsrf, (req, res) => {
  if (!confirmationMatches(req, 'OPEN')) return res.status(400).send(renderPage('Event controls', notice('Confirmation required', 'Type OPEN to open Lab Space.', 'bad'), req));
  if (setting('forced_phase') === 'LOCKED' || eventPhase(Date.now(), cfg.buildDeadlineAt, cfg.portalOpenAt, cfg.gameLockAt) === 'LOCKED') return res.status(403).send(renderPage('Event controls', notice('Event locked', 'The global lock is final.', 'bad'), req));
  setSetting('forced_phase', 'LIVE');
  logEvent(req, 'event_opened', 'event', 'forced_phase');
  res.redirect('/admin/event');
});
app.post('/admin/event/lock', requireAdmin, requireCsrf, (req, res) => {
  if (!confirmationMatches(req, 'LOCK')) return res.status(400).send(renderPage('Event controls', notice('Confirmation required', 'Type LOCK to freeze the event.', 'bad'), req));
  setSetting('forced_phase', 'LOCKED');
  syncLockState();
  logEvent(req, 'event_locked', 'event', 'forced_phase');
  res.redirect('/admin/event');
});

app.get('/admin/audit', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT a.*,u.caas_id FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200').all();
  logEvent(req, 'audit_viewed', 'audit', null, { rowCount: rows.length });
  let content = pageHead('ADMIN / AUDIT', 'Audit trail', 'Recent security, enrollment, peer, review, health, and event actions.');
  content += rows.length ? '<div class="audit-table"><div class="audit-row audit-head"><span>TIME</span><span>ACTOR</span><span>ACTION</span><span>TARGET</span><span>DETAIL</span></div>' + rows.map((row) => '<div class="audit-row"><span>' + esc(row.created_at) + '</span><span>' + esc(row.caas_id || 'SYSTEM') + '</span><strong>' + esc(row.action) + '</strong><span>' + esc([row.target_type, row.target_id].filter(Boolean).join(' / ') || '—') + '</span><code>' + esc(row.details || '') + '</code></div>').join('') + '</div>' : '<div class="empty"><h2>No audit entries</h2><p>Security actions will appear here.</p></div>';
  content += '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Audit trail', content, req));
});

function learnInline(value) {
  return esc(value || '').replace(/`([^`]+)`/g, '<code>$1</code>');
}
function learnTrack(trackId) {
  return learnTracks.find((track) => track.id === trackId);
}
function learnCommandCard(command) {
  let output = '<article class="learn-command-card"><div class="learn-command-head"><span class="kicker">SAFE COMMAND</span><h3>' + esc(command.label) + '</h3></div>';
  output += commandBlock(command.value);
  output += '<div class="learn-command-notes"><div><span>WHAT IT DOES</span><p>' + learnInline(command.explanation) + '</p></div><div><span>WHAT TO LOOK FOR</span><p>' + learnInline(command.lookFor) + '</p></div></div>';
  if (command.output) output += '<div class="learn-output"><span>EXAMPLE OUTPUT</span><pre><code>' + esc(command.output) + '</code></pre></div>';
  return output + '</article>';
}
function learnSection(section, index) {
  let output = '<section class="learn-section" id="' + esc(section.id) + '" data-learn-section><header><span class="kicker">' + String(index + 1).padStart(2, '0') + ' / SECTION</span><h2>' + esc(section.title) + '</h2></header>';
  if (section.paragraphs) output += section.paragraphs.map((paragraph) => '<p>' + learnInline(paragraph) + '</p>').join('');
  if (section.bullets) output += '<ul class="learn-bullets">' + section.bullets.map((item) => '<li>' + learnInline(item) + '</li>').join('') + '</ul>';
  if (section.checklist) output += '<ul class="learn-checklist">' + section.checklist.map((item) => '<li><span aria-hidden="true">□</span><span>' + learnInline(item) + '</span></li>').join('') + '</ul>';
  if (section.commands) output += '<div class="learn-command-list">' + section.commands.map(learnCommandCard).join('') + '</div>';
  if (section.callout) output += '<aside class="learn-callout ' + esc(section.callout.kind || 'info') + '"><strong>' + esc(section.callout.title) + '</strong><p>' + learnInline(section.callout.text) + '</p></aside>';
  return output + '</section>';
}
function learnModuleCard(module, index) {
  const track = learnTrack(module.track);
  return '<a class="learn-module-card" href="/learn/' + esc(module.id) + '" data-module-card="' + esc(module.id) + '"><div class="learn-card-top"><span class="learn-index">' + String(index + 1).padStart(2, '0') + '</span><span class="learn-completion" data-module-completion>NOT STARTED</span></div><span class="kicker">' + esc(track?.title || module.track) + ' · ' + esc(module.minutes) + ' MIN</span><h3>' + esc(module.title) + '</h3><p>' + esc(module.objective) + '</p><span class="learn-card-link">OPEN MODULE <span aria-hidden="true">→</span></span></a>';
}
function learnTrackBlock(track) {
  const trackModules = learnModules.filter((module) => module.track === track.id);
  return '<section class="learn-track" id="track-' + esc(track.id) + '"><header><span class="learn-track-number">' + esc(track.number) + '</span><div><span class="kicker">LEARNING TRACK</span><h2>' + esc(track.title) + '</h2><p>' + esc(track.description) + '</p></div></header><div class="learn-track-grid">' + trackModules.map((module) => learnModuleCard(module, learnModules.indexOf(module))).join('') + '</div></section>';
}
function learnReferences(references) {
  return '<section class="learn-references" id="references"><span class="kicker">PRIMARY SOURCES</span><h2>Read further</h2><p>This material is condensed from primary documentation. Verify command behavior on the Ubuntu/Kali image you are using.</p><ul>' + references.map((reference) => '<li><a href="' + esc(reference.url) + '" target="_blank" rel="noopener noreferrer">' + esc(reference.title) + '<span aria-hidden="true">↗</span></a></li>').join('') + '</ul></section>';
}
function learnModuleNavigation(index) {
  const previous = learnModules[index - 1];
  const next = learnModules[index + 1];
  return '<nav class="learn-module-nav" aria-label="Module navigation">' + (previous ? '<a href="/learn/' + esc(previous.id) + '"><span>PREVIOUS</span><strong>← ' + esc(previous.title) + '</strong></a>' : '<a href="/learn"><span>OVERVIEW</span><strong>← Learning path</strong></a>') + (next ? '<a class="next" href="/learn/' + esc(next.id) + '"><span>NEXT</span><strong>' + esc(next.title) + ' →</strong></a>' : '<a class="next" href="/build"><span>CONTINUE</span><strong>Open Build →</strong></a>') + '</nav>';
}

app.get('/learn', requireAuth, (req, res) => {
  const totalMinutes = learnModules.reduce((sum, module) => sum + module.minutes, 0);
  let content = pageHead('LEARN / PRIVILEGE ESCALATION', 'Know the boundary', 'Week 4 material for building hypotheses, validating privilege boundaries, and producing safe evidence.');
  content += '<section class="learn-overview"><div><span class="kicker">AUTHORIZED LAB ONLY</span><h2>Think in evidence,<br>not command lists.</h2><p>Follow the learning path in order. Each module covers the concept, commands, output interpretation, common mistakes, and a checkpoint you should be able to answer.</p><div class="inline-actions"><a class="button primary" href="/learn/' + esc(learnModules[0].id) + '">START MODULE 01</a><a class="button ghost" href="#curriculum">VIEW CURRICULUM</a></div></div><div class="learn-overview-stats"><div><strong>' + esc(learnModules.length) + '</strong><span>MODULES</span></div><div><strong>' + esc(learnTracks.length) + '</strong><span>TRACKS</span></div><div><strong>±' + esc(totalMinutes) + '</strong><span>MINUTES</span></div></div></section>';
  content += '<figure class="learn-figure learn-overview-figure"><img src="/learn/pe-workflow.svg" alt="Evidence-based privilege-escalation workflow from scope to hardening." width="1200" height="340"><figcaption>The workflow used across every Week 4 module and challenge.</figcaption></figure>';
  content += '<div id="curriculum" class="learn-curriculum">' + learnTracks.map(learnTrackBlock).join('') + '</div>';
  content += '<section class="learn-source-note"><span class="kicker">RESEARCH BASIS</span><p>Built from Linux man-pages, GNU manuals, sudo, systemd, WireGuard, and MITRE ATT&amp;CK. The diagrams were created for LAS Week 4 and are stored locally.</p></section>';
  content += assignmentBrief();
  res.send(renderPage('Learn', content, req));
});
app.get('/learn/:module', requireAuth, (req, res) => {
  const module = learnModules.find((item) => item.id === req.params.module);
  if (!module) return res.status(404).send(renderPage('Not found', notice('Not found', 'Module not found.', 'bad'), req));
  const index = learnModules.indexOf(module);
  const track = learnTrack(module.track);
  const toc = module.sections.map((section) => '<a href="#' + esc(section.id) + '" data-toc-link="' + esc(section.id) + '">' + esc(section.title) + '</a>').join('');
  let content = '<div class="learn-reading-progress" aria-hidden="true"><span data-reading-progress></span></div>';
  content += '<div class="learn-module-shell" data-learn-module="' + esc(module.id) + '"><aside class="learn-sidebar"><a class="learn-back" href="/learn">← ALL MODULES</a><div class="learn-sidebar-meta"><span class="learn-index">' + String(index + 1).padStart(2, '0') + '</span><div><span class="kicker">' + esc(track?.title || module.track) + '</span><strong>' + esc(module.minutes) + ' min read</strong></div></div><nav aria-label="On this page"><span>ON THIS PAGE</span>' + toc + '<a href="#mistakes">Common mistakes</a><a href="#checkpoint">Checkpoint</a><a href="#references">Sources</a></nav></aside>';
  content += '<article class="learn-article"><header class="learn-module-hero"><span class="kicker">MODULE ' + String(index + 1).padStart(2, '0') + ' / ' + esc(track?.title || module.track) + '</span><h1>' + esc(module.title) + '</h1><p class="learn-objective">' + esc(module.objective) + '</p><p>' + esc(module.intro) + '</p><div class="learn-outcomes"><span>AFTER THIS MODULE</span><ul>' + module.outcomes.map((outcome) => '<li>' + esc(outcome) + '</li>').join('') + '</ul></div></header>';
  if (module.diagram) content += '<figure class="learn-figure"><img src="' + esc(module.diagram.src) + '" alt="' + esc(module.diagram.alt) + '" width="1200" height="420"><figcaption>' + esc(module.diagram.caption) + '</figcaption></figure>';
  content += module.sections.map(learnSection).join('');
  content += '<section class="learn-section learn-mistakes" id="mistakes" data-learn-section><header><span class="kicker">PATTERN CHECK</span><h2>Common mistakes</h2></header><ul class="learn-bullets">' + module.mistakes.map((mistake) => '<li>' + esc(mistake) + '</li>').join('') + '</ul></section>';
  content += '<section class="learn-checkpoint" id="checkpoint" data-learn-section><span class="kicker">MODULE CHECKPOINT</span><h2>' + esc(module.checkpoint.prompt) + '</h2><ol>' + module.checkpoint.tasks.map((task) => '<li>' + esc(task) + '</li>').join('') + '</ol><button class="button primary" type="button" data-mark-complete>MARK MODULE COMPLETE</button><p data-complete-status>Progress is stored in this browser.</p></section>';
  content += learnReferences(module.references) + learnModuleNavigation(index) + '</article></div>';
  res.send(renderPage(module.title, content, req));
});

app.get('/build', requireAuth, (req, res) => {
  const challenge = ownChallenge(req.user.id);
  const target = peerForUser(req.user.id, 'target');
  let content = pageHead('BUILD / OWN LAB', 'Your lab', 'One challenge per CaAs. Complete and validate it directly in the portal.');
  content += '<div class="stats">' + stat('Target', target?.assigned_ip || 'not assigned', target?.status || 'setup required') + stat('Challenge', challenge?.status || 'not started', challenge?.validation_status || 'not checked') + stat('Health', challenge?.health_status || 'unknown', challenge?.health_detail || 'IP-level status') + '</div>';
  if (req.user.isVisitor) content += notice('Read-only account', 'Visitor accounts can inspect the build area but cannot create or edit challenges.', 'info');
  else if (!target || target.status !== 'connected') content += notice('Target not connected', 'Complete target setup before opening the builder.', 'info');
  else if (!challenge) content += '<section class="empty"><h2>No draft yet</h2><p>Create your first challenge in the builder.</p><a class="button primary" href="/build/challenge">START BUILD</a></section>';
  else content += '<section class="card"><div class="step-top"><span class="kicker">CURRENT DRAFT</span>' + statusBadge(challenge.status) + '</div><h2>' + esc(challenge.title) + '</h2><p class="muted">' + esc(challenge.description) + '</p><div class="inline-actions"><a class="button primary" href="/build/challenge">EDIT BUILDER</a><form method="post" action="/build/challenge/recheck">' + csrfField(req) + formButton('RECHECK TARGET', 'ghost') + '</form></div></section>';
  content += '<a class="button back" href="/workspace">← BACK TO WORKSPACE</a>';
  res.send(renderPage('Build', content, req));
});
app.get('/build/challenge', requireAuth, (req, res) => {
  if (req.user.isVisitor) return res.status(403).send(renderPage('Builder unavailable', notice('Builder unavailable', 'Visitor accounts are read-only and cannot open the challenge editor.', 'info') + '<a class="button back" href="/build">← BACK TO BUILD</a>', req));
  const target = peerForUser(req.user.id, 'target');
  if (!target || target.status !== 'connected') return res.status(403).send(renderPage('Builder locked', notice('Builder locked', 'The target peer must be connected first.', 'info'), req));
  const challenge = ownChallenge(req.user.id);
  if (challenge?.status === 'approved') return res.status(403).send(renderPage('Approved lab', notice('Approved lab', 'Approved labs are read-only. Ask a mentor to return the lab for revisions.', 'info'), req));
  res.send(builderForm(req, challenge ? builderValues(req, challenge) : {}));
});
app.get('/build/challenge/preview', requireAuth, (req, res) => {
  const challenge = ownChallenge(req.user.id);
  const peer = peerForUser(req.user.id, 'target');
  if (!challenge || !peer) return res.status(404).send(renderPage('Preview unavailable', notice('Preview unavailable', 'Save a draft after target setup first.', 'bad'), req));
  res.send(playerPreview(req, challenge, peer));
});
app.post('/build/challenge/save', requireAuth, requireWriteAccess, requireCsrf, requireBuilderWrite, (req, res) => {
  const values = builderValues(req, ownChallenge(req.user.id));
  const result = saveChallenge(req, values);
  if (result.errors) return res.status(400).send(builderForm(req, values, result.errors));
  logEvent(req, 'challenge_saved', 'challenge', result.challenge.id, { status: 'draft' });
  res.redirect('/build');
});
app.post('/build/challenge/check', requireAuth, requireWriteAccess, requireCsrf, requireBuilderWrite, async (req, res) => {
  const values = builderValues(req, ownChallenge(req.user.id));
  const saved = saveChallenge(req, values);
  if (saved.errors) return res.status(400).send(builderForm(req, values, saved.errors));
  const result = await runLightCheck(saved.challenge, saved.peer);
  const items = result.ok ? ['Target IP reachable.', 'Declared fields valid.', 'Challenge is ready for mentor review.'] : result.failures;
  res.status(result.ok ? 200 : 400).send(builderForm(req, values, [], { ok: result.ok, title: result.ok ? 'LIGHT CHECK PASSED' : 'LIGHT CHECK FAILED', items }));
});
app.post('/build/challenge/submit', requireAuth, requireWriteAccess, requireCsrf, requireBuilderWrite, async (req, res) => {
  if (!isBefore(Date.now(), cfg.buildDeadlineAt)) return res.status(403).send(phaseError(req, 'Review queue closed', 'Challenges must be submitted before ' + formatWhen(cfg.buildDeadlineAt) + '.'));
  const values = builderValues(req, ownChallenge(req.user.id));
  const saved = saveChallenge(req, values);
  if (saved.errors) return res.status(400).send(builderForm(req, values, saved.errors));
  const check = await runLightCheck(saved.challenge, saved.peer);
  if (!check.ok) return res.status(400).send(builderForm(req, values, [], { ok: false, title: 'LIGHT CHECK FAILED', items: check.failures }));
  db.prepare("UPDATE challenges SET status='pending_review',validation_status='passed',updated_at=? WHERE id=? AND owner_user_id=?").run(nowIso(), saved.challenge.id, req.user.id);
  logEvent(req, 'challenge_submitted_for_review', 'challenge', saved.challenge.id);
  res.redirect('/build');
});
app.post('/build/challenge/recheck', requireAuth, requireWriteAccess, requireCsrf, async (req, res) => {
  const challenge = ownChallenge(req.user.id);
  const peer = peerForUser(req.user.id, 'target');
  if (!challenge || !peer) return res.redirect('/build');
  const result = await recordTargetHealth(challenge, peer, 'owner_recheck');
  logEvent(req, 'challenge_rechecked', 'challenge', challenge.id, { ok: result.probe.ok, throttled: result.throttled, health: result.decision.status });
  res.redirect('/build');
});
app.get('/build/validate', requireAuth, (req, res) => res.redirect('/build/challenge'));
app.get('/challenges/new', requireAuth, (req, res) => res.redirect('/build/challenge'));
app.get('/challenges/:id/edit', requireAuth, (req, res) => res.redirect('/build/challenge'));

function challengePublicCard(challenge, req) {
  const solverCount = db.prepare('SELECT COUNT(*) AS count FROM submissions WHERE challenge_id=? AND correct=1').get(challenge.id).count;
  const solved = Boolean(db.prepare('SELECT id FROM submissions WHERE user_id=? AND challenge_id=? AND correct=1').get(req.user.id, challenge.id));
  const own = challenge.owner_user_id === req.user.id;
  const cardState = solved ? ' is-solved' : own ? ' is-owned' : '';
  const stateBadge = solved ? statusBadge('solved') : own ? statusBadge('owned') : '';
  const actionClass = solved ? 'success' : own ? 'ghost' : 'primary';
  const actionLabel = solved ? '✓ SOLVED · VIEW LAB' : own ? 'VIEW YOUR LAB' : 'OPEN LAB';
  return '<article class="challenge-card' + cardState + '"><div class="step-top"><span class="kicker">LAB ' + String(challenge.id).padStart(2, '0') + '</span><div class="card-badges">' + stateBadge + statusBadge(challenge.health_status) + '</div></div><h2>' + esc(challenge.title) + '</h2><p>' + nl2br(challenge.description) + '</p><div class="challenge-meta"><span><small>TARGET</small><code>' + esc(challenge.target_ip) + '</code></span><span><small>SOLVERS</small><strong>' + esc(solverCount) + '</strong></span></div><a class="button ' + actionClass + ' small challenge-action" href="/lab-space/' + challenge.id + '">' + actionLabel + '</a></article>';
}
function scoreboardRows() {
  return db.prepare("SELECT id,caas_id FROM users WHERE role='participant' AND active=1 AND COALESCE(is_visitor,0)=0 AND COALESCE(is_test,0)=0 ORDER BY caas_id").all()
    .map((user) => ({ user, score: scoreForSolved(db.prepare('SELECT correct,first_blood,submitted_at FROM submissions WHERE user_id=?').all(user.id)) }))
    .sort((left, right) => {
      if (right.score.points !== left.score.points) return right.score.points - left.score.points;
      if (!left.score.firstReachedAt && !right.score.firstReachedAt) return left.user.caas_id.localeCompare(right.user.caas_id);
      if (!left.score.firstReachedAt) return 1;
      if (!right.score.firstReachedAt) return -1;
      const reached = String(left.score.firstReachedAt).localeCompare(String(right.score.firstReachedAt));
      return reached || left.user.caas_id.localeCompare(right.user.caas_id);
    });
}
app.get('/scoreboard', (req, res) => {
  const phase = currentPhase();
  const rows = scoreboardRows();
  let content = pageHead('SCOREBOARD / ' + phase, 'Leaderboard', 'Points are equal per challenge. First blood adds +10; ties use the earlier final total.');
  content += '<div class="scoreboard"><div class="score-row score-head"><span>RANK</span><span>CAAS ID</span><span>POINTS</span><span>SOLVED</span></div>';
  content += rows.length ? rows.map((row, index) => '<div class="score-row"><span class="rank">' + (index + 1) + '</span><strong>' + esc(row.user.caas_id) + '</strong><span>' + esc(row.score.points) + '</span><span>' + esc(row.score.solved) + '</span></div>').join('') : '<div class="empty"><h2>No scores yet</h2><p>Leaderboard will populate after approved labs go live.</p></div>';
  content += '</div><p class="score-note">Challenge solver identities are hidden. Each lab exposes only its solver count; this board shows participant scores for the event.</p>';
  res.send(renderPage('Scoreboard', content, req));
});
app.get('/lab-space', requireAuth, (req, res) => {
  const phase = currentPhase();
  let content = pageHead('LAB SPACE / PLAY', 'Find the boundary', 'Target IPs and services are available when the game goes live.');
  if (phase !== 'LIVE' && phase !== 'LOCKED') content += notice('Lab Space is not open', 'Opens at ' + formatWhen(cfg.portalOpenAt) + '.', 'info');
  else {
    const rows = db.prepare("SELECT * FROM challenges WHERE status IN ('approved','locked') AND health_status<>'disabled' ORDER BY id").all();
    content += rows.length ? '<div class="challenge-grid">' + rows.map((challenge) => challengePublicCard(challenge, req)).join('') + '</div>' : '<div class="empty"><h2>No labs yet</h2><p>Waiting for mentor approval.</p></div>';
  }
  content += '<a class="button back" href="/workspace">← BACK TO WORKSPACE</a>';
  res.send(renderPage('Lab Space', content, req));
});
app.get('/lab-space/:id', requireAuth, (req, res) => {
  const challenge = db.prepare("SELECT * FROM challenges WHERE id=? AND status IN ('approved','locked') AND health_status<>'disabled'").get(Number(req.params.id));
  if (!challenge || (currentPhase() !== 'LIVE' && currentPhase() !== 'LOCKED')) return res.status(404).send(renderPage('Not found', notice('Lab unavailable', 'This lab is not available.', 'bad'), req));
  const services = parseStoredServices(challenge.services);
  const solved = Boolean(db.prepare('SELECT id FROM submissions WHERE user_id=? AND challenge_id=? AND correct=1').get(req.user.id, challenge.id));
  const own = challenge.owner_user_id === req.user.id;
  let content = pageHead('LAB SPACE / LAB ' + String(challenge.id).padStart(2, '0'), challenge.title, 'Solver and owner identities are hidden.');
  content += '<div class="lab-detail-stack">';
  content += '<div class="target-banner"><span class="kicker">TARGET IP</span><strong>' + esc(challenge.target_ip) + '</strong><button type="button" class="copy-button inline" data-copy="' + esc(challenge.target_ip) + '">COPY IP</button>' + statusBadge(challenge.health_status) + '</div>';
  content += '<section class="card lab-card"><h2>Services</h2><div class="service-table">' + services.map((service) => '<div><code>' + esc(service.port + '/' + service.protocol) + '</code><strong>' + esc(service.label) + '</strong><span>' + esc(service.note || '') + '</span></div>').join('') + '</div></section>';
  content += '<section class="card lab-card"><h2>Challenge</h2><p>' + nl2br(challenge.description) + '</p><details><summary>INITIAL HINT</summary><p>' + nl2br(challenge.initial_hint) + '</p></details></section>';
  if (req.user.isVisitor) content += '<div class="callout"><strong>READ-ONLY VISITOR</strong><p>Visitor accounts can inspect labs but cannot submit flags or reports.</p></div>';
  else if (own) content += '<div class="callout danger"><strong>SELF-SOLVE BLOCKED</strong><p>Challenge owners cannot submit flags for their own lab.</p></div>';
  else if (currentPhase() === 'LOCKED') content += '<div class="notice compact"><strong>LOCKED</strong><p>Leaderboard and flag submissions are frozen.</p></div>';
  else if (solved) content += '<div class="notice compact good"><strong>SOLVED</strong><p>Your flag has already been recorded.</p></div>';
  content += '</div><div class="lab-detail-actions">';
  if (!req.user.isVisitor && !own && currentPhase() === 'LIVE' && !solved) content += '<form method="post" action="/lab-space/' + challenge.id + '/flag" class="flag-form">' + csrfField(req) + '<label>Submit flag<input name="flag" maxlength="120" autocomplete="off" placeholder="MBC{...}" required></label>' + formButton('SUBMIT FLAG') + '</form>';
  if (currentPhase() === 'LIVE' && !req.user.isVisitor) content += '<form method="post" action="/lab-space/' + challenge.id + '/report" class="report-form">' + csrfField(req) + formButton('REPORT UNREACHABLE', 'danger') + '</form>';
  content += '<a class="button back lab-back" href="/lab-space">← BACK TO LAB SPACE</a></div>';
  res.send(renderPage(challenge.title, content, req));
});
app.post('/lab-space/:id/flag', submitLimiter, requireAuth, requireWriteAccess, requireCsrf, requireLive, (req, res) => {
  const id = Number(req.params.id);
  const challenge = db.prepare("SELECT * FROM challenges WHERE id=? AND status='approved' AND health_status<>'disabled'").get(id);
  if (!challenge) return res.status(404).send(renderPage('Unavailable', notice('Unavailable', 'Challenge is not available.', 'bad'), req));
  if (challenge.owner_user_id === req.user.id) return res.status(403).send(renderPage('Self-solve blocked', notice('Self-solve blocked', 'You cannot solve your own challenge.', 'bad'), req));
  const flag = input(req, 'flag');
  if (!validFlag(flag)) return res.status(400).send(renderPage('Invalid flag', notice('Invalid flag', 'Use the case-sensitive MBC{...} format.', 'bad'), req));
  if (db.prepare('SELECT id FROM submissions WHERE user_id=? AND challenge_id=? AND correct=1').get(req.user.id, id)) return res.redirect('/lab-space/' + id);
  const correct = sameHash(challenge.flag_hash, sha256(flag));
  const firstBlood = withTransaction(() => {
    const first = correct && !db.prepare('SELECT id FROM submissions WHERE challenge_id=? AND correct=1 LIMIT 1').get(id);
    db.prepare('INSERT INTO submissions(user_id,challenge_id,submitted_flag_hash,correct,first_blood) VALUES(?,?,?,?,?)').run(req.user.id, id, sha256(flag), correct ? 1 : 0, first ? 1 : 0);
    return Boolean(first);
  });
  logEvent(req, correct ? 'flag_correct' : 'flag_incorrect', 'challenge', id, { firstBlood });
  res.status(correct ? 200 : 400).send(renderPage(correct ? 'Flag accepted' : 'Flag rejected', notice(correct ? 'Flag accepted' : 'Flag rejected', correct ? (firstBlood ? 'Correct. First blood +10. Total +110.' : 'Correct. +100 points.') : 'Not correct yet. Preserve your evidence chain and try again.', correct ? 'good' : 'bad'), req));
});
app.post('/lab-space/:id/report', submitLimiter, requireAuth, requireWriteAccess, requireCsrf, requireLive, async (req, res) => {
  const challenge = db.prepare("SELECT * FROM challenges WHERE id=? AND status='approved'").get(Number(req.params.id));
  if (!challenge) return res.status(404).send(renderPage('Unavailable', notice('Unavailable', 'Challenge is not available.', 'bad'), req));
  const recent = db.prepare('SELECT id FROM lab_issue_reports WHERE challenge_id=? AND reporter_id=? AND created_at>?').get(challenge.id, req.user.id, new Date(Date.now() - 10 * 60 * 1000).toISOString());
  if (recent) return res.redirect('/lab-space/' + challenge.id);
  const report = db.prepare("INSERT INTO lab_issue_reports(challenge_id,reporter_id,reason) VALUES(?,?, 'target_unreachable')").run(challenge.id, req.user.id);
  logEvent(req, 'challenge_issue_reported', 'challenge', challenge.id, { reportId: report.lastInsertRowid });
  const peer = peerForId(challenge.target_peer_id);
  const health = await recordTargetHealth(challenge, peer, 'solver_report');
  if (health.probe.ok) {
    db.prepare("UPDATE lab_issue_reports SET status='dismissed' WHERE id=? AND status='open'").run(report.lastInsertRowid);
  } else if (health.decision.status === 'degraded') {
    db.prepare("UPDATE lab_issue_reports SET status='confirmed' WHERE id=? AND status='open'").run(report.lastInsertRowid);
    logEvent(req, 'challenge_marked_degraded', 'challenge', challenge.id, { reason: health.decision.reason });
  }
  res.redirect('/lab-space/' + challenge.id);
});

app.get('/healthz', (req, res) => {
  res.set('Cache-Control', 'no-store').json({ ok: true, service: 'mbc-las-week4-portal', phase: currentPhase(), time: nowIso() });
});

app.use((req, res) => {
  if (!req.accepts('html')) return res.status(404).type('text/plain').send('NOT_FOUND');
  const destination = req.user ? '/workspace' : '/';
  const content = pageHead('PORTAL / 404', 'Page not found', 'The requested route does not exist or is no longer available.') + '<section class="empty"><h2>Return to a known route</h2><p>Use the portal navigation or return to the main workspace.</p><a class="button primary" href="' + destination + '">RETURN TO ' + (req.user ? 'WORKSPACE' : 'HOME') + '</a></section>';
  res.status(404).send(renderPage('Page not found', content, req));
});
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  console.error('Unhandled request error:', error?.message || 'unknown error');
  res.status(500).type('text/plain').send('INTERNAL_ERROR');
});

const httpServer = app.listen(cfg.port, cfg.bindHost, () => {
  const address = httpServer.address();
  const bound = typeof address === 'object' && address ? address.port : cfg.port;
  console.log('MBC LAS Week 4 portal listening on ' + cfg.bindHost + ':' + bound);
});
httpServer.on('error', (error) => {
  console.error('Unable to start portal:', error.message);
  process.exitCode = 1;
});
function shutdown() {
  httpServer.close(() => {
    try { db.close(); } catch {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
