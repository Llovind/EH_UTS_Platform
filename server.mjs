import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
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
  validFlag,
} from './src/security.mjs';
import { eventPhase, isBefore } from './src/game.mjs';
import { buildConfig } from './src/config.mjs';
import { learnTracks, learnModules } from './src/learn-content.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------
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
if (cfg.production && !/^https:\/\//i.test(cfg.origin)) {
  console.error('APP_ORIGIN must use HTTPS in production.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Database bootstrap
// ---------------------------------------------------------------------------
fs.mkdirSync(cfg.dataDir, { recursive: true, mode: 0o700 });
try { fs.chmodSync(cfg.dataDir, 0o700); } catch {}
const db = new DatabaseSync(path.join(cfg.dataDir, 'ctf-portal.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');

db.exec(
  // -- Users --
  'CREATE TABLE IF NOT EXISTS users (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'caas_id TEXT NOT NULL UNIQUE,' +
  'password_hash TEXT NOT NULL,' +
  "role TEXT NOT NULL CHECK(role IN ('participant','admin')) DEFAULT 'participant'," +
  'is_visitor INTEGER NOT NULL DEFAULT 0,' +
  'active INTEGER NOT NULL DEFAULT 1,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'last_login_at TEXT' +
  ');' +

  // -- Invite codes --
  'CREATE TABLE IF NOT EXISTS invites (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'caas_id TEXT NOT NULL UNIQUE,' +
  'code_hash TEXT NOT NULL,' +
  'expires_at TEXT NOT NULL,' +
  'used_at TEXT,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +

  // -- Sessions --
  'CREATE TABLE IF NOT EXISTS sessions (' +
  'token_hash TEXT PRIMARY KEY,' +
  'user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,' +
  'csrf_token TEXT NOT NULL,' +
  'ip TEXT,' +
  'user_agent TEXT,' +
  'expires_at TEXT NOT NULL,' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +

  // -- Teams --
  'CREATE TABLE IF NOT EXISTS teams (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'name TEXT NOT NULL UNIQUE,' +
  'join_code TEXT NOT NULL UNIQUE,' +
  'created_by INTEGER NOT NULL REFERENCES users(id),' +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +

  // -- Challenges (admin-created) --
  'CREATE TABLE IF NOT EXISTS challenges (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'title TEXT NOT NULL,' +
  'category TEXT NOT NULL DEFAULT "Misc",' +
  'description TEXT NOT NULL,' +
  'clue TEXT NOT NULL DEFAULT "",' +
  'flag_hash TEXT NOT NULL,' +
  'flag_encrypted TEXT NOT NULL,' +
  'points INTEGER NOT NULL DEFAULT 50,' +
  'hint_penalty INTEGER NOT NULL DEFAULT 10,' +
  'iso_download_url TEXT NOT NULL DEFAULT "",' +
  'vm_specs TEXT NOT NULL DEFAULT "",' +
  "status TEXT NOT NULL CHECK(status IN ('draft','published','locked')) DEFAULT 'draft'," +
  'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +

  // -- Submissions --
  'CREATE TABLE IF NOT EXISTS submissions (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'user_id INTEGER NOT NULL REFERENCES users(id),' +
  'team_id INTEGER REFERENCES teams(id),' +
  'challenge_id INTEGER NOT NULL REFERENCES challenges(id),' +
  'submitted_flag_hash TEXT NOT NULL,' +
  'correct INTEGER NOT NULL DEFAULT 0,' +
  'first_blood INTEGER NOT NULL DEFAULT 0,' +
  'submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');' +

  // -- Hint unlocks (per team per challenge) --
  'CREATE TABLE IF NOT EXISTS hint_unlocks (' +
  'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
  'team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,' +
  'challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,' +
  'unlocked_by_user_id INTEGER NOT NULL REFERENCES users(id),' +
  'unlocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
  'UNIQUE(team_id, challenge_id)' +
  ');' +

  // -- Audit log --
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

  // -- Event settings --
  'CREATE TABLE IF NOT EXISTS event_settings (' +
  'key TEXT PRIMARY KEY,' +
  'value TEXT NOT NULL,' +
  'updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
  ');'
);

// Schema migrations (idempotent)
function tableColumns(table) {
  if (!/^[A-Za-z0-9_]+$/.test(table)) throw new Error('Invalid table name');
  return new Set(db.prepare('PRAGMA table_info(' + table + ')').all().map((row) => row.name));
}
function addColumn(table, name, definition) {
  if (!tableColumns(table).has(name)) db.exec('ALTER TABLE ' + table + ' ADD COLUMN ' + name + ' ' + definition);
}

addColumn('users', 'team_id', 'INTEGER REFERENCES teams(id)');
addColumn('users', 'is_visitor', 'INTEGER NOT NULL DEFAULT 0');

// Unique indexes
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS one_team_correct_solve ON submissions(team_id, challenge_id) WHERE correct = 1 AND team_id IS NOT NULL;');
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS one_user_correct_solo ON submissions(user_id, challenge_id) WHERE correct = 1 AND team_id IS NULL;');
db.exec('CREATE INDEX IF NOT EXISTS submissions_challenge_idx ON submissions(challenge_id, correct, submitted_at);');
db.exec('CREATE INDEX IF NOT EXISTS submissions_team_idx ON submissions(team_id, challenge_id);');
db.exec('CREATE INDEX IF NOT EXISTS users_team_idx ON users(team_id);');
db.exec('CREATE INDEX IF NOT EXISTS teams_code_idx ON teams(join_code);');
db.exec('CREATE INDEX IF NOT EXISTS hint_unlocks_team_idx ON hint_unlocks(team_id, challenge_id);');
db.exec('CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at);');

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
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
  const scheduled = eventPhase(Date.now(), cfg.portalOpenAt, cfg.portalOpenAt, cfg.gameLockAt);
  if (scheduled === 'LOCKED' || forced === 'LOCKED') return 'LOCKED';
  if (forced === 'LIVE') return 'LIVE';
  return scheduled;
}
function formatWhen(value) {
  return new Intl.DateTimeFormat('id-ID', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Jakarta' }).format(new Date(value)) + ' WIB';
}
function writeAudit(req, userId, action, targetType = null, targetId = null, details = null) {
  db.prepare('INSERT INTO audit_logs(user_id,action,target_type,target_id,ip,details) VALUES(?,?,?,?,?,?)').run(
    userId || null, action, targetType, targetId == null ? null : String(targetId), clientIp(req), details ? JSON.stringify(details) : null,
  );
}
function logEvent(req, action, targetType = null, targetId = null, details = null) {
  writeAudit(req, req.user?.id || null, action, targetType, targetId, details);
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------
function setSessionCookie(res, token, maxAge) {
  const parts = ['ctf_sid=' + encodeURIComponent(token), 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=' + Math.floor(maxAge / 1000)];
  if (cfg.production) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearSessionCookie(res) {
  const parts = ['ctf_sid=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (cfg.production) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function cookieValue(req, name) {
  const raw = req.headers.cookie?.split(';').map((v) => v.trim()).find((v) => v.startsWith(name + '='));
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
  const token = cookieValue(req, 'ctf_sid');
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(token));
  clearSessionCookie(req.res);
}
function attachSession(req, res, next) {
  req.session = null;
  req.user = null;
  const token = cookieValue(req, 'ctf_sid');
  if (token) {
    const row = db.prepare(
      'SELECT s.*,u.caas_id,u.role,u.active,u.is_visitor,u.team_id,t.name AS team_name ' +
      'FROM sessions s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN teams t ON t.id=u.team_id ' +
      'WHERE s.token_hash=? AND s.expires_at>?',
    ).get(sha256(token), nowIso());
    if (row && (row.user_id == null || row.active)) {
      req.session = row;
      if (row.user_id != null) {
        req.user = { id: row.user_id, caasId: row.caas_id, role: row.role, isVisitor: Boolean(row.is_visitor), teamId: row.team_id || null, teamName: row.team_name || null };
      }
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
function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}
function requireWriteAccess(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.isVisitor) return res.status(403).send(renderPage('Read-only account', notice('Read-only account', 'This visitor account can view the portal but cannot change data.', 'info'), req));
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(404).send(renderPage('Not found', notice('Not found', 'This resource does not exist.', 'bad'), req));
  next();
}
function requireLive(req, res, next) {
  if (currentPhase() !== 'LIVE') {
    const msg = currentPhase() === 'LOCKED' ? 'Flag submission and leaderboard are frozen.' : 'Game has not started yet. Opens at ' + formatWhen(cfg.portalOpenAt) + '.';
    return res.status(403).send(renderPage(currentPhase() === 'LOCKED' ? 'Game locked' : 'Game not started', notice(currentPhase() === 'LOCKED' ? 'Game locked' : 'Game not started', msg, 'info'), req));
  }
  next();
}
function confirmationMatches(req, expected) {
  return sameHash(input(req, 'confirmation').toUpperCase(), expected);
}

// ---------------------------------------------------------------------------
// HTML render helpers
// ---------------------------------------------------------------------------
function notice(title, body, kind = 'info') {
  return '<section class="notice ' + esc(kind) + '"><span class="kicker">STATUS</span><h1>' + esc(title) + '</h1><p>' + esc(body) + '</p></section>';
}
function statusBadge(value) {
  const safe = String(value || 'unknown').replace(/_/g, ' ');
  return '<span class="status ' + esc(value || 'unknown') + '">' + esc(safe) + '</span>';
}
function formButton(label, kind = 'primary') { return '<button class="button ' + kind + '" type="submit">' + esc(label) + '</button>'; }
function confirmationField(label, expected) {
  return '<label class="confirm-field">' + esc(label) + '<input name="confirmation" required maxlength="20" autocomplete="off" placeholder="Type ' + esc(expected) + '"></label>';
}
function commandBlock(value) {
  return '<pre class="command"><code>' + esc(value) + '</code><button type="button" class="copy-button" data-copy="' + esc(value) + '">COPY</button></pre>';
}
function stat(label, value, note = '') {
  return '<div class="stat"><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong>' + (note ? '<small>' + esc(note) + '</small>' : '') + '</div>';
}
function pageHead(kicker, title, subtitle = '') {
  return '<section class="page-head"><div><span class="kicker">' + esc(kicker) + '</span><h1>' + esc(title) + '</h1>' + (subtitle ? '<p class="muted">' + esc(subtitle) + '</p>' : '') + '</div></section>';
}
function renderPage(title, content, req) {
  const user = req.user;
  const currentPath = req.path;
  const navLink = (href, label, active) => '<a' + (active ? ' class="is-active" aria-current="page"' : '') + ' href="' + href + '">' + label + '</a>';
  const nav = user
    ? navLink('/team', user.teamName ? 'Team (' + esc(user.teamName) + ')' : 'Team', currentPath.startsWith('/team')) +
      navLink('/challenges', 'Challenges', currentPath.startsWith('/challenges')) +
      navLink('/scoreboard', 'Scoreboard', currentPath.startsWith('/scoreboard')) +
      navLink('/learn', 'Learn', currentPath.startsWith('/learn')) +
      (user.role === 'admin' ? navLink('/admin', 'Admin', currentPath.startsWith('/admin')) : '') +
      '<span class="account-chip"><span>' + (user.teamName ? esc(user.teamName) : 'ACCOUNT') + '</span><strong>' + esc(user.caasId) + '</strong></span>' +
      '<form class="nav-form" method="post" action="/logout">' + csrfField(req) + '<button type="submit">Sign out</button></form>'
    : navLink('/scoreboard', 'Scoreboard', currentPath.startsWith('/scoreboard')) +
      '<a class="nav-cta' + (currentPath === '/login' ? ' is-active' : '') + '" href="/login"' + (currentPath === '/login' ? ' aria-current="page"' : '') + '>Sign in</a>';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="description" content="CTF Portal - squad-based capture the flag challenge">' +
    '<title>' + esc(title) + ' · CTF Portal</title>' +
    '<link rel="icon" href="/logo.png"><link rel="stylesheet" href="/styles.css?v=20261014"><script src="/app.js?v=20261014" defer></script>' +
    '</head><body>' +
    '<a class="skip-link" href="#main-content">SKIP TO CONTENT</a>' +
    '<header class="site-header"><a class="brand" href="/"><img src="/logo.png" alt="CTF Portal"><span>CTF PORTAL</span></a>' +
    '<nav aria-label="Primary navigation">' + nav + '</nav></header>' +
    '<main class="shell" id="main-content">' + content + '</main>' +
    '<footer class="site-footer"><span>CTF PORTAL · ETHICAL HACKING</span><span>AUTHORIZED TRAINING NETWORK</span></footer>' +
    '</body></html>';
}

// ---------------------------------------------------------------------------
// Team helpers
// ---------------------------------------------------------------------------
const MAX_TEAM_MEMBERS = 5;

function teamForUser(userId) {
  return db.prepare('SELECT t.* FROM teams t JOIN users u ON u.team_id=t.id WHERE u.id=?').get(userId);
}
function teamMembers(teamId) {
  return db.prepare('SELECT id,caas_id,created_at FROM users WHERE team_id=? ORDER BY id ASC').all(teamId);
}
function teamById(teamId) {
  return db.prepare('SELECT * FROM teams WHERE id=?').get(Number(teamId));
}
function generateJoinCode() {
  for (let i = 0; i < 10; i += 1) {
    const code = 'TEAM-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const existing = db.prepare('SELECT id FROM teams WHERE join_code=?').get(code);
    if (!existing) return code;
  }
  return 'TEAM-' + Date.now().toString(36).toUpperCase();
}
function teamScore(teamId) {
  const solves = db.prepare(
    'SELECT s.correct, s.first_blood, s.team_id, s.challenge_id, c.points, c.hint_penalty, ' +
    '(SELECT COUNT(*) FROM hint_unlocks hu WHERE hu.team_id=s.team_id AND hu.challenge_id=s.challenge_id) AS hint_used ' +
    'FROM submissions s JOIN challenges c ON c.id=s.challenge_id ' +
    'WHERE s.team_id=? AND s.correct=1',
  ).all(teamId);
  return solves.reduce((sum, s) => {
    const base = s.points ?? 50;
    const penalty = s.hint_used ? (s.hint_penalty ?? 10) : 0;
    const bonus = s.first_blood ? 10 : 0;
    return sum + (base - penalty + bonus);
  }, 0);
}

// ---------------------------------------------------------------------------
// Challenge helpers
// ---------------------------------------------------------------------------
function publishedChallenges() {
  return db.prepare("SELECT * FROM challenges WHERE status IN ('published','locked') ORDER BY category, id").all();
}
function challengeById(id) {
  return db.prepare('SELECT * FROM challenges WHERE id=?').get(Number(id));
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
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

const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });
const authLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12,  standardHeaders: true, legacyHeaders: false });
const submitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 80,  standardHeaders: true, legacyHeaders: false });
const teamLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40,  standardHeaders: true, legacyHeaders: false });
const hintLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30,  standardHeaders: true, legacyHeaders: false });
app.use(generalLimiter);

// Bootstrap or sync admin account credentials from environment
const existingAdmin = db.prepare("SELECT id, caas_id FROM users WHERE role='admin' LIMIT 1").get();
if (!existingAdmin) {
  if (cfg.adminPassword) {
    db.prepare("INSERT INTO users(caas_id,password_hash,role) VALUES(?,?,'admin')").run(cfg.adminId, hashPassword(cfg.adminPassword));
  }
} else if (cfg.adminPassword) {
  db.prepare("UPDATE users SET caas_id=?, password_hash=?, active=1 WHERE id=?").run(cfg.adminId, hashPassword(cfg.adminPassword), existingAdmin.id);
}

// Auto-seed default challenges if challenges table is empty
const challengeCount = db.prepare("SELECT COUNT(*) AS count FROM challenges").get().count;
if (challengeCount === 0 && cfg.appKey) {
  const defaultChallenges = [
    {
      title: 'User Flag',
      category: 'Initial Access & Lateral Movement',
      description:
        'Gunakan seluruh tahapan recon dan eksploitasi web untuk mendapatkan akses awal ke target ExamCorp.\n\n' +
        'Setelah berhasil menembus panel admin via SQL Injection dan mendapatkan webshell, lakukan enumerasi credential pada file konfigurasi internal (/var/www/html/db_config.php).\n\n' +
        'Gunakan credential tersebut untuk login interaktif melalui SSH sebagai `examuser` dan dapatkan user flag dari home directory (/home/examuser/user.txt).',
      iso_download_url: cfg.vulnMachineUrl || 'https://drive.google.com/drive/folders/1VmJFkHvxpfF5WYlh1-3pttyZJUyviEXN',
      vm_specs: 'RAM: 2GB · Disk: 20GB · Arch: x86_64 · Mode: Host-Only',
      clue: 'Temukan file db_config.php melalui webshell. Password yang ditemukan pada file konfigurasi di-reuse untuk akun SSH examuser.',
      points: 50,
      hint_penalty: 10,
      flag: 'EH{user_flag_1}',
    },
    {
      title: 'Root Flag',
      category: 'Privilege Escalation',
      description:
        'Setelah berhasil memperoleh shell sebagai `examuser`, misimu belum selesai - kamu harus mendapatkan akses administrator penuh (root).\n\n' +
        'Lakukan audit izin sudo pada sistem. Manfaatkan binary dengan konfigurasi istimewa untuk mengeksekusi root shell (referensi: GTFOBins).\n\n' +
        'Baca flag akhir yang tersimpan di direktori root (/root/root.txt).',
      iso_download_url: cfg.vulnMachineUrl || 'https://drive.google.com/drive/folders/1VmJFkHvxpfF5WYlh1-3pttyZJUyviEXN',
      vm_specs: 'RAM: 2GB · Disk: 20GB · Arch: x86_64 · Mode: Host-Only',
      clue: 'Jalankan `sudo -l` untuk mengidentifikasi binary yang diizinkan tanpa password. Cari teknik abuse untuk binary tersebut di GTFOBins.',
      points: 50,
      hint_penalty: 10,
      flag: 'EH{root_flag_congrats}',
    },
  ];
  for (const c of defaultChallenges) {
    db.prepare(`
      INSERT INTO challenges (
        title, category, description, clue, flag_hash, flag_encrypted,
        points, hint_penalty, iso_download_url, vm_specs, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')
    `).run(
      c.title, c.category, c.description, c.clue, sha256(c.flag), encryptSecret(c.flag, cfg.appKey),
      c.points, c.hint_penalty, c.iso_download_url, c.vm_specs
    );
  }
}

// ---------------------------------------------------------------------------
// Public: Home
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  const phase = currentPhase();
  const count = db.prepare("SELECT COUNT(*) AS count FROM challenges WHERE status='published'").get().count;
  const content = '<section class="hero-compact">' +
    '<span class="kicker">ETHICAL HACKING / SQUAD CTF</span>' +
    '<h1>CTF PORTAL<br><em>HACK. FIND. PROVE.</em></h1>' +
    '<p>A squad-based Capture the Flag competition. Download the official vulnerable lab virtual machine, exploit privilege escalation boundaries, and submit flags with your squad.</p>' +
    '<div class="hero-actions">' +
    '<a class="button primary" href="' + (req.user ? '/workspace' : '/register') + '">' + (req.user ? 'OPEN WORKSPACE' : 'REGISTER / ENTER') + '</a>' +
    (!req.user ? '<a class="button ghost" href="/login">SIGN IN</a>' : '') +
    '<a class="button ghost" href="' + esc(cfg.vulnMachineUrl) + '" target="_blank" rel="noopener noreferrer">DOWNLOAD VULN LAB VM ↗</a>' +
    '<a class="button back" href="/scoreboard">SCOREBOARD</a></div>' +
    '<div class="hero-meta">' +
    '<span><strong>' + esc(phase) + '</strong><small>EVENT STATE</small></span>' +
    '<span><strong>' + esc(String(count)) + '</strong><small>CHALLENGES</small></span>' +
    '<span><strong>SQUADS</strong><small>3-5 PLAYERS</small></span>' +
    '</div></section>';
  res.send(renderPage('CTF Portal', content, req));
});

// ---------------------------------------------------------------------------
// Auth: Register (Open Registration + Squad Join Gating)
// ---------------------------------------------------------------------------
app.get('/register', (req, res) => {
  if (req.user) return res.redirect('/team');
  const content = pageHead('ACCOUNT / REGISTER', 'Create Account', 'Register your username to enter the CTF. You will join or create a squad in the next step.') +
    '<form method="post" action="/register" class="form-card">' + csrfField(req) +
    '<label>Username / Participant ID<input name="caas_id" autocomplete="username" maxlength="40" required placeholder="e.g. CYBER_WARRIOR" autofocus><small>3-40 characters (letters, numbers, underscore, hyphen).</small></label>' +
    '<label>Password<input name="password" type="password" autocomplete="new-password" minlength="8" required><small>Minimum 8 characters.</small></label>' +
    '<label>Confirm password<input name="password_confirm" type="password" autocomplete="new-password" minlength="8" required></label>' +
    formButton('CREATE ACCOUNT & CONTINUE') + '</form>' +
    '<p class="form-foot">Already registered? <a href="/login">Sign in</a></p>';
  res.send(renderPage('Create Account', content, req));
});
app.post('/register', authLimiter, requireCsrf, (req, res) => {
  const caasId   = normalizeId(input(req, 'caas_id'));
  const password = input(req, 'password');
  const confirm  = input(req, 'password_confirm');

  if (!/^[A-Z0-9][A-Z0-9_-]{2,39}$/.test(caasId)) {
    return res.status(400).send(renderPage('Registration failed', notice('Invalid Username', 'Username must be 3-40 characters (letters, numbers, underscores, hyphens).', 'bad'), req));
  }
  if (!password || password.length < 8) {
    return res.status(400).send(renderPage('Registration failed', notice('Weak Password', 'Password must be at least 8 characters long.', 'bad'), req));
  }
  if (password !== confirm) {
    return res.status(400).send(renderPage('Registration failed', notice('Password Mismatch', 'Password confirmation does not match.', 'bad'), req));
  }

  const existing = db.prepare('SELECT id FROM users WHERE caas_id=?').get(caasId);
  if (existing) {
    return res.status(400).send(renderPage('Registration failed', notice('Username Taken', 'This Username / Participant ID is already taken. Please choose another username.', 'bad'), req));
  }

  try {
    const info = db.prepare("INSERT INTO users(caas_id,password_hash,role) VALUES(?,?,'participant')").run(caasId, hashPassword(password));
    const userId = info.lastInsertRowid;
    clearSession(req);
    req.user = { id: userId, caasId, role: 'participant', isVisitor: false, teamId: null, teamName: null };
    createSession(req, userId);
    logEvent(req, 'account_registered', 'user', userId);
    res.redirect('/team');
  } catch {
    res.status(500).send(renderPage('Registration failed', notice('Error', 'Failed to register account. Please try again.', 'bad'), req));
  }
});

// ---------------------------------------------------------------------------
// Auth: Login / Logout
// ---------------------------------------------------------------------------
function loginForm(req, error = '', caasId = '') {
  const message = error ? '<div class="flash bad"><strong>Sign in failed</strong><p>' + esc(error) + '</p></div>' : '';
  return pageHead('ACCOUNT / SIGN IN', 'Sign in', 'Use your Participant ID and password.') + message +
    '<form method="post" action="/login" class="form-card">' + csrfField(req) +
    '<label>Participant ID<input name="caas_id" autocomplete="username" maxlength="40" required placeholder="PLAYER-01" value="' + esc(caasId) + '"></label>' +
    '<label>Password<input name="password" type="password" autocomplete="current-password" required></label>' +
    formButton('SIGN IN') + '</form><p class="form-foot">New to the CTF? <a href="/register">Create an account</a></p>';
}
app.get('/login', (req, res) => {
  if (req.user) return res.redirect(req.user.role === 'admin' ? '/admin' : '/workspace');
  res.send(renderPage('Sign in', loginForm(req), req));
});
app.post('/login', authLimiter, requireCsrf, (req, res) => {
  const caasId = normalizeId(input(req, 'caas_id'));
  const user   = db.prepare('SELECT * FROM users WHERE caas_id=? AND active=1').get(caasId);
  const ok     = Boolean(user && verifyPassword(input(req, 'password'), user.password_hash));
  if (!ok) {
    logEvent(req, 'login_failed', 'user', user?.id || null);
    return res.status(401).send(renderPage('Sign in', loginForm(req, 'The credentials are invalid.', caasId), req));
  }
  clearSession(req);
  const userTeam = user.team_id ? teamById(user.team_id) : null;
  req.user = { id: user.id, caasId: user.caas_id, role: user.role, isVisitor: Boolean(user.is_visitor), teamId: user.team_id || null, teamName: userTeam?.name || null };
  createSession(req, user.id);
  db.prepare('UPDATE users SET last_login_at=? WHERE id=?').run(nowIso(), user.id);
  logEvent(req, 'login_success', 'user', user.id);
  res.redirect(user.role === 'admin' ? '/admin' : '/workspace');
});
app.post('/logout', requireCsrf, (req, res) => {
  logEvent(req, 'logout');
  clearSession(req);
  res.redirect('/');
});

// ---------------------------------------------------------------------------
// Workspace (participant dashboard)
// ---------------------------------------------------------------------------
function stepCard(number, title, state, text, href) {
  return '<article class="step-card"><div class="step-number">' + esc(number) + '</div><div class="step-content"><div class="step-top"><span class="kicker">' + esc(title) + '</span>' + statusBadge(state) + '</div><p>' + esc(text) + '</p>' + (href ? '<a class="button primary small" href="' + esc(href) + '">OPEN</a>' : '') + '</div></article>';
}
app.get('/workspace', requireAuth, (req, res) => {
  const team    = teamForUser(req.user.id);
  const phase   = currentPhase();
  const myScore = team ? teamScore(team.id) : 0;
  const solvedCount = team ? db.prepare('SELECT COUNT(*) AS c FROM submissions WHERE team_id=? AND correct=1').get(team.id).c : 0;

  let content = pageHead('WORKSPACE / ' + esc(req.user.caasId), 'Participant Hub', 'Your CTF mission dashboard.');
  content += '<div class="stats">' +
    stat('Event Phase', phase, 'Contest status') +
    stat('Team', team ? esc(team.name) : 'No Team', team ? 'Squad active' : 'Join a squad (3-5 members)') +
    stat('Team Score', String(myScore) + ' PTS', solvedCount + ' challenges solved') +
    '</div>';
  content += '<section class="card vm-card" style="margin-bottom:1.5rem;">' +
    '<div class="step-top"><span class="kicker">OFFICIAL VULNERABLE MACHINE</span><span class="status healthy">READY FOR DOWNLOAD</span></div>' +
    '<h2>Competition Lab VM (OVA/ISO)</h2>' +
    '<p class="muted">All CTF challenges run on this virtual machine. Import it into VMware Workstation or VirtualBox in Host-Only or NAT mode to begin attacking.</p>' +
    '<div class="inline-actions">' +
    '<a class="button primary" href="' + esc(cfg.vulnMachineUrl) + '" target="_blank" rel="noopener noreferrer">DOWNLOAD VM (GOOGLE DRIVE) ↗</a>' +
    '<a class="button ghost" href="/challenges">VIEW CHALLENGES →</a>' +
    '</div></section>';
  content += '<section class="step-list">' +
    stepCard('01', 'SQUAD / TEAM',    team ? 'ready' : 'required', team ? 'Your squad is active: ' + esc(team.name) + '. View roster & invite code.' : 'Create or join a team (3-5 members) to participate.', '/team') +
    stepCard('02', 'CHALLENGES',      phase === 'LIVE' || phase === 'LOCKED' ? phase.toLowerCase() : 'closed', 'Browse the CTF challenge catalog, inspect targets, and submit flags.', '/challenges') +
    stepCard('03', 'SCOREBOARD',      'live',  'Track live team rankings, solve counts, and first bloods.', '/scoreboard') +
    stepCard('04', 'LEARNING MODULES','ready', 'Access Linux privilege escalation training guides and research.', '/learn') +
    '</section>';
  content += '<section class="timeline"><span class="kicker">SCHEDULE</span>' +
    '<div><strong>PORTAL OPEN</strong><span>' + esc(formatWhen(cfg.portalOpenAt)) + '</span></div>' +
    '<div><strong>GAME LOCK</strong><span>' + esc(formatWhen(cfg.gameLockAt)) + '</span></div>' +
    '</section>';
  res.send(renderPage('Workspace', content, req));
});
app.get('/dashboard', requireAuth, (req, res) => res.redirect('/workspace'));

// ---------------------------------------------------------------------------
// Team management
// ---------------------------------------------------------------------------
app.get('/team', requireAuth, (req, res) => {
  const team = teamForUser(req.user.id);
  if (!team) {
    let content = pageHead('TEAM / SQUAD', 'Join or Create Team', 'Compete as a squad (3 to 5 members). Solve flags together to climb the team scoreboard.');
    content += '<div class="team-setup-grid">';
    content += '<section class="card"><span class="kicker">NEW SQUAD</span><h2>Create a Team</h2>';
    content += '<p class="muted">Become team captain. You will receive an invite code to share with teammates.</p>';
    content += '<form method="post" action="/team/create" class="form-card-stacked">' + csrfField(req);
    content += '<label>Team Name<input name="team_name" maxlength="30" required placeholder="e.g. CyberVanguard" autocomplete="off"><small>3-30 characters (letters, numbers, space, hyphens).</small></label>';
    content += formButton('CREATE TEAM', 'primary') + '</form></section>';
    content += '<section class="card"><span class="kicker">EXISTING SQUAD</span><h2>Join with Code</h2>';
    content += '<p class="muted">Enter the invite code provided by your team captain.</p>';
    content += '<form method="post" action="/team/join" class="form-card-stacked">' + csrfField(req);
    content += '<label>Team Invite Code<input name="join_code" maxlength="20" required placeholder="TEAM-XXXXXX" autocomplete="off" style="text-transform:uppercase;"><small>Format: TEAM-XXXXXX</small></label>';
    content += formButton('JOIN SQUAD', 'ghost') + '</form></section>';
    content += '</div>';
    return res.send(renderPage('Team Setup', content, req));
  }

  const members    = teamMembers(team.id);
  const solves     = db.prepare(
    'SELECT s.*, c.title AS challenge_title, c.category, c.points AS challenge_points, c.hint_penalty, u.caas_id AS solver_name, ' +
    '(SELECT COUNT(*) FROM hint_unlocks hu WHERE hu.team_id=s.team_id AND hu.challenge_id=s.challenge_id) AS hint_used ' +
    'FROM submissions s JOIN challenges c ON c.id=s.challenge_id JOIN users u ON u.id=s.user_id ' +
    'WHERE s.team_id=? AND s.correct=1 ORDER BY s.submitted_at DESC',
  ).all(team.id);
  const totalScore  = solves.reduce((sum, s) => {
    const base = s.challenge_points ?? 50;
    const penalty = s.hint_used ? (s.hint_penalty ?? 10) : 0;
    const bonus = s.first_blood ? 10 : 0;
    return sum + (base - penalty + bonus);
  }, 0);
  const memberCount = members.length;
  const capacityBadge = memberCount >= 5
    ? '<span class="status locked">FULL (5/5)</span>'
    : memberCount >= 3
      ? '<span class="status approved">READY (' + memberCount + '/5)</span>'
      : '<span class="status draft">FORMING (' + memberCount + '/5)</span>';

  let content = pageHead('TEAM / ' + esc(team.name), esc(team.name), 'Team Roster and Solves');
  content += '<div class="stats">' +
    stat('Team Score', String(totalScore) + ' PTS', solves.length + ' challenges solved') +
    stat('Roster', memberCount + ' / 5 Members', memberCount < 3 ? 'Recruit 3-5 members' : 'Valid squad size') +
    stat('Join Code', team.join_code, 'Share with teammates') +
    '</div>';
  content += '<div class="team-dashboard-grid">';

  // Roster card
  content += '<section class="card">';
  content += '<div class="step-top"><span class="kicker">SQUAD ROSTER</span>' + capacityBadge + '</div>';
  content += '<h2>Members (' + memberCount + ' of ' + MAX_TEAM_MEMBERS + ')</h2>';
  content += '<p class="muted">Share this invite code with your teammates:</p>';
  content += commandBlock(team.join_code);
  content += '<div class="team-member-list">';
  for (const m of members) {
    const isMe      = m.id === req.user.id;
    const isCaptain = m.id === team.created_by;
    content += '<div class="team-member-item">';
    content += '<div class="member-meta"><strong>' + esc(m.caas_id) + '</strong>' +
      (isMe      ? ' <span class="tag-pill tag-self">YOU</span>'         : '') +
      (isCaptain ? ' <span class="tag-pill tag-captain">CAPTAIN</span>' : ' <span class="tag-pill tag-member">MEMBER</span>') +
      '</div>';
    content += '<span class="muted"><small>Joined ' + formatWhen(m.created_at) + '</small></span>';
    content += '</div>';
  }
  content += '</div>';
  content += '<div class="team-danger-zone">';
  content += '<form method="post" action="/team/leave" onsubmit="return confirm(\'Are you sure you want to leave this team?\');">' + csrfField(req);
  content += '<button type="submit" class="button danger small">LEAVE TEAM</button></form>';
  content += '</div></section>';

  // Solves card
  content += '<section class="card"><span class="kicker">TEAM SOLVES</span><h2>Completed Challenges (' + solves.length + ')</h2>';
  if (solves.length === 0) {
    content += '<div class="empty"><h3>No Solves Yet</h3><p>Head to <a href="/challenges">Challenges</a> to start submitting flags.</p></div>';
  } else {
    content += '<div class="team-solves-list">';
    for (const s of solves) {
      const base    = s.challenge_points ?? 50;
      const penalty = s.hint_used ? (s.hint_penalty ?? 10) : 0;
      const bonus   = s.first_blood ? 10 : 0;
      const pts     = base - penalty + bonus;
      content += '<div class="team-solve-item">';
      content += '<div><strong>' + esc(s.challenge_title) + '</strong> <small class="muted">by ' + esc(s.solver_name) + '</small></div>';
      content += '<div class="solve-points"><strong>+' + pts + ' PTS</strong>' +
        (s.first_blood ? ' <span class="tag-pill tag-blood">FIRST BLOOD</span>' : '') +
        (s.hint_used   ? ' <span class="tag-pill tag-penalty">HINT USED</span>' : '') +
        '</div></div>';
    }
    content += '</div>';
  }
  content += '</section>';
  content += '</div>';
  res.send(renderPage('Team ' + team.name, content, req));
});

app.post('/team/create', teamLimiter, requireAuth, requireWriteAccess, requireCsrf, (req, res) => {
  if (req.user.teamId) return res.status(400).send(renderPage('Team Error', notice('Already In Team', 'Leave your current team first.', 'bad'), req));
  const rawName = input(req, 'team_name');
  if (rawName.length < 3 || rawName.length > 30 || !/^[A-Za-z0-9 _-]{3,30}$/.test(rawName)) {
    return res.status(400).send(renderPage('Team Error', notice('Invalid Name', 'Team name must be 3-30 characters (alphanumeric, spaces, hyphens, underscores).', 'bad'), req));
  }
  if (db.prepare('SELECT id FROM teams WHERE LOWER(name)=LOWER(?)').get(rawName)) {
    return res.status(400).send(renderPage('Team Error', notice('Name Taken', 'That team name is already taken.', 'bad'), req));
  }
  const joinCode = generateJoinCode();
  try {
    withTransaction(() => {
      const result = db.prepare('INSERT INTO teams(name, join_code, created_by) VALUES(?, ?, ?)').run(rawName, joinCode, req.user.id);
      db.prepare('UPDATE users SET team_id=? WHERE id=?').run(result.lastInsertRowid, req.user.id);
    });
    logEvent(req, 'team_created', 'team', rawName, { joinCode });
    res.redirect('/team');
  } catch {
    res.status(500).send(renderPage('Team Error', notice('Error', 'Failed to create team. Please try again.', 'bad'), req));
  }
});

app.post('/team/join', teamLimiter, requireAuth, requireWriteAccess, requireCsrf, (req, res) => {
  if (req.user.teamId) return res.status(400).send(renderPage('Team Error', notice('Already In Team', 'Leave your current team first.', 'bad'), req));
  const rawCode = input(req, 'join_code').toUpperCase();
  if (!rawCode || rawCode.length < 5 || rawCode.length > 20) return res.status(400).send(renderPage('Team Error', notice('Invalid Code', 'Please enter a valid team invite code.', 'bad'), req));
  const team = db.prepare('SELECT * FROM teams WHERE UPPER(join_code)=?').get(rawCode);
  if (!team) return res.status(404).send(renderPage('Team Error', notice('Team Not Found', 'No team found with that invite code.', 'bad'), req));
  const memberCount = db.prepare('SELECT COUNT(*) AS count FROM users WHERE team_id=?').get(team.id).count;
  if (memberCount >= MAX_TEAM_MEMBERS) return res.status(400).send(renderPage('Team Full', notice('Team Full', 'This team is at maximum capacity (' + MAX_TEAM_MEMBERS + ' members).', 'bad'), req));
  try {
    withTransaction(() => { db.prepare('UPDATE users SET team_id=? WHERE id=?').run(team.id, req.user.id); });
    logEvent(req, 'team_joined', 'team', team.id, { memberCount: memberCount + 1 });
    res.redirect('/team');
  } catch {
    res.status(500).send(renderPage('Team Error', notice('Error', 'Failed to join team. Please try again.', 'bad'), req));
  }
});

app.post('/team/leave', teamLimiter, requireAuth, requireWriteAccess, requireCsrf, (req, res) => {
  if (!req.user.teamId) return res.redirect('/team');
  const teamId = req.user.teamId;
  const team   = teamById(teamId);
  if (!team) { db.prepare('UPDATE users SET team_id=NULL WHERE id=?').run(req.user.id); return res.redirect('/team'); }
  const members = db.prepare('SELECT id FROM users WHERE team_id=? ORDER BY id ASC').all(teamId);
  withTransaction(() => {
    db.prepare('UPDATE users SET team_id=NULL WHERE id=?').run(req.user.id);
    if (team.created_by === req.user.id) {
      const remaining = members.filter((m) => m.id !== req.user.id);
      if (remaining.length > 0) db.prepare('UPDATE teams SET created_by=? WHERE id=?').run(remaining[0].id, teamId);
      else db.prepare('DELETE FROM teams WHERE id=?').run(teamId);
    }
  });
  logEvent(req, 'team_left', 'team', teamId);
  res.redirect('/team');
});

// ---------------------------------------------------------------------------
// Challenges (CTF catalog)
// ---------------------------------------------------------------------------
app.get('/challenges', requireAuth, (req, res) => {
  const phase = currentPhase();
  let content = pageHead('CHALLENGES / CTF', 'Challenge Catalog', 'Download the vulnerable VM, find the flag, submit it here.');
  if (phase !== 'LIVE' && phase !== 'LOCKED') {
    content += notice('Challenges not yet open', 'Opens at ' + formatWhen(cfg.portalOpenAt) + '.', 'info');
    content += '<a class="button back" href="/workspace">← BACK TO WORKSPACE</a>';
    return res.send(renderPage('Challenges', content, req));
  }
  content += '<section class="card vm-card" style="margin-bottom:2rem;">' +
    '<div class="step-top"><span class="kicker">OFFICIAL COMPETITION LAB VM</span><span class="status healthy">READY FOR DOWNLOAD</span></div>' +
    '<h2>Vulnerable Virtual Machine (OVA/ISO)</h2>' +
    '<p class="muted">All CTF challenges are hosted inside the official vulnerable lab virtual machine. Download the machine image below, import into VMware Workstation or VirtualBox, and boot in Host-Only or NAT mode.</p>' +
    '<div class="inline-actions">' +
    '<a class="button primary" href="' + esc(cfg.vulnMachineUrl) + '" target="_blank" rel="noopener noreferrer">DOWNLOAD VULN VM (GOOGLE DRIVE) ↗</a>' +
    '</div></section>';
  const challs  = publishedChallenges();
  const teamId  = req.user.teamId;
  // Group by category
  const categories = [...new Set(challs.map((c) => c.category))];
  if (challs.length === 0) {
    content += '<div class="empty"><h2>No challenges yet</h2><p>The admin will publish challenges soon.</p></div>';
  } else {
    for (const cat of categories) {
      const group = challs.filter((c) => c.category === cat);
      content += '<section class="chall-category"><span class="kicker">CATEGORY</span><h2>' + esc(cat) + '</h2>';
      content += '<div class="challenge-grid">';
      for (const c of group) {
        const solved    = teamId
          ? Boolean(db.prepare('SELECT id FROM submissions WHERE team_id=? AND challenge_id=? AND correct=1').get(teamId, c.id))
          : false;
        const solverCnt = db.prepare('SELECT COUNT(*) AS n FROM submissions WHERE challenge_id=? AND correct=1').get(c.id).n;
        const hintUsed  = teamId
          ? Boolean(db.prepare('SELECT id FROM hint_unlocks WHERE team_id=? AND challenge_id=?').get(teamId, c.id))
          : false;
        content += '<article class="challenge-card' + (solved ? ' is-solved' : '') + '">';
        content += '<div class="step-top"><span class="kicker">' + esc(cat) + ' · ' + esc(String(c.points)) + ' PTS</span>' +
          (solved ? statusBadge('solved') : '') +
          (hintUsed ? '<span class="tag-pill tag-penalty">HINT USED</span>' : '') +
          '</div>';
        content += '<h2>' + esc(c.title) + '</h2>';
        content += '<p>' + nl2br(c.description.slice(0, 200)) + (c.description.length > 200 ? '…' : '') + '</p>';
        content += '<div class="challenge-meta"><span><small>SOLVERS</small><strong>' + esc(String(solverCnt)) + '</strong></span></div>';
        content += '<a class="button ' + (solved ? 'success' : 'primary') + ' small challenge-action" href="/challenges/' + c.id + '">' + (solved ? '✓ SOLVED · VIEW' : 'OPEN CHALLENGE') + '</a>';
        content += '</article>';
      }
      content += '</div></section>';
    }
  }
  content += '<a class="button back" href="/workspace">← BACK TO WORKSPACE</a>';
  res.send(renderPage('Challenges', content, req));
});

app.get('/challenges/:id', requireAuth, (req, res) => {
  const phase   = currentPhase();
  const chall   = challengeById(req.params.id);
  if (!chall || (chall.status !== 'published' && chall.status !== 'locked')) {
    return res.status(404).send(renderPage('Not found', notice('Not found', 'Challenge not found or not yet published.', 'bad'), req));
  }
  if (phase !== 'LIVE' && phase !== 'LOCKED') {
    return res.status(403).send(renderPage('Challenges closed', notice('Challenges closed', 'Opens at ' + formatWhen(cfg.portalOpenAt) + '.', 'info'), req));
  }

  const teamId     = req.user.teamId;
  const solved     = teamId ? Boolean(db.prepare('SELECT id FROM submissions WHERE team_id=? AND challenge_id=? AND correct=1').get(teamId, chall.id)) : false;
  const hintRow    = teamId ? db.prepare('SELECT * FROM hint_unlocks WHERE team_id=? AND challenge_id=?').get(teamId, chall.id) : null;
  const hintUsed   = Boolean(hintRow);
  const solverCnt  = db.prepare('SELECT COUNT(*) AS n FROM submissions WHERE challenge_id=? AND correct=1').get(chall.id).n;
  const solvedByRow = teamId && solved ? db.prepare('SELECT s.*, u.caas_id AS solver_name FROM submissions s JOIN users u ON u.id=s.user_id WHERE s.team_id=? AND s.challenge_id=? AND s.correct=1').get(teamId, chall.id) : null;

  let content = pageHead('CHALLENGES / ' + esc(chall.category.toUpperCase()), chall.title, esc(chall.category) + ' · ' + String(chall.points) + ' pts');
  content += '<div class="lab-detail-stack">';

  // VM Download card
  const downloadUrl = chall.iso_download_url || cfg.vulnMachineUrl;
  if (downloadUrl || chall.vm_specs) {
    content += '<section class="card vm-card"><span class="kicker">VULNERABLE MACHINE</span><h2>Download &amp; Setup</h2>';
    if (chall.vm_specs) content += '<p class="muted">' + esc(chall.vm_specs) + '</p>';
    if (downloadUrl) {
      content += '<a class="button primary" href="' + esc(downloadUrl) + '" target="_blank" rel="noopener noreferrer">DOWNLOAD VM / OVA ↗</a>';
    }
    content += '</section>';
  }

  // Description card
  content += '<section class="card lab-card"><h2>Challenge Description</h2>';
  content += '<p>' + nl2br(chall.description) + '</p>';
  content += '<div class="challenge-meta"><span><small>CATEGORY</small><strong>' + esc(chall.category) + '</strong></span><span><small>POINTS</small><strong>' + esc(String(chall.points)) + '</strong></span><span><small>SOLVERS</small><strong>' + esc(String(solverCnt)) + '</strong></span></div>';
  content += '</section>';

  // Clue card (with point penalty)
  if (chall.clue) {
    content += '<section class="card lab-card">';
    if (hintUsed) {
      content += '<span class="kicker">HINT (UNLOCKED · -' + esc(String(chall.hint_penalty)) + ' PTS)</span>';
      content += '<p>' + nl2br(chall.clue) + '</p>';
    } else {
      content += '<span class="kicker">HINT AVAILABLE</span>';
      content += '<p class="muted">Unlocking this hint will deduct ' + esc(String(chall.hint_penalty)) + ' points from your team\'s score for this challenge.</p>';
      if (!req.user.isVisitor && teamId && phase === 'LIVE' && !solved) {
        content += '<form method="post" action="/challenges/' + chall.id + '/hint">' + csrfField(req) +
          '<button class="button ghost" type="submit" onclick="return confirm(\'Unlock hint and lose ' + chall.hint_penalty + ' pts?\')">UNLOCK HINT (-' + esc(String(chall.hint_penalty)) + ' PTS)</button></form>';
      }
    }
    content += '</section>';
  }

  // Status / flag submission
  content += '</div><div class="lab-detail-actions">';
  if (req.user.isVisitor) {
    content += '<div class="callout"><strong>READ-ONLY VISITOR</strong><p>Visitor accounts cannot submit flags.</p></div>';
  } else if (!teamId) {
    content += '<div class="callout"><strong>TEAM REQUIRED</strong><p><a href="/team">Join or create a team</a> before submitting flags.</p></div>';
  } else if (phase === 'LOCKED') {
    content += '<div class="notice compact"><strong>LOCKED</strong><p>Flag submission is frozen.</p></div>';
  } else if (solved) {
    content += '<div class="notice compact good"><strong>SOLVED</strong><p>Solved by <strong>' + esc(solvedByRow?.solver_name || '-') + '</strong>' + (solvedByRow ? ' on ' + esc(formatWhen(solvedByRow.submitted_at)) : '') + '.</p></div>';
  } else if (phase === 'LIVE') {
    content += '<section class="card flag-card">' +
      '<form method="post" action="/challenges/' + chall.id + '/flag" class="flag-submit-form">' + csrfField(req) +
      '<div class="flag-input-group">' +
      '<input type="text" name="flag" class="flag-input" maxlength="120" autocomplete="off" placeholder="Flag" required spellcheck="false">' +
      '<button type="submit" class="flag-submit-btn">Submit</button>' +
      '</div></form></section>';
  }
  content += '<a class="button back lab-back" href="/challenges">← BACK TO CHALLENGES</a></div>';
  res.send(renderPage(chall.title, content, req));
});

// Hint unlock
app.post('/challenges/:id/hint', hintLimiter, requireAuth, requireWriteAccess, requireCsrf, requireLive, (req, res) => {
  const chall = challengeById(req.params.id);
  if (!chall || (chall.status !== 'published' && chall.status !== 'locked')) return res.status(404).send(renderPage('Not found', notice('Not found', 'Challenge not found.', 'bad'), req));
  if (!req.user.teamId) return res.status(403).send(renderPage('Team Required', notice('Team Required', 'You must be in a team to unlock hints.', 'bad'), req));
  if (!chall.clue) return res.redirect('/challenges/' + chall.id);
  const already = db.prepare('SELECT id FROM hint_unlocks WHERE team_id=? AND challenge_id=?').get(req.user.teamId, chall.id);
  if (!already) {
    db.prepare('INSERT OR IGNORE INTO hint_unlocks(team_id,challenge_id,unlocked_by_user_id) VALUES(?,?,?)').run(req.user.teamId, chall.id, req.user.id);
    logEvent(req, 'hint_unlocked', 'challenge', chall.id, { teamId: req.user.teamId, penalty: chall.hint_penalty });
  }
  res.redirect('/challenges/' + chall.id);
});

// Flag submission
app.post('/challenges/:id/flag', submitLimiter, requireAuth, requireWriteAccess, requireCsrf, requireLive, (req, res) => {
  const id    = Number(req.params.id);
  const chall = db.prepare("SELECT * FROM challenges WHERE id=? AND status='published'").get(id);
  if (!chall) return res.status(404).send(renderPage('Unavailable', notice('Unavailable', 'Challenge is not available.', 'bad'), req));
  if (!req.user.teamId) return res.status(403).send(renderPage('Team Required', notice('Team Required', 'Join or create a team before submitting flags.', 'bad'), req));
  if (db.prepare('SELECT id FROM submissions WHERE team_id=? AND challenge_id=? AND correct=1').get(req.user.teamId, id)) return res.redirect('/challenges/' + id);
  const flag = input(req, 'flag');
  if (!validFlag(flag)) return res.status(400).send(renderPage('Invalid flag', notice('Invalid flag', 'Use the case-sensitive EH{...} format.', 'bad'), req));
  const correct     = sameHash(chall.flag_hash, sha256(flag));
  const hintUnlocked = Boolean(db.prepare('SELECT id FROM hint_unlocks WHERE team_id=? AND challenge_id=?').get(req.user.teamId, id));
  const basePoints  = chall.points ?? 50;
  const penalty     = hintUnlocked ? (chall.hint_penalty ?? 10) : 0;
  const firstBlood  = withTransaction(() => {
    const first = correct && !db.prepare('SELECT id FROM submissions WHERE challenge_id=? AND correct=1 LIMIT 1').get(id);
    db.prepare('INSERT INTO submissions(user_id,team_id,challenge_id,submitted_flag_hash,correct,first_blood) VALUES(?,?,?,?,?,?)').run(
      req.user.id, req.user.teamId, id, sha256(flag), correct ? 1 : 0, first ? 1 : 0,
    );
    return Boolean(first);
  });
  logEvent(req, correct ? 'flag_correct' : 'flag_incorrect', 'challenge', id, { firstBlood, teamId: req.user.teamId });
  const pointsAwarded = basePoints - penalty + (firstBlood ? 10 : 0);
  const msg = correct
    ? (firstBlood
        ? 'Correct! First blood bonus +10. Total awarded: ' + pointsAwarded + ' points to your team.'
        : 'Correct! ' + pointsAwarded + ' points awarded to your team.' + (penalty > 0 ? ' (Hint penalty -' + penalty + ' applied)' : ''))
    : 'Not correct yet. Keep analyzing and try again.';
  res.status(correct ? 200 : 400).send(renderPage(
    correct ? 'Flag accepted' : 'Flag rejected',
    notice(correct ? 'Flag accepted' : 'Flag rejected', msg, correct ? 'good' : 'bad') +
    '<a class="button back" href="/challenges/' + id + '">← BACK TO CHALLENGE</a>',
    req,
  ));
});

// ---------------------------------------------------------------------------
// Scoreboard (team-based)
// ---------------------------------------------------------------------------
function buildTeamScoreboard() {
  const teams = db.prepare('SELECT id, name FROM teams ORDER BY name').all();
  return teams.map((team) => {
    const score = teamScore(team.id);
    const solves = db.prepare('SELECT COUNT(*) AS n FROM submissions WHERE team_id=? AND correct=1').get(team.id).n;
    const lastSolve = db.prepare('SELECT submitted_at FROM submissions WHERE team_id=? AND correct=1 ORDER BY submitted_at DESC LIMIT 1').get(team.id)?.submitted_at || null;
    return { team, score, solves, lastSolve };
  }).sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (!a.lastSolve && !b.lastSolve) return a.team.name.localeCompare(b.team.name);
    if (!a.lastSolve) return 1;
    if (!b.lastSolve) return -1;
    return String(a.lastSolve).localeCompare(String(b.lastSolve));
  });
}

app.get('/scoreboard', (req, res) => {
  const phase = currentPhase();
  const rows  = buildTeamScoreboard();
  let content = pageHead('SCOREBOARD / ' + phase, 'Team Leaderboard', 'Points per challenge: base − hint penalty + first blood bonus (+10). Ties broken by earliest final score.');
  content += '<div class="scoreboard"><div class="score-row score-head"><span>RANK</span><span>TEAM</span><span>POINTS</span><span>SOLVED</span></div>';
  content += rows.length
    ? rows.map((row, index) =>
        '<div class="score-row' + (index === 0 ? ' score-first' : '') + '">' +
        '<span class="rank">' + (index + 1) + '</span>' +
        '<strong>' + esc(row.team.name) + '</strong>' +
        '<span>' + esc(String(row.score)) + '</span>' +
        '<span>' + esc(String(row.solves)) + '</span>' +
        '</div>',
      ).join('')
    : '<div class="empty"><h2>No scores yet</h2><p>Leaderboard populates once teams solve challenges.</p></div>';
  content += '</div><p class="score-note">Rankings are updated in real time. Flag submissions are frozen when the game locks.</p>';
  res.send(renderPage('Scoreboard', content, req));
});

// ---------------------------------------------------------------------------
// /lab-space redirect for old links
// ---------------------------------------------------------------------------
app.get('/lab-space', requireAuth, (req, res) => res.redirect('/challenges'));
app.get('/lab-space/:id', requireAuth, (req, res) => res.redirect('/challenges/' + req.params.id));

// ---------------------------------------------------------------------------
// Learn modules
// ---------------------------------------------------------------------------
function learnInline(value) {
  return esc(value || '').replace(/`([^`]+)`/g, '<code>$1</code>');
}
function learnTrackFn(trackId) {
  return learnTracks.find((t) => t.id === trackId);
}
function learnCommandCard(command) {
  let output = '<article class="learn-command-card"><div class="learn-command-head"><span class="kicker">SAFE COMMAND</span><h3>' + esc(command.label) + '</h3></div>';
  output += '<pre class="command"><code>' + esc(command.value) + '</code><button type="button" class="copy-button" data-copy="' + esc(command.value) + '">COPY</button></pre>';
  output += '<div class="learn-command-notes"><div><span>WHAT IT DOES</span><p>' + learnInline(command.explanation) + '</p></div><div><span>WHAT TO LOOK FOR</span><p>' + learnInline(command.lookFor) + '</p></div></div>';
  if (command.output) output += '<div class="learn-output"><span>EXAMPLE OUTPUT</span><pre><code>' + esc(command.output) + '</code></pre></div>';
  return output + '</article>';
}
function learnSection(section, index) {
  let output = '<section class="learn-section" id="' + esc(section.id) + '" data-learn-section><header><span class="kicker">' + String(index + 1).padStart(2, '0') + ' / SECTION</span><h2>' + esc(section.title) + '</h2></header>';
  if (section.paragraphs) output += section.paragraphs.map((p) => '<p>' + learnInline(p) + '</p>').join('');
  if (section.bullets) output += '<ul class="learn-bullets">' + section.bullets.map((item) => '<li>' + learnInline(item) + '</li>').join('') + '</ul>';
  if (section.checklist) output += '<ul class="learn-checklist">' + section.checklist.map((item) => '<li><span aria-hidden="true">□</span><span>' + learnInline(item) + '</span></li>').join('') + '</ul>';
  if (section.commands) output += '<div class="learn-command-list">' + section.commands.map(learnCommandCard).join('') + '</div>';
  if (section.callout) output += '<aside class="learn-callout ' + esc(section.callout.kind || 'info') + '"><strong>' + esc(section.callout.title) + '</strong><p>' + learnInline(section.callout.text) + '</p></aside>';
  return output + '</section>';
}
function learnModuleCard(module, index) {
  const track = learnTrackFn(module.track);
  return '<a class="learn-module-card" href="/learn/' + esc(module.id) + '" data-module-card="' + esc(module.id) + '"><div class="learn-card-top"><span class="learn-index">' + String(index + 1).padStart(2, '0') + '</span><span class="learn-completion" data-module-completion>NOT STARTED</span></div><span class="kicker">' + esc(track?.title || module.track) + ' · ' + esc(module.minutes) + ' MIN</span><h3>' + esc(module.title) + '</h3><p>' + esc(module.objective) + '</p><span class="learn-card-link">OPEN MODULE <span aria-hidden="true">→</span></span></a>';
}
function learnTrackBlock(track) {
  const trackModules = learnModules.filter((m) => m.track === track.id);
  return '<section class="learn-track" id="track-' + esc(track.id) + '"><header><span class="learn-track-number">' + esc(track.number) + '</span><div><span class="kicker">LEARNING TRACK</span><h2>' + esc(track.title) + '</h2><p>' + esc(track.description) + '</p></div></header><div class="learn-track-grid">' + trackModules.map((m) => learnModuleCard(m, learnModules.indexOf(m))).join('') + '</div></section>';
}
function learnReferences(references) {
  return '<section class="learn-references" id="references"><span class="kicker">PRIMARY SOURCES</span><h2>Read further</h2><p>This material is condensed from primary documentation. Verify command behavior on the image you are using.</p><ul>' + references.map((r) => '<li><a href="' + esc(r.url) + '" target="_blank" rel="noopener noreferrer">' + esc(r.title) + '<span aria-hidden="true">↗</span></a></li>').join('') + '</ul></section>';
}
function learnModuleNavigation(index) {
  const previous = learnModules[index - 1];
  const next     = learnModules[index + 1];
  return '<nav class="learn-module-nav" aria-label="Module navigation">' +
    (previous
      ? '<a href="/learn/' + esc(previous.id) + '"><span>PREVIOUS</span><strong>← ' + esc(previous.title) + '</strong></a>'
      : '<a href="/learn"><span>OVERVIEW</span><strong>← Learning path</strong></a>') +
    (next
      ? '<a class="next" href="/learn/' + esc(next.id) + '"><span>NEXT</span><strong>' + esc(next.title) + ' →</strong></a>'
      : '<a class="next" href="/challenges"><span>CONTINUE</span><strong>Open Challenges →</strong></a>') +
    '</nav>';
}
app.get('/learn', requireAuth, (req, res) => {
  const totalMinutes = learnModules.reduce((sum, m) => sum + m.minutes, 0);
  let content = pageHead('LEARN / ATTACK METHODOLOGY', 'From Recon to Root', 'Full-chain penetration testing curriculum matching the ExamCorp CTF challenge methodology.');
  content += '<section class="learn-overview"><div><span class="kicker">ATTACK CHAIN WALKTHROUGH</span><h2>Master the complete<br>penetration lifecycle.</h2><p>Follow the curriculum in order: Network Discovery, Service Enumeration, FTP Anonymous Access, SQL Injection Authentication Bypass, Webshell Command Execution, Lateral Movement, and Linux Sudo Privilege Escalation.</p><div class="inline-actions"><a class="button primary" href="/learn/' + esc(learnModules[0].id) + '">START MODULE 01</a><a class="button ghost" href="#curriculum">VIEW CURRICULUM</a></div></div><div class="learn-overview-stats"><div><strong>' + esc(learnModules.length) + '</strong><span>MODULES</span></div><div><strong>' + esc(learnTracks.length) + '</strong><span>TRACKS</span></div><div><strong>±' + esc(totalMinutes) + '</strong><span>MINUTES</span></div></div></section>';
  content += '<figure class="learn-figure learn-overview-figure"><img src="/learn/pe-workflow.svg" alt="Evidence-based privilege-escalation workflow from scope to hardening." width="1200" height="340"><figcaption>The workflow used across every module and challenge.</figcaption></figure>';
  content += '<div id="curriculum" class="learn-curriculum">' + learnTracks.map(learnTrackBlock).join('') + '</div>';
  content += '<section class="learn-source-note"><span class="kicker">CURRICULUM BASIS</span><p>Crafted around the ExamCorp CTF attack methodology, Linux man-pages, OWASP testing guides, and GTFOBins references.</p></section>';
  res.send(renderPage('Learn', content, req));
});
app.get('/learn/:module', requireAuth, (req, res) => {
  const module = learnModules.find((m) => m.id === req.params.module);
  if (!module) return res.status(404).send(renderPage('Not found', notice('Not found', 'Module not found.', 'bad'), req));
  const index = learnModules.indexOf(module);
  const track = learnTrackFn(module.track);
  const toc = module.sections.map((s) => '<a href="#' + esc(s.id) + '" data-toc-link="' + esc(s.id) + '">' + esc(s.title) + '</a>').join('');
  let content = '<div class="learn-reading-progress" aria-hidden="true"><span data-reading-progress></span></div>';
  content += '<div class="learn-module-shell" data-learn-module="' + esc(module.id) + '"><aside class="learn-sidebar"><a class="learn-back" href="/learn">← ALL MODULES</a><div class="learn-sidebar-meta"><span class="learn-index">' + String(index + 1).padStart(2, '0') + '</span><div><span class="kicker">' + esc(track?.title || module.track) + '</span><strong>' + esc(module.minutes) + ' min read</strong></div></div><nav aria-label="On this page"><span>ON THIS PAGE</span>' + toc + '<a href="#mistakes">Common mistakes</a><a href="#checkpoint">Checkpoint</a><a href="#references">Sources</a></nav></aside>';
  content += '<article class="learn-article"><header class="learn-module-hero"><span class="kicker">MODULE ' + String(index + 1).padStart(2, '0') + ' / ' + esc(track?.title || module.track) + '</span><h1>' + esc(module.title) + '</h1><p class="learn-objective">' + esc(module.objective) + '</p><p>' + esc(module.intro) + '</p><div class="learn-outcomes"><span>AFTER THIS MODULE</span><ul>' + module.outcomes.map((o) => '<li>' + esc(o) + '</li>').join('') + '</ul></div></header>';
  if (module.diagram) content += '<figure class="learn-figure"><img src="' + esc(module.diagram.src) + '" alt="' + esc(module.diagram.alt) + '" width="1200" height="420"><figcaption>' + esc(module.diagram.caption) + '</figcaption></figure>';
  content += module.sections.map(learnSection).join('');
  content += '<section class="learn-section learn-mistakes" id="mistakes" data-learn-section><header><span class="kicker">PATTERN CHECK</span><h2>Common mistakes</h2></header><ul class="learn-bullets">' + module.mistakes.map((m) => '<li>' + esc(m) + '</li>').join('') + '</ul></section>';
  content += '<section class="learn-checkpoint" id="checkpoint" data-learn-section><span class="kicker">MODULE CHECKPOINT</span><h2>' + esc(module.checkpoint.prompt) + '</h2><ol>' + module.checkpoint.tasks.map((t) => '<li>' + esc(t) + '</li>').join('') + '</ol><button class="button primary" type="button" data-mark-complete>MARK MODULE COMPLETE</button><p data-complete-status>Progress is stored in this browser.</p></section>';
  content += learnReferences(module.references) + learnModuleNavigation(index) + '</article></div>';
  res.send(renderPage(module.title, content, req));
});

// ---------------------------------------------------------------------------
// Admin panel
// ---------------------------------------------------------------------------
app.get('/admin', requireAdmin, (req, res) => {
  const total    = db.prepare("SELECT COUNT(*) AS n FROM challenges").get().n;
  const published = db.prepare("SELECT COUNT(*) AS n FROM challenges WHERE status='published'").get().n;
  const teams    = db.prepare('SELECT COUNT(*) AS n FROM teams').get().n;
  const users    = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='participant'").get().n;
  const content  = pageHead('ADMIN / OPERATIONS', 'Admin Panel', 'Manage challenges, invites, teams, and event state.') +
    '<div class="stats">' +
    stat('Challenges', String(total), published + ' published') +
    stat('Teams', String(teams), 'registered squads') +
    stat('Participants', String(users), 'active accounts') +
    '</div>' +
    '<div class="admin-actions">' +
    '<a class="button primary" href="/admin/challenges">CHALLENGES</a>' +
    '<a class="button ghost" href="/admin/challenges/new">NEW CHALLENGE</a>' +
    '<a class="button ghost" href="/admin/invites">INVITES</a>' +
    '<a class="button ghost" href="/admin/event">EVENT CONTROLS</a>' +
    '<a class="button ghost" href="/admin/audit">AUDIT LOG</a>' +
    '</div>';
  res.send(renderPage('Admin', content, req));
});

// Admin: Challenge list
app.get('/admin/challenges', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM challenges ORDER BY id DESC').all();
  let content = pageHead('ADMIN / CHALLENGES', 'Challenge Manager', 'Create, edit, publish, and delete CTF challenges.');
  content += '<a class="button primary" href="/admin/challenges/new">+ NEW CHALLENGE</a>';
  content += rows.length
    ? '<div class="admin-list">' + rows.map((row) =>
        '<article class="admin-card">' +
        '<div class="step-top"><span class="kicker">#' + row.id + ' · ' + esc(row.category) + '</span>' + statusBadge(row.status) + '</div>' +
        '<h2>' + esc(row.title) + '</h2>' +
        '<div class="admin-grid"><span><small>POINTS</small><strong>' + esc(String(row.points)) + '</strong></span><span><small>HINT PENALTY</small><strong>-' + esc(String(row.hint_penalty)) + '</strong></span></div>' +
        '<div class="inline-actions">' +
        '<a class="button primary small" href="/admin/challenges/' + row.id + '/edit">EDIT</a>' +
        (row.status === 'draft' ? '<form method="post" action="/admin/challenges/' + row.id + '/publish" style="display:inline">' + csrfField(req) + '<button class="button ghost small" type="submit">PUBLISH</button></form>' : '') +
        (row.status === 'published' ? '<form method="post" action="/admin/challenges/' + row.id + '/unpublish" style="display:inline">' + csrfField(req) + '<button class="button ghost small" type="submit">UNPUBLISH</button></form>' : '') +
        '<form method="post" action="/admin/challenges/' + row.id + '/delete" style="display:inline" onsubmit="return confirm(\'Delete this challenge?\');">' + csrfField(req) + '<button class="button danger small" type="submit">DELETE</button></form>' +
        '</div></article>',
      ).join('') + '</div>'
    : '<div class="empty"><h2>No challenges yet</h2><p>Create the first challenge.</p></div>';
  content += '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Challenges', content, req));
});

// Admin: New challenge form
function challengeForm(req, values = {}, errors = []) {
  const isEdit = Boolean(values.id);
  const action = isEdit ? '/admin/challenges/' + values.id + '/edit' : '/admin/challenges/new';
  let body = pageHead(isEdit ? 'ADMIN / EDIT CHALLENGE' : 'ADMIN / NEW CHALLENGE', isEdit ? 'Edit Challenge' : 'New Challenge', 'All challenges are created by the admin and published when ready.');
  if (errors.length) body += '<div class="flash bad"><strong>Fix these issues:</strong><ul>' + errors.map((e) => '<li>' + esc(e) + '</li>').join('') + '</ul></div>';
  body += '<form method="post" action="' + action + '" class="builder-form">' + csrfField(req);
  body += '<fieldset><legend>BASIC INFO</legend>' +
    '<label>Title<input name="title" maxlength="100" required value="' + esc(values.title || '') + '" placeholder="Challenge title"></label>' +
    '<label>Category<input name="category" maxlength="40" required value="' + esc(values.category || 'Boot2Root') + '" placeholder="e.g. Boot2Root, Web, Crypto"></label>' +
    '<label>Points (max 100)<input name="points" type="number" min="1" max="100" required value="' + esc(String(values.points ?? 50)) + '"></label>' +
    '<label>Hint Penalty<input name="hint_penalty" type="number" min="0" max="50" required value="' + esc(String(values.hint_penalty ?? 10)) + '"></label>' +
    '</fieldset>';
  body += '<fieldset><legend>CONTENT</legend>' +
    '<label>Description (player-facing)<textarea name="description" maxlength="2000" required>' + esc(values.description || '') + '</textarea></label>' +
    '<label>Clue / Hint (optional, costs ' + esc(String(values.hint_penalty ?? 10)) + ' pts when unlocked)<textarea name="clue" maxlength="1000">' + esc(values.clue || '') + '</textarea></label>' +
    '</fieldset>';
  body += '<fieldset><legend>VULNERABLE MACHINE</legend>' +
    '<label>ISO / OVA Download URL<input name="iso_download_url" type="url" maxlength="500" value="' + esc(values.iso_download_url || cfg.vulnMachineUrl) + '" placeholder="' + esc(cfg.vulnMachineUrl) + '"></label>' +
    '<label>VM Specs / Notes<input name="vm_specs" maxlength="200" value="' + esc(values.vm_specs || 'RAM: 2GB · Disk: 20GB · Arch: x86_64 · Mode: Host-Only / NAT') + '" placeholder="e.g. Ubuntu 22.04, 1 vCPU, 2 GB RAM"></label>' +
    '</fieldset>';
  body += '<fieldset><legend>FLAG</legend>' +
    '<label>Flag (leave blank to keep current when editing)<input name="flag" maxlength="120" value="" placeholder="EH{...}"></label>' +
    '<p class="muted">The flag is hashed and encrypted at rest. It will never be shown in plaintext again after saving.</p>' +
    '</fieldset>';
  body += '<div class="form-actions"><div class="action-group action-group-primary">' + formButton(isEdit ? 'SAVE CHANGES' : 'CREATE CHALLENGE') + '</div>' +
    '<div class="action-group action-group-navigation"><a class="button back" href="/admin/challenges">← BACK TO CHALLENGES</a></div></div></form>';
  return renderPage(isEdit ? 'Edit Challenge' : 'New Challenge', body, req);
}
function validateChallengeForm(values, requireFlag) {
  const errors = [];
  if (!values.title || values.title.length < 2 || values.title.length > 100) errors.push('Title must be 2-100 characters.');
  if (!values.category || values.category.length < 2 || values.category.length > 40) errors.push('Category must be 2-40 characters.');
  if (!values.description || values.description.length < 10 || values.description.length > 2000) errors.push('Description must be 10-2000 characters.');
  if (values.clue && values.clue.length > 1000) errors.push('Clue must be 1000 characters or fewer.');
  const pts = Number(values.points);
  if (!Number.isInteger(pts) || pts < 1 || pts > 100) errors.push('Points must be 1-100.');
  const penalty = Number(values.hint_penalty);
  if (!Number.isInteger(penalty) || penalty < 0 || penalty > 50) errors.push('Hint penalty must be 0-50.');
  if (requireFlag && !validFlag(values.flag || '')) errors.push('Flag must use the case-sensitive EH{...} format.');
  if (!requireFlag && values.flag && !validFlag(values.flag)) errors.push('If providing a new flag, it must use the EH{...} format.');
  if (values.iso_download_url && values.iso_download_url.length > 500) errors.push('Download URL must be 500 characters or fewer.');
  return errors;
}

app.get('/admin/challenges/new', requireAdmin, (req, res) => {
  res.send(challengeForm(req));
});
app.post('/admin/challenges/new', requireAdmin, requireCsrf, (req, res) => {
  const values = {
    title: input(req, 'title'), category: input(req, 'category'), description: input(req, 'description'),
    clue: input(req, 'clue'), points: input(req, 'points'), hint_penalty: input(req, 'hint_penalty'),
    flag: input(req, 'flag'), iso_download_url: input(req, 'iso_download_url'), vm_specs: input(req, 'vm_specs'),
  };
  const errors = validateChallengeForm(values, true);
  if (errors.length) return res.status(400).send(challengeForm(req, values, errors));
  const flagHash = sha256(values.flag);
  const flagEnc  = encryptSecret(values.flag, cfg.appKey);
  const result = db.prepare(
    "INSERT INTO challenges(title,category,description,clue,points,hint_penalty,flag_hash,flag_encrypted,iso_download_url,vm_specs,status) VALUES(?,?,?,?,?,?,?,?,?,?,'draft')",
  ).run(values.title, values.category, values.description, values.clue, Number(values.points), Number(values.hint_penalty), flagHash, flagEnc, values.iso_download_url, values.vm_specs);
  logEvent(req, 'challenge_created', 'challenge', result.lastInsertRowid, { title: values.title });
  res.redirect('/admin/challenges/' + result.lastInsertRowid + '/edit');
});

app.get('/admin/challenges/:id/edit', requireAdmin, (req, res) => {
  const chall = challengeById(req.params.id);
  if (!chall) return res.status(404).send(renderPage('Not found', notice('Not found', 'Challenge not found.', 'bad'), req));
  res.send(challengeForm(req, { ...chall, flag: '' }));
});
app.post('/admin/challenges/:id/edit', requireAdmin, requireCsrf, (req, res) => {
  const chall = challengeById(req.params.id);
  if (!chall) return res.status(404).send(renderPage('Not found', notice('Not found', 'Challenge not found.', 'bad'), req));
  const values = {
    id: chall.id,
    title: input(req, 'title'), category: input(req, 'category'), description: input(req, 'description'),
    clue: input(req, 'clue'), points: input(req, 'points'), hint_penalty: input(req, 'hint_penalty'),
    flag: input(req, 'flag'), iso_download_url: input(req, 'iso_download_url'), vm_specs: input(req, 'vm_specs'),
  };
  const errors = validateChallengeForm(values, false);
  if (errors.length) return res.status(400).send(challengeForm(req, values, errors));
  const updateFlag = values.flag && validFlag(values.flag);
  if (updateFlag) {
    db.prepare('UPDATE challenges SET title=?,category=?,description=?,clue=?,points=?,hint_penalty=?,flag_hash=?,flag_encrypted=?,iso_download_url=?,vm_specs=?,updated_at=? WHERE id=?').run(
      values.title, values.category, values.description, values.clue, Number(values.points), Number(values.hint_penalty),
      sha256(values.flag), encryptSecret(values.flag, cfg.appKey), values.iso_download_url, values.vm_specs, nowIso(), chall.id,
    );
  } else {
    db.prepare('UPDATE challenges SET title=?,category=?,description=?,clue=?,points=?,hint_penalty=?,iso_download_url=?,vm_specs=?,updated_at=? WHERE id=?').run(
      values.title, values.category, values.description, values.clue, Number(values.points), Number(values.hint_penalty),
      values.iso_download_url, values.vm_specs, nowIso(), chall.id,
    );
  }
  logEvent(req, 'challenge_updated', 'challenge', chall.id, { title: values.title, flagUpdated: updateFlag });
  res.redirect('/admin/challenges');
});

app.post('/admin/challenges/:id/publish', requireAdmin, requireCsrf, (req, res) => {
  const chall = challengeById(req.params.id);
  if (!chall || chall.status !== 'draft') return res.redirect('/admin/challenges');
  db.prepare("UPDATE challenges SET status='published',updated_at=? WHERE id=?").run(nowIso(), chall.id);
  logEvent(req, 'challenge_published', 'challenge', chall.id);
  res.redirect('/admin/challenges');
});
app.post('/admin/challenges/:id/unpublish', requireAdmin, requireCsrf, (req, res) => {
  const chall = challengeById(req.params.id);
  if (!chall || chall.status !== 'published') return res.redirect('/admin/challenges');
  db.prepare("UPDATE challenges SET status='draft',updated_at=? WHERE id=?").run(nowIso(), chall.id);
  logEvent(req, 'challenge_unpublished', 'challenge', chall.id);
  res.redirect('/admin/challenges');
});
app.post('/admin/challenges/:id/delete', requireAdmin, requireCsrf, (req, res) => {
  const chall = challengeById(req.params.id);
  if (!chall) return res.redirect('/admin/challenges');
  withTransaction(() => {
    db.prepare('DELETE FROM hint_unlocks WHERE challenge_id=?').run(chall.id);
    db.prepare('DELETE FROM submissions WHERE challenge_id=?').run(chall.id);
    db.prepare('DELETE FROM challenges WHERE id=?').run(chall.id);
  });
  logEvent(req, 'challenge_deleted', 'challenge', chall.id, { title: chall.title });
  res.redirect('/admin/challenges');
});

// Admin: Invites
app.get('/admin/invites', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT i.*, u.id AS uid FROM invites i LEFT JOIN users u ON u.caas_id=i.caas_id ORDER BY i.id DESC LIMIT 100').all();
  let content = pageHead('ADMIN / INVITES', 'Invite Codes', 'Generate one-time activation codes for new participants.');
  content += '<form method="post" action="/admin/invites/new" class="form-card">' + csrfField(req) +
    '<label>Participant ID<input name="caas_id" maxlength="40" required placeholder="PLAYER-01"></label>' +
    '<label>Expires in (hours)<input name="hours" type="number" min="1" max="720" value="72"></label>' +
    formButton('GENERATE INVITE') + '</form>';
  content += rows.length
    ? '<div class="ops-table"><div class="ops-row ops-head"><span>PARTICIPANT ID</span><span>EXPIRES</span><span>USED</span><span>ACTIVATED</span></div>' +
      rows.map((row) =>
        '<div class="ops-row"><span><strong>' + esc(row.caas_id) + '</strong></span><span>' + esc(formatWhen(row.expires_at)) + '</span><span>' + (row.used_at ? esc(formatWhen(row.used_at)) : '-') + '</span><span>' + (row.uid ? '✓' : '✗') + '</span></div>',
      ).join('') + '</div>'
    : '<div class="empty"><h2>No invites</h2></div>';
  content += '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Invites', content, req));
});
app.post('/admin/invites/new', requireAdmin, requireCsrf, (req, res) => {
  const caasId = normalizeId(input(req, 'caas_id'));
  const hours  = Math.min(720, Math.max(1, Number(input(req, 'hours')) || 72));
  if (!/^[A-Z0-9][A-Z0-9_-]{2,39}$/.test(caasId)) return res.status(400).send(renderPage('Invite error', notice('Invalid Participant ID', 'Use alphanumeric characters, underscores, or hyphens (3-40 chars).', 'bad'), req));
  const code    = randomToken(16);
  const expires = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  try {
    db.prepare('INSERT INTO invites(caas_id,code_hash,expires_at) VALUES(?,?,?) ON CONFLICT(caas_id) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,used_at=NULL').run(caasId, sha256(code), expires);
    logEvent(req, 'invite_created', 'user', caasId, { hours });
    const content = notice('Invite created', 'One-time code for ' + caasId + ' (expires in ' + hours + ' h):', 'good') +
      '<div class="form-card" style="margin-top:1rem"><p><strong>Share this code with ' + esc(caasId) + ':</strong></p>' +
      '<pre class="command"><code>' + esc(code) + '</code><button type="button" class="copy-button" data-copy="' + esc(code) + '">COPY</button></pre>' +
      '<p class="muted">This code is shown only once. The participant uses it at /register.</p></div>' +
      '<a class="button ghost" href="/admin/invites">BACK TO INVITES</a>';
    return res.send(renderPage('Invite created', content, req));
  } catch {
    res.status(500).send(renderPage('Invite error', notice('Error', 'Failed to generate invite.', 'bad'), req));
  }
});

// Admin: Event controls
app.get('/admin/event', requireAdmin, (req, res) => {
  const forced  = setting('forced_phase') || 'AUTO';
  const phase   = currentPhase();
  let content = pageHead('ADMIN / EVENT', 'Event Controls', 'Force the game open or lock it. Lock is global and cannot be undone from the portal.');
  content += '<div class="stats">' + stat('Current Phase', phase, forced === 'AUTO' ? 'schedule' : 'forced: ' + forced) + stat('Portal Open', formatWhen(cfg.portalOpenAt), 'Challenge start') + stat('Game Lock', formatWhen(cfg.gameLockAt), 'submissions freeze') + '</div>';
  content += '<section class="card"><h2>Authority Actions</h2><div class="admin-actions">' +
    '<form method="post" action="/admin/event/open">' + csrfField(req) + confirmationField('Type OPEN', 'OPEN') + formButton('OPEN GAME') + '</form>' +
    '<form method="post" action="/admin/event/lock">' + csrfField(req) + confirmationField('Type LOCK', 'LOCK') + formButton('LOCK EVENT', 'danger') + '</form>' +
    '<form method="post" action="/admin/event/reset-scores">' + csrfField(req) + confirmationField('Type RESET', 'RESET') + formButton('RESET SUBMISSIONS', 'danger') + '</form>' +
    '</div></section>' +
    '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Event Controls', content, req));
});
app.post('/admin/event/open', requireAdmin, requireCsrf, (req, res) => {
  if (!confirmationMatches(req, 'OPEN')) return res.status(400).send(renderPage('Event Controls', notice('Confirmation required', 'Type OPEN to open the game.', 'bad'), req));
  if (setting('forced_phase') === 'LOCKED') return res.status(403).send(renderPage('Event Controls', notice('Event locked', 'The global lock is final.', 'bad'), req));
  setSetting('forced_phase', 'LIVE');
  logEvent(req, 'event_opened', 'event', 'forced_phase');
  res.redirect('/admin/event');
});
app.post('/admin/event/lock', requireAdmin, requireCsrf, (req, res) => {
  if (!confirmationMatches(req, 'LOCK')) return res.status(400).send(renderPage('Event Controls', notice('Confirmation required', 'Type LOCK to freeze the event.', 'bad'), req));
  setSetting('forced_phase', 'LOCKED');
  // Lock all published challenges
  db.prepare("UPDATE challenges SET status='locked',updated_at=? WHERE status='published'").run(nowIso());
  logEvent(req, 'event_locked', 'event', 'forced_phase');
  res.redirect('/admin/event');
});
app.post('/admin/event/reset-scores', requireAdmin, requireCsrf, (req, res) => {
  if (!confirmationMatches(req, 'RESET')) return res.status(400).send(renderPage('Event Controls', notice('Confirmation required', 'Type RESET to purge submissions and hint unlocks.', 'bad'), req));
  withTransaction(() => {
    db.prepare('DELETE FROM submissions').run();
    db.prepare('DELETE FROM hint_unlocks').run();
  });
  logEvent(req, 'scores_reset', 'event', 'submissions');
  res.redirect('/admin/event');
});

// Admin: Audit log
app.get('/admin/audit', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT a.*,u.caas_id FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200').all();
  logEvent(req, 'audit_viewed', 'audit', null, { rowCount: rows.length });
  let content = pageHead('ADMIN / AUDIT', 'Audit Trail', 'Recent security and event actions.');
  content += rows.length
    ? '<div class="audit-table"><div class="audit-row audit-head"><span>TIME</span><span>ACTOR</span><span>ACTION</span><span>TARGET</span><span>DETAIL</span></div>' +
      rows.map((row) =>
        '<div class="audit-row"><span>' + esc(row.created_at) + '</span><span>' + esc(row.caas_id || 'SYSTEM') + '</span><strong>' + esc(row.action) + '</strong><span>' + esc([row.target_type, row.target_id].filter(Boolean).join(' / ') || '-') + '</span><code>' + esc(row.details || '') + '</code></div>',
      ).join('') + '</div>'
    : '<div class="empty"><h2>No audit entries</h2></div>';
  content += '<a class="button back" href="/admin">← BACK TO ADMIN</a>';
  res.send(renderPage('Audit Trail', content, req));
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get('/healthz', (req, res) => {
  res.set('Cache-Control', 'no-store').json({ ok: true, service: 'ctf-portal', phase: currentPhase(), time: nowIso() });
});

// ---------------------------------------------------------------------------
// 404 / error handlers
// ---------------------------------------------------------------------------
app.use((req, res) => {
  if (!req.accepts('html')) return res.status(404).type('text/plain').send('NOT_FOUND');
  const destination = req.user ? '/workspace' : '/';
  const content = pageHead('PORTAL / 404', 'Page not found', 'The requested route does not exist.') +
    '<section class="empty"><h2>Return to a known route</h2><p>Use the navigation or return to the main page.</p><a class="button primary" href="' + destination + '">RETURN TO ' + (req.user ? 'WORKSPACE' : 'HOME') + '</a></section>';
  res.status(404).send(renderPage('Page not found', content, req));
});
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  console.error('Unhandled request error:', error?.message || 'unknown error');
  res.status(500).type('text/plain').send('INTERNAL_ERROR');
});

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------
const httpServer = app.listen(cfg.port, cfg.bindHost, () => {
  const address = httpServer.address();
  const bound = typeof address === 'object' && address ? address.port : cfg.port;
  console.log('CTF Portal listening on ' + cfg.bindHost + ':' + bound);
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
