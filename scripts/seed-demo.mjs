import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword, encryptSecret, sha256 } from '../src/security.mjs';
import { buildConfig } from '../src/config.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

// Load .env
const envFile = path.join(ROOT, '.env');
const env = {};
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (match) env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}

const cfg = buildConfig(env, ROOT);
const dbPath = path.join(cfg.dataDir, 'ctf-portal.db');
const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caas_id TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('participant','admin')) DEFAULT 'participant',
    is_visitor INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TEXT
  );
  CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    join_code TEXT NOT NULL UNIQUE,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'Misc',
    description TEXT NOT NULL,
    clue TEXT NOT NULL DEFAULT '',
    flag_hash TEXT NOT NULL,
    flag_encrypted TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 50,
    hint_penalty INTEGER NOT NULL DEFAULT 10,
    iso_download_url TEXT NOT NULL DEFAULT '',
    vm_specs TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('draft','published','locked')) DEFAULT 'draft',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    team_id INTEGER REFERENCES teams(id),
    challenge_id INTEGER NOT NULL REFERENCES challenges(id),
    submitted_flag_hash TEXT NOT NULL,
    correct INTEGER NOT NULL DEFAULT 0,
    first_blood INTEGER NOT NULL DEFAULT 0,
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS hint_unlocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    unlocked_by_user_id INTEGER NOT NULL REFERENCES users(id),
    unlocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(team_id, challenge_id)
  );
  CREATE TABLE IF NOT EXISTS event_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const cols = new Set(db.prepare('PRAGMA table_info(users)').all().map((r) => r.name));
if (!cols.has('team_id')) db.exec('ALTER TABLE users ADD COLUMN team_id INTEGER REFERENCES teams(id);');

console.log('Seeding ExamCorp CTF data into', dbPath);

// Clean up legacy challenges and placeholder users
db.prepare("DELETE FROM challenges WHERE title NOT IN ('User Flag', 'Root Flag')").run();
db.prepare("DELETE FROM users WHERE caas_id LIKE 'CAAS-%'").run();

// 1. Ensure Admin User
const adminPass = cfg.adminPassword || 'AdminPass1234!';
const existingAdmin = db.prepare('SELECT id FROM users WHERE caas_id=?').get(cfg.adminId);
let adminUserId;
if (!existingAdmin) {
  const res = db.prepare("INSERT INTO users(caas_id, password_hash, role) VALUES(?, ?, 'admin')").run(cfg.adminId, hashPassword(adminPass));
  adminUserId = res.lastInsertRowid;
  console.log(`Created admin user: ${cfg.adminId}`);
} else {
  adminUserId = existingAdmin.id;
}

// 2. Ensure Demo Participant Users
const demoUsers = [
  { id: 'PLAYER-01', pass: 'Password123456!' },
  { id: 'PLAYER-02', pass: 'Password123456!' },
  { id: 'PLAYER-03', pass: 'Password123456!' },
  { id: 'PLAYER-04', pass: 'Password123456!' },
  { id: 'PLAYER-05', pass: 'Password123456!' },
  { id: 'PLAYER-06', pass: 'Password123456!' },
];

const userIds = {};
for (const u of demoUsers) {
  const existing = db.prepare('SELECT id FROM users WHERE caas_id=?').get(u.id);
  if (!existing) {
    const res = db.prepare("INSERT INTO users(caas_id, password_hash, role) VALUES(?, ?, 'participant')").run(u.id, hashPassword(u.pass));
    userIds[u.id] = res.lastInsertRowid;
    console.log(`Created participant: ${u.id}`);
  } else {
    userIds[u.id] = existing.id;
  }
}

// 2b. Ensure Demo Invites for testing registration (/register)
const demoInvites = [
  { id: 'PLAYER-07', code: 'INVITE-CODE-PLAYER07' },
  { id: 'PLAYER-08', code: 'INVITE-CODE-PLAYER08' },
  { id: 'PLAYER-09', code: 'INVITE-CODE-PLAYER09' },
];
const expires30d = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
for (const inv of demoInvites) {
  db.prepare(`
    INSERT INTO invites (caas_id, code_hash, expires_at, used_at)
    VALUES (?, ?, ?, NULL)
    ON CONFLICT(caas_id) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, used_at=NULL
  `).run(inv.id, sha256(inv.code), expires30d);
  console.log(`Seeded activation invite for ${inv.id} (Code: ${inv.code})`);
}

// 3. ExamCorp CTF Challenges — 2 Challenges: User Flag and Root Flag
const VULN_VM_URL = cfg.vulnMachineUrl || 'https://drive.google.com/drive/folders/1VmJFkHvxpfF5WYlh1-3pttyZJUyviEXN';

const challenges = [
  // -----------------------------------------------------------------------
  // Challenge 1 — User Flag
  // -----------------------------------------------------------------------
  {
    title: 'User Flag',
    category: 'Initial Access & Lateral Movement',
    description:
      'Gunakan seluruh tahapan recon dan eksploitasi web untuk mendapatkan akses awal ke target ExamCorp.\n\n' +
      'Setelah berhasil menembus panel admin via SQL Injection dan mendapatkan webshell, lakukan enumerasi credential pada file konfigurasi internal (/var/www/html/db_config.php).\n\n' +
      'Gunakan credential tersebut untuk login interaktif melalui SSH sebagai `examuser` dan dapatkan user flag dari home directory (/home/examuser/user.txt).',
    iso_download_url: VULN_VM_URL,
    vm_specs: 'RAM: 2GB · Disk: 20GB · Arch: x86_64 · Mode: Host-Only',
    clue: 'Temukan file db_config.php melalui webshell. Password yang ditemukan pada file konfigurasi di-reuse untuk akun SSH examuser.',
    points: 50,
    hint_penalty: 10,
    flag: 'EH{user_flag_1}',
  },
  // -----------------------------------------------------------------------
  // Challenge 2 — Root Flag
  // -----------------------------------------------------------------------
  {
    title: 'Root Flag',
    category: 'Privilege Escalation',
    description:
      'Setelah berhasil memperoleh shell sebagai `examuser`, misimu belum selesai — kamu harus mendapatkan akses administrator penuh (root).\n\n' +
      'Lakukan audit izin sudo pada sistem. Manfaatkan binary dengan konfigurasi istimewa untuk mengeksekusi root shell (referensi: GTFOBins).\n\n' +
      'Baca flag akhir yang tersimpan di direktori root (/root/root.txt).',
    iso_download_url: VULN_VM_URL,
    vm_specs: 'RAM: 2GB · Disk: 20GB · Arch: x86_64 · Mode: Host-Only',
    clue: 'Jalankan `sudo -l` untuk mengidentifikasi binary yang diizinkan tanpa password. Cari teknik abuse untuk binary tersebut di GTFOBins.',
    points: 50,
    hint_penalty: 10,
    flag: 'EH{root_flag_congrats}',
  },
];

const challengeIds = [];
for (const c of challenges) {
  let existing = db.prepare('SELECT id FROM challenges WHERE title=?').get(c.title);
  if (!existing) {
    const flagHash = sha256(c.flag);
    const flagEnc = encryptSecret(c.flag, cfg.appKey);
    const res = db.prepare(`
      INSERT INTO challenges (
        title, category, description, clue, flag_hash, flag_encrypted,
        points, hint_penalty, iso_download_url, vm_specs, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')
    `).run(
      c.title, c.category, c.description, c.clue, flagHash, flagEnc,
      c.points, c.hint_penalty, c.iso_download_url, c.vm_specs
    );
    challengeIds.push(res.lastInsertRowid);
    console.log(`Created challenge: "${c.title}" [${c.category}]`);
  } else {
    db.prepare('UPDATE challenges SET points=?, hint_penalty=?, iso_download_url=?, vm_specs=? WHERE id=?').run(c.points, c.hint_penalty, c.iso_download_url, c.vm_specs, existing.id);
    challengeIds.push(existing.id);
  }
}

// 4. Ensure Demo Teams (3 to 5 members per team)
const demoTeams = [
  { name: 'CyberVanguard', code: 'TEAM-ALPHA1', captain: 'PLAYER-01', members: ['PLAYER-01', 'PLAYER-02', 'PLAYER-03'] },
  { name: 'ShadowBit',     code: 'TEAM-BRAVO2', captain: 'PLAYER-04', members: ['PLAYER-04', 'PLAYER-05', 'PLAYER-06'] },
];

const teamIds = {};
for (const t of demoTeams) {
  let existing = db.prepare('SELECT id FROM teams WHERE name=?').get(t.name);
  if (!existing) {
    const captainId = userIds[t.captain];
    const res = db.prepare('INSERT INTO teams (name, join_code, created_by) VALUES (?, ?, ?)').run(t.name, t.code, captainId);
    teamIds[t.name] = res.lastInsertRowid;
    console.log(`Created team "${t.name}" (Join Code: ${t.code})`);
  } else {
    teamIds[t.name] = existing.id;
  }
  for (const m of t.members) {
    db.prepare('UPDATE users SET team_id=? WHERE id=?').run(teamIds[t.name], userIds[m]);
  }
}

// 5. Seed demo submissions for realistic scoreboard
// Clean up submissions for challenges that no longer exist
db.prepare('DELETE FROM submissions WHERE challenge_id NOT IN (SELECT id FROM challenges)').run();
db.prepare('DELETE FROM hint_unlocks WHERE challenge_id NOT IN (SELECT id FROM challenges)').run();

const existingSubmissions = db.prepare('SELECT COUNT(*) AS count FROM submissions').get().count;
if (existingSubmissions === 0 && challengeIds.length >= 2) {
  // CyberVanguard — Ch1 user flag first blood
  db.prepare(`
    INSERT INTO submissions (user_id, team_id, challenge_id, submitted_flag_hash, correct, first_blood, submitted_at)
    VALUES (?, ?, ?, ?, 1, 1, '2026-10-25T11:10:00+07:00')
  `).run(userIds['PLAYER-01'], teamIds['CyberVanguard'], challengeIds[0], sha256('EH{user_flag_1}'));

  // ShadowBit — Ch1 user flag regular solve
  db.prepare(`
    INSERT INTO submissions (user_id, team_id, challenge_id, submitted_flag_hash, correct, first_blood, submitted_at)
    VALUES (?, ?, ?, ?, 1, 0, '2026-10-25T11:45:00+07:00')
  `).run(userIds['PLAYER-04'], teamIds['ShadowBit'], challengeIds[0], sha256('EH{user_flag_1}'));

  console.log('Seeded demo submissions for scoreboard.');
}

// Set portal to LIVE
db.prepare("INSERT INTO event_settings(key, value, updated_at) VALUES('forced_phase', 'LIVE', CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value='LIVE', updated_at=CURRENT_TIMESTAMP").run();

console.log('Done! ExamCorp CTF Portal seeded — 2 challenges (User Flag + Root Flag), 2 squads, scoreboard ready.');
