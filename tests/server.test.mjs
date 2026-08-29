import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { hashPassword } from '../src/security.mjs';

const PORTAL_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = address.port;
      probe.close(() => resolve(port));
    });
  });
}

function startServer(dataDir, port, overrides = {}) {
  const env = {
    ...process.env,
    APP_KEY_BASE64: Buffer.alloc(32, 7).toString('base64'),
    APP_ORIGIN: 'http://127.0.0.1:' + port,
    APP_BIND_HOST: '127.0.0.1',
    DATA_DIR: dataDir,
    NODE_ENV: 'test',
    PORT: String(port),
    ADMIN_ID: 'MBC-ADMIN',
    ADMIN_PASSWORD: 'A-valid-admin-password-123',
    SKIP_NETWORK_CHECKS: 'true',
    TRUSTED_PROXY_IPS: '127.0.0.1,::1',
    WG_HELPER_PATH: path.join(dataDir, 'missing-helper'),
    ...overrides,
  };
  const child = spawn(process.execPath, ['server.mjs'], { cwd: PORTAL_DIR, env, stdio: ['ignore', 'pipe', 'pipe'] });
  const ready = new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('server did not start: ' + output)), 8000);
    const onData = (chunk) => {
      output += chunk.toString();
      if (output.includes('MBC LAS Week 4 portal listening')) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code) => {
      if (code !== null && !output.includes('MBC LAS Week 4 portal listening')) {
        clearTimeout(timer);
        reject(new Error('server exited before start: ' + output));
      }
    });
  });
  return { child, ready };
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 3000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
  });
}

function setCookies(response) {
  const values = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
  return values.filter(Boolean).map((value) => value.split(';', 1)[0]);
}

function sessionCookie(response) {
  const cookies = setCookies(response).filter((value) => value.startsWith('mbc_las_sid=') && value !== 'mbc_las_sid=');
  return cookies.at(-1) || '';
}

function csrfFrom(html) {
  const match = String(html).match(/name="_csrf" value="([^"]+)"/);
  assert.ok(match, 'page should include a CSRF token');
  return match[1];
}

function body(values) {
  return new URLSearchParams(values).toString();
}

function bodyEntries(entries) {
  const params = new URLSearchParams();
  for (const [key, value] of entries) params.append(key, value);
  return params.toString();
}

test('runnable setup surface exposes health, public installer, and enrollment security boundaries', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mbc-las-w4-server-'));
  const port = await freePort();
  const running = startServer(dataDir, port);
  t.after(async () => {
    await stopServer(running.child);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  await running.ready;

  const base = 'http://127.0.0.1:' + port;
  const health = await fetch(base + '/healthz');
  assert.equal(health.status, 200);
  assert.deepEqual((await health.json()).ok, true);
  const scoreboard = await fetch(base + '/scoreboard');
  assert.equal(scoreboard.status, 200);
  assert.match(await scoreboard.text(), /Leaderboard/);

  const installer = await fetch(base + '/setup/linux.sh');
  const installerText = await installer.text();
  assert.equal(installer.status, 200);
  assert.match(installerText, /^#!\/usr\/bin\/env bash/);
  assert.match(installerText, /TOKEN="\$\{1:-\}"/);
  assert.match(installerText, /PRIVATE_KEY=/);
  assert.match(installerText, /VERIFY_TLS=\(\)/);
  assert.match(installerText, /VERIFY_RESOLVE=\(--resolve/);
  assert.match(installerText, /10\.77\.4\.1/);
  assert.match(installerText, /\[INFO\]/);
  assert.match(installer.headers.get('content-disposition') || '', /mbc-las-w4-setup\.sh/);
  const appJs = await fetch(base + '/app.js');
  assert.equal(appJs.status, 200);
  assert.match(await appJs.text(), /api\/setup\/status/);

  const publicVerify = await fetch(base + '/internal/verify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: body({ nonce: 'forged' }) });
  assert.equal(publicVerify.status, 403);
  assert.deepEqual((await publicVerify.json()).code, 'WIREGUARD_ONLY');

  const registerPage = await fetch(base + '/register');
  const registerCookie = setCookies(registerPage).find((value) => value.startsWith('mbc_las_sid=')) || '';
  const registerCsrf = csrfFrom(await registerPage.text());
  const inviteCode = 'invite-code-001';
  const db = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  db.prepare('INSERT INTO invites(caas_id,code_hash,expires_at) VALUES(?,?,?)').run('CAAS-001', sha256(inviteCode), new Date(Date.now() + 60 * 60 * 1000).toISOString());
  db.close();

  const registration = await fetch(base + '/register', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: registerCookie },
    body: body({ _csrf: registerCsrf, caas_id: 'CAAS-001', activation_code: inviteCode, password: 'correct horse battery staple', password_confirm: 'correct horse battery staple' }),
  });
  assert.equal(registration.status, 302);
  const cookie = sessionCookie(registration);
  assert.ok(cookie.startsWith('mbc_las_sid='));

  const workspace = await fetch(base + '/workspace', { headers: { cookie } });
  const workspaceText = await workspace.text();
  assert.equal(workspace.status, 200);
  assert.match(workspaceText, /LAB CONFIGURATION/);
  assert.match(workspaceText, /SETUP ATTACKER/);
  assert.match(workspaceText, /BUILD YOUR LAB/);
  assert.ok(workspaceText.indexOf('LAB CONFIGURATION') < workspaceText.indexOf('SETUP ATTACKER'));
  assert.ok(workspaceText.indexOf('LAB CONFIGURATION') < workspaceText.indexOf('SETUP TARGET'));
  assert.ok(workspaceText.indexOf('SETUP TARGET') < workspaceText.indexOf('BUILD YOUR LAB'));
  assert.ok(workspaceText.indexOf('BUILD YOUR LAB') < workspaceText.indexOf('SETUP ATTACKER'));

  const setupOverview = await fetch(base + '/setup', { headers: { cookie } });
  const setupOverviewText = await setupOverview.text();
  assert.equal(setupOverview.status, 200);
  assert.ok(setupOverviewText.indexOf('LAB CONFIGURATION') < setupOverviewText.indexOf('TARGET'));
  assert.ok(setupOverviewText.indexOf('TARGET') < setupOverviewText.indexOf('ATTACKER'));

  const targetBeforeAttacker = await fetch(base + '/setup/target', { headers: { cookie } });
  assert.equal(targetBeforeAttacker.status, 200);
  assert.doesNotMatch(await targetBeforeAttacker.text(), /Complete attacker setup first|LOCKED/);

  const setupPage = await fetch(base + '/setup/attacker', { headers: { cookie } });
  const setupCsrf = csrfFrom(await setupPage.text());
  const tokenPage = await fetch(base + '/api/setup/attacker/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: body({ _csrf: setupCsrf }),
  });
  assert.equal(tokenPage.status, 200);
  const tokenMarkup = await tokenPage.text();
  const tokenMatch = tokenMarkup.match(/\/s\/([A-Za-z0-9_-]+)/);
  assert.ok(tokenMatch, 'setup page should contain one-time command token');
  const shortInstaller = await fetch(base + '/s/' + tokenMatch[1]);
  assert.equal(shortInstaller.status, 200);
  assert.match(await shortInstaller.text(), /setup\/linux\.sh/);

  const publicKey = 'A'.repeat(42) + 'A=';
  const enrolled = await fetch(base + '/api/enroll', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body({ token: tokenMatch[1], public_key: publicKey, client_os: 'linux', hostname: 'kali-test' }),
  });
  assert.equal(enrolled.status, 200);
  const enrolledText = await enrolled.text();
  assert.match(enrolledText, /MBC_STATUS=OK/);
  assert.match(enrolledText, /MBC_PEER_TYPE=attacker/);
  assert.doesNotMatch(enrolledText, /PRIVATE_KEY|private key/i);

  const replay = await fetch(base + '/api/enroll', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body({ token: tokenMatch[1], public_key: publicKey, client_os: 'linux', hostname: 'kali-test' }),
  });
  assert.equal(replay.status, 401);
  assert.equal(await replay.text(), 'TOKEN_USED');

  const status = await fetch(base + '/api/setup/status', { headers: { cookie } });
  assert.equal(status.status, 200);
  assert.equal(status.headers.get('cache-control'), 'no-store');
  assert.equal((await status.json()).attacker.status, 'enrolled');

  const setupAgain = await fetch(base + '/setup/attacker', { headers: { cookie } });
  const wrongPasswordRevoke = await fetch(base + '/api/setup/attacker/revoke', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: body({ _csrf: csrfFrom(await setupAgain.text()), current_password: 'wrong-password' }),
  });
  assert.equal(wrongPasswordRevoke.status, 403);

  const setupDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  const participant = setupDb.prepare('SELECT id FROM users WHERE caas_id=?').get('CAAS-001');
  setupDb.prepare("INSERT INTO wireguard_peers(user_id,peer_type,assigned_ip,status) VALUES(?, 'target', '10.77.4.100', 'connected')").run(participant.id);
  setupDb.close();

  const builderPage = await fetch(base + '/build/challenge', { headers: { cookie } });
  const builderPageText = await builderPage.text();
  assert.equal(builderPage.status, 200);
  const builderCsrf = csrfFrom(builderPageText);
  assert.doesNotMatch(builderPageText, /recovery|reset/i);
  assert.match(builderPageText, /MENTOR NOTES/);
  assert.doesNotMatch(builderPageText, /Learning objective|Initial foothold summary|Enumeration clue|Privilege-escalation technique|Flag location summary/);
  const learnPage = await fetch(base + '/learn', { headers: { cookie } });
  const learnText = await learnPage.text();
  assert.equal(learnPage.status, 200);
  assert.match(learnText, /WED 02 SEP/);
  assert.match(learnText, /FRI 04 SEP · 18:00 WIB/);
  assert.doesNotMatch(learnText, /credential recovery|reset notes/i);
  const builderEntries = [
    ['_csrf', builderCsrf], ['title', 'Quiet Backup'],
    ['description', 'A controlled Linux privilege escalation lab for evidence practice.'],
    ['mentor_notes', 'Enumerate the SUID binary, validate its input boundary, and use it to read the flag.'],
    ['flag', 'MBC{test_flag}'],
    ['service_port', '22'], ['service_protocol', 'tcp'], ['service_label', 'SSH'], ['service_note', 'Remote shell'],
    ['service_port', '80'], ['service_protocol', 'tcp'], ['service_label', 'HTTP'], ['service_note', 'Web clue'],
    ['service_port', '8080'], ['service_protocol', 'tcp'], ['service_label', 'App'], ['service_note', 'Challenge service'],
  ];
  const checked = await fetch(base + '/build/challenge/check', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie }, body: bodyEntries(builderEntries),
  });
  assert.equal(checked.status, 200);
  assert.match(await checked.text(), /LIGHT CHECK PASSED/);

  const preview = await fetch(base + '/build/challenge/preview', { headers: { cookie } });
  const previewText = await preview.text();
  assert.equal(preview.status, 200);
  assert.match(previewText, /Quiet Backup/);
  assert.doesNotMatch(previewText, /SUID|secret-path|test_flag/);
  assert.doesNotMatch(previewText, /REDACTION CHECK/);
  assert.match(previewText, /preview-stack/);

  const submitted = await fetch(base + '/build/challenge/submit', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie }, body: bodyEntries(builderEntries),
  });
  assert.equal(submitted.status, 302);
  const submittedDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  const savedChallenge = submittedDb.prepare('SELECT status,target_peer_id,owner_user_id,validation_status FROM challenges WHERE owner_user_id=?').get(participant.id);
  submittedDb.close();
  assert.deepEqual({ ...savedChallenge }, { status: 'pending_review', target_peer_id: 2, owner_user_id: participant.id, validation_status: 'passed' });
});

test('admin review is protected by WireGuard source and redacts flag material from review output', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mbc-las-w4-admin-'));
  const port = await freePort();
  const running = startServer(dataDir, port, {
    WG_CIDR: '127.0.0.0/8',
    WG_HUB_IP: '127.0.0.1',
    WG_ATTACKER_START: '127.0.0.10', WG_ATTACKER_END: '127.0.0.19',
    WG_TARGET_START: '127.0.0.100', WG_TARGET_END: '127.0.0.109',
  });
  t.after(async () => {
    await stopServer(running.child);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  await running.ready;
  const db = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  const owner = db.prepare("INSERT INTO users(caas_id,password_hash,role) VALUES(?,?, 'participant')").run('CAAS-REVIEW', hashPassword('correct horse battery staple')).lastInsertRowid;
  const target = db.prepare("INSERT INTO wireguard_peers(user_id,peer_type,assigned_ip,status) VALUES(?, 'target', '127.0.0.100', 'connected')").run(owner).lastInsertRowid;
  db.prepare("INSERT INTO challenges(owner_user_id,target_peer_id,title,target_ip,target_ports,services,description,initial_hint,learning_objective,initial_foothold_summary,enumeration_clue,pe_technique,intended_path,flag_location_summary,flag_hash,flag_encrypted,status,validation_status,health_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending_review','passed','healthy')").run(
    owner, target, 'Reviewable Lab', '127.0.0.100', '22/tcp', '[{"port":22,"protocol":"tcp","label":"SSH","note":"shell"}]', 'A review fixture with enough detail for the mentor.', 'Read the banner.', 'Evidence objective', 'Non-root shell.', 'Check permissions.', 'SUID', 'Follow the intended path.', 'Flag in controlled location.', 'hidden-flag-hash', 'hidden-encrypted',
  );
  db.close();

  const base = 'http://127.0.0.1:' + port;
  const loginPage = await fetch(base + '/login');
  const loginCookie = setCookies(loginPage).find((value) => value.startsWith('mbc_las_sid=')) || '';
  const loginCsrf = csrfFrom(await loginPage.text());
  const failedLogin = await fetch(base + '/login', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: loginCookie },
    body: body({ _csrf: loginCsrf, caas_id: 'MBC-ADMIN', password: 'wrong-password' }),
  });
  const failedLoginText = await failedLogin.text();
  assert.equal(failedLogin.status, 401);
  assert.match(failedLoginText, /<title>Sign in · MBC LAS W4<\/title>/);
  assert.match(failedLoginText, /The credentials are invalid\./);
  assert.doesNotMatch(failedLoginText, /wrong-password/);
  const login = await fetch(base + '/login', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: loginCookie },
    body: body({ _csrf: loginCsrf, caas_id: 'MBC-ADMIN', password: 'A-valid-admin-password-123' }),
  });
  assert.equal(login.status, 302);
  const adminCookie = sessionCookie(login);
  const loggedInLogin = await fetch(base + '/login', { redirect: 'manual', headers: { cookie: adminCookie } });
  assert.equal(loggedInLogin.status, 302);
  assert.equal(loggedInLogin.headers.get('location'), '/admin');
  const publicAdmin = await fetch(base + '/admin', { headers: { cookie: adminCookie, 'x-forwarded-for': '198.51.100.10' } });
  assert.equal(publicAdmin.status, 403);
  const tailscaleAdmin = await fetch(base + '/admin', { headers: { cookie: adminCookie, 'x-forwarded-for': '100.83.254.54' } });
  assert.equal(tailscaleAdmin.status, 200);
  assert.match(await tailscaleAdmin.text(), /href="\/learn"/);
  const adminPages = await Promise.all([
    fetch(base + '/admin/peers', { headers: { cookie: adminCookie } }),
    fetch(base + '/admin/health', { headers: { cookie: adminCookie } }),
    fetch(base + '/admin/event', { headers: { cookie: adminCookie } }),
    fetch(base + '/admin/audit', { headers: { cookie: adminCookie } }),
  ]);
  assert.deepEqual(adminPages.map((response) => response.status), [200, 200, 200, 200]);
  assert.match(await adminPages[0].text(), /CAAS-REVIEW/);
  assert.match(await adminPages[2].text(), /Event controls/);
  const review = await fetch(base + '/admin/review/1', { headers: { cookie: adminCookie } });
  const reviewText = await review.text();
  assert.equal(review.status, 200);
  assert.match(reviewText, /CAAS-REVIEW/);
  assert.match(reviewText, /Follow the intended path/);
  assert.doesNotMatch(reviewText, /hidden-flag-hash|hidden-encrypted/);
  const approveCsrf = csrfFrom(reviewText);
  const approved = await fetch(base + '/admin/review/1/approve', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: adminCookie },
    body: body({ _csrf: approveCsrf, reviewer_note: 'Approved in test.' }),
  });
  assert.equal(approved.status, 302);
  const resultDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  assert.equal(resultDb.prepare('SELECT status FROM challenges WHERE id=1').get().status, 'approved');
  resultDb.close();

  const reopenDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  reopenDb.prepare("UPDATE challenges SET status='pending_review',validation_status='passed',health_status='healthy' WHERE id=1").run();
  reopenDb.close();
  const reviewAgain = await fetch(base + '/admin/review/1', { headers: { cookie: adminCookie } });
  const returnCsrf = csrfFrom(await reviewAgain.text());
  const returned = await fetch(base + '/admin/review/1/return', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: adminCookie },
    body: body({ _csrf: returnCsrf, reviewer_note: 'Add a clearer evidence step.' }),
  });
  assert.equal(returned.status, 302);
  const returnedDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  assert.deepEqual({ ...returnedDb.prepare('SELECT status,validation_status FROM challenges WHERE id=1').get() }, { status: 'draft', validation_status: 'needs_revision' });
  returnedDb.close();

  const peersPage = await fetch(base + '/admin/peers', { headers: { cookie: adminCookie } });
  const revoked = await fetch(base + '/admin/peers/1/revoke', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: adminCookie },
    body: body({ _csrf: csrfFrom(await peersPage.text()), confirmation: 'REVOKE' }),
  });
  assert.equal(revoked.status, 302);
  const disabledReview = await fetch(base + '/admin/review/1', { headers: { cookie: adminCookie } });
  const disabled = await fetch(base + '/admin/challenges/1/disable', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: adminCookie },
    body: body({ _csrf: csrfFrom(await disabledReview.text()), confirmation: 'DISABLE', reason: 'Target requires repair.' }),
  });
  assert.equal(disabled.status, 302);
  const enableReview = await fetch(base + '/admin/review/1', { headers: { cookie: adminCookie } });
  const enabled = await fetch(base + '/admin/challenges/1/enable', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: adminCookie },
    body: body({ _csrf: csrfFrom(await enableReview.text()) }),
  });
  assert.equal(enabled.status, 302);
  const operationsDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  assert.deepEqual({ ...operationsDb.prepare('SELECT status,health_status FROM challenges WHERE id=1').get() }, { status: 'draft', health_status: 'unknown' });
  assert.equal(operationsDb.prepare('SELECT status FROM wireguard_peers WHERE id=1').get().status, 'revoked');
  operationsDb.close();

  const eventPage = await fetch(base + '/admin/event', { headers: { cookie: adminCookie } });
  const locked = await fetch(base + '/admin/event/lock', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: adminCookie },
    body: body({ _csrf: csrfFrom(await eventPage.text()), confirmation: 'LOCK' }),
  });
  assert.equal(locked.status, 302);
  const lockDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  assert.equal(lockDb.prepare('SELECT status FROM challenges WHERE id=1').get().status, 'locked');
  lockDb.close();
});

test('scheduled lock is authoritative and freezes challenge state even without an admin visit', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mbc-las-w4-lock-'));
  const port = await freePort();
  const running = startServer(dataDir, port, {
    BUILD_DEADLINE_AT: '2026-08-01T09:00:00+07:00',
    PORTAL_OPEN_AT: '2026-08-02T11:00:00+07:00',
    SUBMISSION_DEADLINE_AT: '2026-08-03T15:00:00+07:00',
    GAME_LOCK_AT: '2026-08-03T18:00:00+07:00',
  });
  t.after(async () => {
    await stopServer(running.child);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  await running.ready;
  const db = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  const owner = db.prepare("INSERT INTO users(caas_id,password_hash,role) VALUES(?,?, 'participant')").run('CAAS-LOCK', hashPassword('correct horse battery staple')).lastInsertRowid;
  db.prepare("INSERT INTO challenges(owner_user_id,title,target_ip,target_ports,services,description,initial_hint,flag_hash,flag_encrypted,status) VALUES(?,?,?,?,?,?,?,?,?,'approved')").run(owner, 'Lock Fixture', '10.77.4.100', '22/tcp', '[{"port":22}]', 'Fixture challenge for the scheduled event lock.', 'Read the banner.', 'flag-hash', 'flag-encrypted');
  db.close();
  const health = await fetch('http://127.0.0.1:' + port + '/healthz');
  assert.equal(health.status, 200);
  assert.equal((await health.json()).phase, 'LOCKED');
  const lockedDb = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  assert.equal(lockedDb.prepare('SELECT status FROM challenges WHERE title=?').get('Lock Fixture').status, 'locked');
  lockedDb.close();
});

test('visitor accounts are read-only, hidden from scoreboard, and cannot access admin', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mbc-las-w4-visitor-'));
  const port = await freePort();
  const running = startServer(dataDir, port);
  t.after(async () => {
    await stopServer(running.child);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  await running.ready;

  const db = new DatabaseSync(path.join(dataDir, 'las-week4.db'));
  db.prepare("INSERT INTO users(caas_id,password_hash,role,is_visitor,is_test) VALUES(?,?, 'participant',1,0)").run('MBC-VISITOR', hashPassword('CS#TrustBreaker2526'));
  db.prepare("INSERT INTO users(caas_id,password_hash,role,is_visitor,is_test) VALUES(?,?, 'participant',0,1)").run('TEST-CAAS-01', hashPassword('LASW4-Test1!2026'));
  db.close();

  const base = 'http://127.0.0.1:' + port;
  const loginPage = await fetch(base + '/login');
  const loginCookie = setCookies(loginPage).find((value) => value.startsWith('mbc_las_sid=')) || '';
  const loginCsrf = csrfFrom(await loginPage.text());
  const login = await fetch(base + '/login', {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: loginCookie },
    body: body({ _csrf: loginCsrf, caas_id: 'MBC-VISITOR', password: 'CS#TrustBreaker2526' }),
  });
  assert.equal(login.status, 302);
  assert.equal(login.headers.get('location'), '/workspace');
  const visitorCookie = sessionCookie(login);

  const workspace = await fetch(base + '/workspace', { headers: { cookie: visitorCookie } });
  const workspaceText = await workspace.text();
  assert.equal(workspace.status, 200);
  assert.match(workspaceText, /Learn/);
  assert.doesNotMatch(workspaceText, /href="\/admin"/);

  const learn = await fetch(base + '/learn', { headers: { cookie: visitorCookie } });
  assert.equal(learn.status, 200);
  assert.match(await learn.text(), /Week 4 scope/);

  const admin = await fetch(base + '/admin', { headers: { cookie: visitorCookie } });
  assert.equal(admin.status, 404);

  const setup = await fetch(base + '/setup/attacker', { headers: { cookie: visitorCookie } });
  const setupText = await setup.text();
  assert.equal(setup.status, 200);
  assert.match(setupText, /READ-ONLY/);
  assert.doesNotMatch(setupText, /GENERATE COMMAND/);
  const deniedSetup = await fetch(base + '/api/setup/attacker/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: visitorCookie }, body: '',
  });
  assert.equal(deniedSetup.status, 403);

  const scoreboard = await fetch(base + '/scoreboard');
  const scoreboardText = await scoreboard.text();
  assert.equal(scoreboard.status, 200);
  assert.doesNotMatch(scoreboardText, /MBC-VISITOR|TEST-CAAS-01/);
});
