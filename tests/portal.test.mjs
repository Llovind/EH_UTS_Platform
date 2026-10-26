import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

const ROOT = path.resolve(import.meta.dirname, '..');

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function startServer(dataDir, port) {
  const env = {
    ...process.env,
    APP_ORIGIN: `http://127.0.0.1:${port}`,
    APP_BIND_HOST: '127.0.0.1',
    DATA_DIR: dataDir,
    NODE_ENV: 'test',
    PORT: String(port),
    ADMIN_ID: 'ADMIN-ROOT',
    ADMIN_PASSWORD: 'SuperSecretTestAdmin123!',
    APP_KEY_BASE64: Buffer.alloc(32, 7).toString('base64'),
    VULN_MACHINE_URL: 'https://drive.google.com/test-vm-folder',
  };

  const child = spawn(process.execPath, ['--experimental-sqlite', 'server.mjs'], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const ready = new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('Server did not start in time: ' + output)), 10000);
    const onData = (chunk) => {
      output += chunk.toString();
      if (output.toLowerCase().includes('listening on')) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('error', (err) => { clearTimeout(timer); reject(err); });
    child.once('exit', (code) => {
      if (code !== null && !output.toLowerCase().includes('listening on')) {
        clearTimeout(timer);
        reject(new Error('Server exited prematurely: ' + output));
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
  return values.filter(Boolean).map((v) => v.split(';', 1)[0]);
}

test('CTF Portal HTTP Endpoints & Walkthrough Verification', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-portal-test-'));
  const port = await freePort();
  const server = startServer(dataDir, port);

  t.after(async () => {
    await stopServer(server.child);
    try { fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
  });

  await server.ready;
  const base = `http://127.0.0.1:${port}`;

  // 1. Health check
  const healthRes = await fetch(`${base}/healthz`);
  assert.equal(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.equal(healthJson.ok, true);
  assert.equal(healthJson.service, 'ctf-portal');

  // 2. Landing page
  const homeRes = await fetch(`${base}/`);
  assert.equal(homeRes.status, 200);
  const homeHtml = await homeRes.text();
  assert.match(homeHtml, /ETHICAL HACKING \/ SQUAD CTF/);
  assert.match(homeHtml, /https:\/\/drive\.google\.com\/test-vm-folder/);
  assert.match(homeHtml, /DOWNLOAD VULN LAB VM/);

  // 3. Login Page
  const loginPageRes = await fetch(`${base}/login`);
  assert.equal(loginPageRes.status, 200);
  const loginHtml = await loginPageRes.text();
  assert.match(loginHtml, /Sign in · CTF Portal/);
  const csrfMatch = loginHtml.match(/name="_csrf" value="([^"]+)"/);
  assert.ok(csrfMatch, 'Login page should include a CSRF token');
  const csrfToken = csrfMatch[1];
  const initialCookie = setCookies(loginPageRes).find((c) => c.startsWith('ctf_sid=')) || '';

  // 4. Authenticate as Admin
  const loginPostRes = await fetch(`${base}/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: initialCookie,
    },
    body: new URLSearchParams({
      _csrf: csrfToken,
      caas_id: 'ADMIN-ROOT',
      password: 'SuperSecretTestAdmin123!',
    }).toString(),
  });
  assert.equal(loginPostRes.status, 302);
  const sessionCookie = setCookies(loginPostRes).find((c) => c.startsWith('ctf_sid='));
  assert.ok(sessionCookie, 'Successful login should issue ctf_sid session cookie');

  // 5. Learn Overview Page (Authenticated)
  const learnRes = await fetch(`${base}/learn`, {
    headers: { cookie: sessionCookie },
  });
  assert.equal(learnRes.status, 200);
  const learnHtml = await learnRes.text();
  assert.match(learnHtml, /From Recon to Root/);
  assert.match(learnHtml, /Reconnaissance &amp; Discovery/);
  assert.match(learnHtml, /Web Exploitation &amp; Initial Access/);
  assert.match(learnHtml, /Lateral Movement &amp; Privilege Escalation/);
  assert.match(learnHtml, /Hardening &amp; Defensive Remediation/);

  // 6. Learn Individual Module Page
  const moduleRes = await fetch(`${base}/learn/network-discovery`, {
    headers: { cookie: sessionCookie },
  });
  assert.equal(moduleRes.status, 200);
  const moduleHtml = await moduleRes.text();
  assert.match(moduleHtml, /Local Network Discovery &amp; Host Identification/);
  assert.match(moduleHtml, /sudo arp-scan --localnet/);
  assert.match(moduleHtml, /TARGET_IP/);

  // 7. Check Module 7 (Privilege Escalation)
  const privescRes = await fetch(`${base}/learn/sudo-privesc-find`, {
    headers: { cookie: sessionCookie },
  });
  assert.equal(privescRes.status, 200);
  const privescHtml = await privescRes.text();
  assert.match(privescHtml, /Privilege Escalation via Sudo Find/);
  assert.match(privescHtml, /sudo -l/);
  assert.match(privescHtml, /GTFOBins/);

  // 8. Scoreboard
  const scoreRes = await fetch(`${base}/scoreboard`);
  assert.equal(scoreRes.status, 200);
  const scoreHtml = await scoreRes.text();
  assert.match(scoreHtml, /Scoreboard/i);

  // 9. Open Self-Registration (Option 2: No Activation Code Needed)
  const regPageRes = await fetch(`${base}/register`);
  assert.equal(regPageRes.status, 200);
  const regHtml = await regPageRes.text();
  assert.match(regHtml, /Create Account/);
  const regCsrf = regHtml.match(/name="_csrf" value="([^"]+)"/)[1];
  const regCookie = setCookies(regPageRes).find((c) => c.startsWith('ctf_sid=')) || '';

  const regSubmitRes = await fetch(`${base}/register`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: regCookie,
    },
    body: new URLSearchParams({
      _csrf: regCsrf,
      caas_id: 'NEW-PLAYER-99',
      password: 'MyPassword123!',
      password_confirm: 'MyPassword123!',
    }).toString(),
  });
  assert.equal(regSubmitRes.status, 302);
  assert.equal(regSubmitRes.headers.get('location'), '/team');
  const newPlayerCookie = setCookies(regSubmitRes).find((c) => c.startsWith('ctf_sid='));
  assert.ok(newPlayerCookie, 'Self-registration should immediately log user in');

  // Verify access to /team
  const teamRes = await fetch(`${base}/team`, {
    headers: { cookie: newPlayerCookie },
  });
  assert.equal(teamRes.status, 200);
  const teamHtml = await teamRes.text();
  assert.match(teamHtml, /Join or Create Team/);
  assert.match(teamHtml, /Create a Team/);
  assert.match(teamHtml, /Join with Code/);
});
