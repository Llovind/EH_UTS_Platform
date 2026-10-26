# CTF Portal — Squad-Based Capture the Flag

A lightweight, self-contained CTF portal built for squad-based competitions. Participants download an official vulnerable lab VM, exploit privilege escalation boundaries, and submit flags in `EH{...}` format as a team.

## What is included

- Invite-code-based participant registration with one-time activation codes.
- Squad system: 3–5 members per team, join via shareable invite codes.
- Challenge catalogue: categories, hints (with score penalty), flag submission, and first-blood bonus.
- Live scoreboard with score tie-break by time of last solve.
- Learning modules with reading progress tracking (stored client-side).
- Admin panel: challenge management, invite generation, audit log, and event phase control.
- Flags are validated as `EH{...}`, hashed with SHA-256, and encrypted at rest (AES-256-GCM). Plaintext flags are never stored.
- Secure session cookies (`ctf_sid`), CSRF protection, Helmet headers, rate limits, parameterized SQLite queries, and audit logs.

## Quick start (Ubuntu 24.04 / Node 22+)

The portal uses Node's built-in `node:sqlite` — requires Node.js **22.5 or newer**.

1. Clone the repo and copy `.env.example` to `.env`.
2. Set `APP_KEY_BASE64` to a random 32-byte base64 value (`openssl rand -base64 32`) and set a long, unique `ADMIN_PASSWORD`.
3. Run `npm ci` and `npm start`. The portal listens on `127.0.0.1:3000` by default.
4. Put Caddy or Nginx in front for HTTPS and set `APP_ORIGIN` to the HTTPS URL.
5. Generate participant invites, then import:

   ```bash
   node scripts/generate-invites.mjs ./participant-ids.txt > ./invites.csv
   npm run import:invites -- ./invites.csv
   ```

   CSV header: `caas_id,activation_code,expires_at`

6. Provide participants with the invite code and the vuln machine download link (`VULN_MACHINE_URL` in `.env`).

## Admin operations

- Admin page: `/admin` — manage challenges, invites, audit log, and event phase.
- Event phases: `BEFORE OPEN → LIVE → LOCKED`. Force a phase override from `/admin/event`.
- Challenge statuses: `draft → published → locked`.
- `PORTAL_OPEN_AT` and `GAME_LOCK_AT` control the automatic phase schedule (ISO 8601 with timezone).

## Vulnerable machine

The official lab VM is provided via Google Drive. Set `VULN_MACHINE_URL` in `.env` to the public Google Drive folder link. The download button appears on the homepage and participant workspace automatically.

## Zero-cost cloud deployment (No domain needed)

Because the portal uses SQLite and Node 22+, deploy using one of the following free options without purchasing a custom domain:

### Option A: Fly.io (Recommended — free `*.fly.dev` subdomain + persistent volume)
1. Install flyctl: `powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"` or `brew install flyctl`.
2. Run `fly launch` in the repository root.
3. Attach a persistent volume for the SQLite database:
   ```bash
   fly volumes create ctf_data --size 1
   ```
4. Set production secrets in Fly:
   ```bash
   fly secrets set APP_KEY_BASE64="<random_base64_32_bytes>" ADMIN_PASSWORD="<strong_password>"
   ```
5. Deploy: `fly deploy`. Your portal will be live at `https://<app-name>.fly.dev` with automatic free TLS.

### Option B: Cloudflare Tunnel (Run locally or on free VM, public free URL)
1. Run the app locally with `npm start`.
2. Install `cloudflared` and run:
   ```bash
   cloudflared tunnel --url http://localhost:3000
   ```
3. Cloudflare gives an instant, free `https://<random>.trycloudflare.com` URL accessible by anyone without open router ports or domain purchase.

## Deployment checklist

1. Set a random 32-byte `APP_KEY_BASE64` and a strong `ADMIN_PASSWORD` (16+ chars).
2. Set `APP_ORIGIN` to the HTTPS URL in production.
3. Set `NODE_ENV=production`.
4. Set `VULN_MACHINE_URL` to the Google Drive folder link for the vulnerable machine.
5. Set `PORTAL_OPEN_AT` and `GAME_LOCK_AT` to the correct event window.
6. Confirm `/healthz` returns `{"ok":true}` before distributing invite codes.
7. Never commit `.env`, invite CSVs, or flag values to the repository.

## Security notes

- Passwords are hashed with scrypt. Flags are SHA-256 hashed and AES-256-GCM encrypted at rest.
- All admin functionality is behind role-based access control — no WireGuard or IP-based restrictions.
- This portal is intended for bounded, authorized training events. Do not expose the vulnerable VM to the public internet.
