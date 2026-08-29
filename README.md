# MBC LAS Week 4 mini-CTF portal

This is a deliberately small portal for the LAS Week 4 recruitment exercise. The portal is public over HTTPS at the chosen placeholder subdomain, while every target VM and vulnerable service remains inside the WireGuard network (`10.77.4.0/24`). The admin area requires an admin identity and a source IP inside the WireGuard CIDR.

## What is included

- Individual CaAs activation with one-time invite codes.
- Challenge self-service: `draft → pending review → approved → locked`.
- Public challenge catalogue, hints, flag submission, equal scoring (100 + 10 first blood), and scoreboard tie-break by time reached.
- Owner IDs, intended PE paths, flag material, and mentor notes are never sent to participant pages. No recovery credential or reset field is collected by the portal.
- Passwords are scrypt-hashed and flags are encrypted/hashed at rest; secrets are never committed to the repository.
- Secure session cookies, CSRF checks, Helmet headers, rate limits, parameterized SQLite queries, and audit logs.

## Ubuntu 24.04 quick start

The portal uses Node's built-in `node:sqlite`, so use Node.js 22.5 or newer (the setup script installs Node 22 when needed).

1. Clone the repository on the VPS and copy `.env.example` to `.env`.
2. Set `APP_KEY_BASE64` to a random 32-byte base64 value and set a long, unique `ADMIN_PASSWORD`.
3. Run `npm ci` and `npm start`. The app listens only on `127.0.0.1:3000`.
4. Replace `portal.example.org` in `.env` and `deploy/Caddyfile.example` with the chosen subdomain, then put Caddy/Nginx in front for HTTPS.
5. Bring up WireGuard using `deploy/wg0.conf.example` as the routing template. Use `deploy/peer-client.conf.example` for each laptop/VM. Replace every placeholder key; never commit private keys.
6. Install the strict root-owned helper and sudoers template from `deploy/mbc-las-wg-peer.example` and `deploy/mbc-las-wg-peer.sudoers.example`. `deploy/setup-ubuntu-24.sh` performs this automatically for the default path. Keep its interface and IP pools synchronized with `.env`.
7. Generate participant invites from a local ID list, then import the CSV (do not upload either file to the portal):

   `node scripts/generate-invites.mjs ./caas-ids.txt > ./invites.csv`

   `npm run import:invites -- ./invites.csv`

   CSV header: `caas_id,activation_code,expires_at`

## Operations

- Set `PORTAL_OPEN_AT` to Wednesday 2 September 2026 11:00 WIB and `GAME_LOCK_AT` to Friday 4 September 2026 18:00 WIB for this event.
- Keep `data/las-week4.db` mode `0700` and back it up offline. Never put `.env`, invite CSVs, or flags in GitHub.
- Use the portal admin page only from a WireGuard-connected device. The server rejects admin requests from public addresses.
- Target IPs must be assigned from the target peer range (`10.77.4.100–129`); the form rejects other networks.
- Admin pages: `/admin/review`, `/admin/peers`, `/admin/health`, `/admin/event`, and `/admin/audit`.
- `OPEN` is an explicit early-open override. `LOCK` is global and final; it freezes challenge writes, flag submissions, leaderboard changes, and challenge statuses.
- A target becomes `degraded` only when the WireGuard handshake is stale and three target-IP probes fail with at least 20 seconds between attempts. A single service-port failure or one probe failure is not enough.
- In local development `SKIP_NETWORK_CHECKS=true` safely treats the probe as a pass-through. Production startup requires `SKIP_NETWORK_CHECKS=false`, a real WireGuard helper, HTTPS, and a long admin password.

## Deployment checklist

1. Replace every `portal.example.org`, `HUB_PRIVATE_KEY`, `HUB_PUBLIC_KEY`, and peer key placeholder.
2. Configure the real portal subdomain in DNS and Caddy.
3. Set a random 32-byte `APP_KEY_BASE64`, a long unique admin password, and production WireGuard settings.
4. Install the helper as root with mode `0750` and sudoers with mode `0440`; validate with `visudo -cf`. The portal service user may elevate only through this exact helper (do not enable unrestricted sudo or `NoNewPrivileges`, which would prevent the narrow helper call).
5. Confirm `/healthz` returns `ok: true`, then activate one attacker and one target peer before importing all invites.
6. Test admin access from WireGuard and rejection from a public source before opening the event.

## Security boundary

This repository is for a bounded, authorized training event. The vulnerable VMs are not hosted by this application and must not be exposed to the public internet. Rotate all keys and admin credentials before the real event.
