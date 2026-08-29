# LAS Week 4 Portal — UI E2E Test Plan

## Tujuan

Memastikan seluruh perjalanan peserta dan mentor berjalan melalui UI, dengan target VM tetap privat di subnet WireGuard `10.77.4.0/24`.

## Environment

- URL lokal: `http://127.0.0.1:3000`
- Browser: Chromium melalui Playwright CLI
- Peserta uji: `CAAS-UI-02`
- Mode lokal: `WG_HELPER_DRY_RUN=true`, `SKIP_NETWORK_CHECKS=true`
- Mode event: HTTPS, WireGuard aktif, helper root aktif, network checks aktif

## Flow peserta

| ID | Langkah UI | Ekspektasi |
|---|---|---|
| P-01 | Buka landing page | Status event, jadwal, subnet privat, dan link login/scoreboard tampil; tidak ada secret. |
| P-02 | Guest membuka `/workspace` | Redirect ke login. |
| P-03 | Buka Activate account, isi CaAs ID + one-time code + password | Akun dibuat dan diarahkan ke workspace. |
| P-04 | Pakai code yang sama lagi | Ditolak sebagai code invalid/expired/already used. |
| P-05 | Login dengan akun peserta | Workspace menampilkan ID sendiri, status event, score, dan next action. |
| P-06 | Setup → Attacker → Generate command | Peer attacker dialokasikan; command one-time tampil; private key tidak dikirim ke portal. |
| P-07 | Jalankan installer Kali VM/WSL | Enrollment sukses, peer menjadi enrolled/connected setelah verifikasi. |
| P-08 | Buka Setup Target sebelum attacker connected | Tetap locked dengan instruksi yang jelas. |
| P-09 | Setup Target setelah attacker connected | Peer target dialokasikan dan command Ubuntu tampil. |
| P-10 | Jalankan installer Ubuntu 24.04 | Target connected dan IP target tampil. |

## Flow build lab

| ID | Langkah UI | Ekspektasi |
|---|---|---|
| B-01 | Buka Build sebelum target connected | Builder tidak dapat dibuka; target setup diminta. |
| B-02 | Isi challenge sendiri | Form menerima title, deskripsi, minimal tiga service, port, initial access, PE path, hint, dan flag `MBC{...}`. |
| B-03 | Isi target IP di luar target pool | Ditolak server. |
| B-04 | Submit challenge | Status menjadi `draft`; owner dan target peer otomatis milik akun tersebut. |
| B-05 | Jalankan Light Check | Hasil reachability/health tampil; gagal tidak langsung menghapus challenge. |
| B-06 | Submit untuk review | Status menjadi `pending_review`; owner tidak dapat menyetujui lab sendiri. |
| B-07 | Coba memasukkan credential recovery/reset | Field tidak tersedia dan tidak disimpan. |

## Flow admin/mentor

| ID | Langkah UI | Ekspektasi |
|---|---|---|
| A-01 | Guest membuka route admin | Route disamarkan/ditolak; tidak membocorkan data admin. |
| A-02 | Admin login from a WireGuard IP with the admin password | Admin dashboard opens. |
| A-03 | Review queue | Owner ID, status, health, dan detail teknis terlihat; flag material tetap terlindungi. |
| A-04 | Approve/return challenge | Status berubah dan audit log tercatat. |
| A-05 | Recheck health | Probe memakai target IP; status `degraded` hanya setelah handshake stale + tiga kegagalan berjarak. |
| A-06 | Revoke peer | Peer dicabut, token lama tidak dapat digunakan kembali. |

## Flow live mini-CTF

| ID | Langkah UI | Ekspektasi |
|---|---|---|
| L-01 | Sebelum `PORTAL_OPEN_AT`, buka Lab Space | Page menampilkan closed dan waktu open. |
| L-02 | Setelah open, buka Lab Space | Hanya challenge approved/healthy yang tampil; challenge milik sendiri disembunyikan. |
| L-03 | Buka challenge peer | Target IP, port, command enumeration, dan hint tampil; solver identity/flag tidak tampil. |
| L-04 | Submit flag valid | +100 poin; first blood mendapat +10. |
| L-05 | Submit flag salah/duplikat | Ditolak; tidak ada poin ganda. |
| L-06 | Buka scoreboard | Rank berdasarkan total poin, lalu waktu mencapai total; jumlah solver terlihat tanpa identitas solver. |
| L-07 | Submit setelah `SUBMISSION_DEADLINE_AT` | Ditolak. |
| L-08 | Setelah `GAME_LOCK_AT` | Challenge, flag submission, status, dan leaderboard terkunci final. |

## Evidence yang disimpan

- Snapshot UI per milestone.
- Screenshot landing, setup command, build form, lab space, scoreboard, dan lock state.
- HTTP status/redirect untuk guest, admin public, dan invalid token.
- `npm test` harus tetap `20 passed, 0 failed`.

## Batas pengujian lokal

Mode lokal tidak menjalankan perubahan WireGuard host dan tidak melakukan probe jaringan. P-07, P-09, A-02, A-05, L-02 sampai L-08 perlu diulang pada staging/VPS dengan WireGuard aktif sebelum event dibuka.
