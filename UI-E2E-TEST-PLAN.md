# CTF Portal — UI & E2E Test Plan

## Objective

Validate the entire participant and admin journey through the web interface for the squad-based CTF competition using the ExamCorp vulnerable lab machine.

## Environment

- Local URL: `http://127.0.0.1:3000`
- Database: `data/ctf-portal.db`
- Node requirement: Node.js 22.5+ (`node --experimental-sqlite server.mjs`)
- Test squad: `CyberVanguard` (Leader: `PLAYER-01`)
- Flag format: `EH{...}`
- Vulnerable machine: Google Drive hosted VM

---

## 1. Participant Journey

| ID | Action / Page | Expected Result |
|---|---|---|
| P-01 | Open Landing Page (`/`) | Hero kicker shows `ETHICAL HACKING / SQUAD CTF`, download link for VM is present, links to Login, Scoreboard, and Curriculum. |
| P-02 | Guest accesses protected route (`/challenges`, `/workspace`, `/team`) | Redirected to `/login` with clean return path. |
| P-03 | Account Activation (`/register`) | Submit valid participant ID, one-time activation code, and password. Account created and redirected to `/team`. |
| P-04 | Re-use activation code | Rejected with `Invalid or expired activation code`. |
| P-05 | Squad Management (`/team`) | Create squad with unique name, generate shareable Join Code. Team members join via code (3–5 per squad). |
| P-06 | Challenge Catalog (`/challenges`) | 4 ExamCorp challenges: "Open Lobby" (FTP Q, 50pts), "Backdoor Staging" (HTTP Q, 50pts), "Config Leak" (100pts), "Root or Nothing" (100pts). |
| P-07 | Unlock Hint | Warning dialog about hint score penalty (-5 pts). After confirmation, hint revealed to entire squad. |
| P-08 | Flag Submission (`EH{user_flag_1}`) | Correct flag award 100 points. First blood bonus (+10 pts) awarded to first solving squad. |
| P-09 | Duplicate Submission | Clean notice stating flag has already been solved by team. No duplicate points awarded. |
| P-10 | Final Flag Submission (`EH{root_flag_congrats}`) | Solves challenge 4 ("Root or Nothing"), root badge displayed on team card. |

---

## 2. Learning Curriculum Journey (`/learn`)

| ID | Action / Page | Expected Result |
|---|---|---|
| L-01 | Open Curriculum (`/learn`) | 4 tracks and 8 modules rendered in sequence. Total minutes calculated. |
| L-02 | Open Module 1 (`/learn/network-discovery`) | ARP scanning theory, commands (`sudo arp-scan --localnet`), output examples, and checkpoint task list. |
| L-03 | Mark Module Complete | Client-side progress stored in `localStorage` under `ctf-learn-progress-v1`. Card marked completed in overview. |
| L-04 | Navigate Attack Chain | Next button navigates smoothly through Port Enumeration, FTP Recon, SQLi, Webshell, Credential Harvest, Sudo PrivEsc, and Hardening. |

---

## 3. Administrator Operations (`/admin`)

| ID | Action / Page | Expected Result |
|---|---|---|
| A-01 | Guest opens `/admin` | Denied / redirected to login. No administrative endpoints exposed. |
| A-02 | Admin Login (`admin` + strong password) | Admin panel opens showing challenge, squad, and participant counts. |
| A-03 | Challenge Management (`/admin/challenges`) | Create, edit, publish, and unpublish challenges. Validate flag encryption (AES-256-GCM). |
| A-04 | Invite Management (`/admin/invites`) | Bulk generate activation codes, export CSV, and view used/active codes. |
| A-05 | Event Controls (`/admin/event`) | Force phase override: `BEFORE OPEN` → `LIVE` → `LOCKED`. Game freezes automatically when lock time reached. |
| A-06 | Audit Log (`/admin/audit`) | All admin actions, publishing events, and lock triggers logged with timestamp and user ID. |

---

## 4. Scoreboard & Game Lock (`/scoreboard`)

| ID | Action / Page | Expected Result |
|---|---|---|
| S-01 | Scoreboard during event | Ranked by total squad points, tie-broken by time of last solve. |
| S-02 | Game Lock | When phase is `LOCKED`, flag submission forms disabled, final rankings frozen. |
