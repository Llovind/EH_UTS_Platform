# LAS Week 4 — Linux Privilege Escalation Curriculum Research

Status: teaching design for an authorized, isolated mini-CTF

Audience: CaAs using the assigned Kali attacker VM/WSL and Ubuntu target VM/VPS over WireGuard

Date: 29 August 2026

## 0. Scope and teaching contract

This curriculum teaches evidence-led Linux enumeration and privilege-escalation reasoning inside the assigned LAS Week 4 lab only. The target IPs and vulnerable services are reachable through the WireGuard tunnel; do not scan or test public addresses, classmates’ infrastructure outside the Lab Space, campus systems, or any host without explicit authorization. WireGuard’s official quick start documents the peer model, key handling, interface setup, and `AllowedIPs`; use the portal-generated configuration rather than inventing routes or keys ([WireGuard Quick Start](https://www.wireguard.com/quickstart/)).

The objective is to explain why a control fails, demonstrate the smallest lab-safe proof, preserve evidence, and report a repair. It is not a persistence or real-world compromise exercise.

**Out of scope:** destructive commands, deletion of files, password spraying/brute force, persistence, kernel exploits, exploit chaining against unowned systems, data exfiltration, denial of service, evasion, and modifying the target outside the challenge’s intended path. Stop when the flag is proven or when the mentor’s objective is met.

**Operating rules**

- Use the assigned attacker peer and the target peer allocated to your account. Confirm the IP shown in the portal before any network command.
- Prefer read-only commands. Save output in a local evidence directory; redact passwords, tokens, private keys, and unrelated personal data before submission.
- Do not use `sudo` to “try things.” First inspect policy with `sudo -l`; use a permitted command only when the challenge explicitly expects it.
- Do not change permissions, timers, services, PATH files, users, or credentials unless the challenge explicitly supplies a reversible, mentor-approved exercise.
- A finding needs a chain: observation → security consequence → minimal validation → evidence → remediation.
- If a command could affect availability or data, pause and ask the mentor. “It worked” is not permission to repeat it elsewhere.

## 1. Learning outcomes and assessment

By the end, a CaAs should be able to:

1. Distinguish real UID, effective UID, real/effective groups, supplementary groups, and the permissions relevant to a process. Linux documents these credentials and their role in permission checks in [`credentials(7)`](https://man7.org/linux/man-pages/man7/credentials.7.html).
2. Build a repeatable, low-noise enumeration workflow instead of running a memorized list.
3. Interpret `sudo`, SUID/SGID, file capabilities, writable execution paths, cron, and systemd evidence without assuming that every unusual setting is exploitable.
4. Validate only the intended privilege boundary and stop at proof.
5. Produce a short report with commands, timestamps, sanitized output, impact, root cause, and hardening guidance.

Recommended evidence rubric: 30% identity and scope, 30% enumeration quality, 25% reasoning and safe validation, 15% report quality and cleanup. A flag alone is not a complete submission.

## 2. Enumeration workflow: the repeatable loop

Use this loop for every lab:

```text
scope → baseline → enumerate → prioritize → validate minimally → record → report/stop
```

The `/proc` pseudo-filesystem exposes process and kernel state; most of it is read-only, but some entries are writable kernel controls, so treat writes as out of scope ([`proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html)). MITRE classifies account, group, process, network, and file discovery as discovery behaviors; here they are constrained to the assigned lab ([Account Discovery](https://attack.mitre.org/techniques/T1087/001/), [Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/001/), [Process Discovery](https://attack.mitre.org/techniques/T1057/), [Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/001/), [File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)).

**Safe baseline**

```bash
date -Is
hostname
id
pwd
cat /etc/os-release
uname -a
```

- `date -Is` creates an ISO-8601 timestamp for the evidence timeline.
- `id` prints the current UID, GID, and supplementary groups.
- `/etc/os-release` identifies the distribution; `uname -a` reports kernel and machine information. Record them, but do not infer a kernel exploit from version alone.

**What to look for:** expected lab hostname, current non-root identity, target distribution, and whether the target is actually the assigned IP.

**Example interpretation**

```text
uid=1001(labuser) gid=1001(labuser) groups=1001(labuser),1005(backup)
```

This is not privilege escalation by itself. The `backup` membership is a lead; inspect what that group can access before drawing a conclusion.

**Common mistakes:** scanning before confirming scope, treating a version string as proof, collecting output without timestamps, and testing every lead at once so the evidence chain is lost.

**Checkpoint:** create `evidence/00-scope.txt` with the baseline output and a one-sentence scope statement. Next: [credentials and UID model](#3-module-identity-uideuid-groups-and-permissions).

## 3. Module — identity, UID/EUID, groups, and permissions

### Concepts

Linux separates real and effective user/group IDs. The effective IDs are used for many permission decisions, while filesystem IDs and supplementary groups participate in file access checks ([`credentials(7)`](https://man7.org/linux/man-pages/man7/credentials.7.html)). A process can be privileged because its effective UID is 0, but Linux also splits some traditional superuser powers into per-thread capabilities ([`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)).

File metadata includes owner UID, group GID, type, mode, timestamps, and link count ([`inode(7)`](https://man7.org/linux/man-pages/man7/inode.7.html)). The nine ordinary permission bits are owner/group/other read, write, and execute; SUID, SGID, and sticky are special mode bits. Execute on a directory means search/traverse, not “run the directory” ([`path_resolution(7)`](https://man7.org/linux/man-pages/man7/path_resolution.7.html)).

### Safe commands and options

```bash
id
id -u
id -g
id -G
groups
getent passwd
getent group
stat -c '%A %a %U %G %n' /path/to/file
namei -l /path/to/file
```

- `id -u`, `-g`, and `-G` isolate the effective UID, effective GID, and supplementary group IDs.
- `getent` reads the system name-service database rather than assuming only local files.
- `stat -c` prints symbolic mode, octal mode, owner, group, and path. The format is read-only and avoids ambiguous `ls` output ([`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html)).
- `namei -l` shows each directory component and its permissions, useful when the file itself looks readable but a parent directory blocks traversal.

### What to look for

- A group that owns a sensitive lab script, socket, backup, or service configuration.
- A path component writable by the current user or a group the user belongs to.
- A mismatch between the apparent owner and the permissions needed by the executing service.
- SUID/SGID bits in the mode column (`s` or octal `4000`/`2000`). Treat them as candidates, not proof.

### Example interpretation

```text
-rwxrwx--- 770 labuser backup /opt/ctf/check.sh
drwxr-x--- 750 root backup /opt/ctf
```

The current user’s `backup` membership may allow reading or executing the file. It does not show that the file runs as root; inspect the process/service that invokes it and the file’s actual owner.

### Common mistakes and safety boundary

Do not change mode/owner bits, write to a candidate file, or replace a symlink during enumeration. Do not assume `777` means root execution; execution context and invocation matter. Do not read unrelated users’ private data simply because a directory is traversable.

### Mini exercise and summary

Run the commands against the declared challenge path. Report the permission tuple as `subject → object → operation → consequence`. Checkpoint: explain why the group membership matters and name one missing fact that must be validated. Next: [system, user, process, and network enumeration](#4-module-system-users-processes-and-network).

## 4. Module — system, users, processes, and network

### Concepts

Enumeration is a hypothesis generator. `/proc` contains per-process files such as `cmdline` and `status`; process IDs survive an `execve`, so a PID is a useful evidence anchor ([`proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html), [`proc_pid(5)`](https://www.man7.org/linux/man-pages/man5/proc_pid.5.html)). MITRE documents the same categories as discovery techniques, but the lab task is to understand local context, not to maximize collection.

### Safe commands and options

```bash
ps -eo user,pid,ppid,stat,lstart,args --forest
tr '\0' ' ' < /proc/<PID>/cmdline; printf '\n'
grep -E '^(Name|Uid|Gid|Groups|Cap|NoNewPrivs):' /proc/<PID>/status
getent passwd | awk -F: '$3 >= 1000 {print $1 ":" $3 ":" $6 ":" $7}'
getent group
ip -br address
ip route
ss -tulpen
```

- `ps -e` selects every process; `-o` chooses stable columns; `--forest` shows parent/child relationships. `args` is the command with arguments; treat arguments as potentially sensitive.
- `/proc/<PID>/cmdline` is NUL-separated, so `tr` makes it readable without modifying the process.
- `/proc/<PID>/status` exposes identity and capability fields when permitted; `Cap*` fields are hexadecimal bitmasks that need capability-aware interpretation.
- `awk -F:` selects likely human accounts from `passwd`; UID thresholds vary, so confirm local policy.
- `ip -br address` is concise address/interface state; `ip route` shows routing; `ss -tulpen` lists listening TCP/UDP sockets with process information when permissions allow ([`ip(8)`](https://man7.org/linux/man-pages/man8/ip.8.html), [`ss(8)`](https://man7.org/linux/man-pages/man8/ss.8.html)).

### What to look for

- A root-owned process running a script or binary from a writable path.
- Environment/argument references to a lab configuration, script, or service account.
- A listener not declared in the challenge, or an expected listener bound only to localhost.
- Parent-child relationships that explain how a privileged service invokes a lower-privileged helper.

### Example interpretation

```text
root  812  1  ... /usr/bin/python3 /opt/ctf/rotate.py
```

The process is worth investigating because root runs a script. It is not proof until ownership, mode, invocation frequency, interpreter behavior, and the script’s writable dependencies are documented.

### Common mistakes and safety boundary

`ps` output can contain secrets in arguments; redact it. Do not kill, stop, attach to, or alter processes. Do not treat every localhost listener as a vulnerability. Do not run a full-port scan outside the assigned target; use declared ports or a mentor-approved narrow check.

### Mini exercise and summary

Draw one parent-child chain for a suspicious process and map one listening socket to its owning service. Checkpoint: state exactly which observation would justify the next read-only inspection. Next: [filesystem and network interpretation](#5-module-filesystem-and-service-surface).

## 5. Module — filesystem and service surface

### Concepts

File discovery must be bounded by purpose and path. GNU `find` evaluates expressions left-to-right and documents permission expressions such as `/222` for “writable by someone”; use a known start path and `-xdev` to avoid crossing filesystems ([GNU `find(1)`](https://man7.org/linux/man-pages/man1/find.1.html)). Inodes record ownership and mode independently from path names, so inspect both the object and every directory component.

### Safe commands and options

```bash
find /opt /srv /var/www /home -xdev -type f -name '*.sh' -print 2>/dev/null
find /opt /srv /var/www /home -xdev -type f -perm /222 -print 2>/dev/null
find /opt /srv /var/www /home -xdev -type f \( -name '*.conf' -o -name '*.env' -o -name '*.ini' \) -print 2>/dev/null
find /opt /srv /var/www /home -xdev -type l -ls 2>/dev/null
file /path/to/candidate
stat -c '%A %a %U %G %n' /path/to/candidate
```

- `-xdev` keeps traversal on the starting filesystem; `-type f`/`l` selects regular files/symlinks.
- `-perm /222` matches any write bit; it does not say who can write, so follow with `stat`.
- `2>/dev/null` suppresses expected permission-denied noise; do not confuse silence with absence.
- `file` identifies content type without executing it.

### What to look for

- A root-run script in a path writable by the current user/group.
- A service configuration that references a relative executable or an unsafe `PATH`.
- Symlinks whose target ownership/mode differs from the link’s apparent location.
- Configuration files inside the challenge-owned directories that explain credentials or execution flow.

### Example interpretation

```text
-rwxrwxr-x 775 root labuser /opt/ctf/rotate.sh
```

The group can modify the script. If a root service executes it, the combination is a candidate for validation. If no privileged invocation exists, it may be harmless.

### Common mistakes and safety boundary

Do not use `find / -exec ...` during the exercise; it can execute commands on many files. Do not follow all symlinks by default. Do not edit a candidate to see what happens. Keep searches inside the lab’s intended directories unless the challenge explicitly asks for a broader read-only check.

### Mini exercise and summary

Choose one writable candidate and prove ownership, mode, path traversal, and invocation source with `stat`, `namei`, and `ps`/service metadata. Checkpoint: a candidate is only reportable when those facts form a complete chain. Next: [sudo policy](#6-module-sudo-policy).

## 6. Module — sudo policy

### Concepts

`sudoers` is the policy plugin that decides who may run which commands; it can also control authentication, environment, and logging ([`sudoers(5)`](https://man7.org/linux/man-pages/man5/sudoers.5.html)). The permission is command-specific. A user allowed to run one binary is not automatically allowed to run a root shell.

### Safe commands and options

```bash
sudo -l
sudo -V
```

- `sudo -l` lists the current user’s effective policy. It is the first and usually the only required sudo command for enumeration.
- `sudo -V` prints sudo version/configuration information; do not treat an old version as an invitation to search for or run an exploit.

### What to look for

- `NOPASSWD` entries and exact command paths.
- Wildcards, user-controlled arguments, interpreters, editors, pagers, archive tools, or scripts in a rule.
- `SETENV`, preserved environment variables, or a relative command path.
- Whether the rule applies on this host and whether the user can satisfy its arguments without modifying policy.

### Example interpretation

```text
(root) NOPASSWD: /usr/local/bin/backup --source /opt/ctf
```

The candidate is the argument and the program’s behavior, not the word `NOPASSWD` alone. Read the program or challenge documentation, verify whether `/opt/ctf` is user-controlled, and stop after a mentor-approved proof.

### Common mistakes and safety boundary

Never run `sudo -i`, `sudo su`, `sudo bash`, or a shell escape merely to test access. Do not alter `/etc/sudoers`, `/etc/sudoers.d`, environment policy, or command files. Do not paste a public write-up’s exploit blindly; document the exact rule and intended validation instead.

### Mini exercise and summary

Translate one rule into four fields: invoking user, run-as user, exact executable, argument constraints. Checkpoint: explain the least-privilege remediation (narrow path, fixed arguments, safe environment, logging). Next: [SUID/SGID](#7-module-suid-and-sgid).

## 7. Module — SUID and SGID

### Concepts

The SUID bit can change the effective user ID when an executable is run; SGID can change the effective group ID. The kernel mode bits and credential transition are described by [`inode(7)`](https://man7.org/linux/man-pages/man7/inode.7.html), [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html), and [`credentials(7)`](https://man7.org/linux/man-pages/man7/credentials.7.html). MITRE classifies abuse of setuid/setgid as [T1548.001](https://attack.mitre.org/techniques/T1548/001/).

### Safe commands and options

```bash
find /usr /bin /sbin /opt -xdev -type f -perm -4000 -printf '%m %u %g %p\n' 2>/dev/null
find /usr /bin /sbin /opt -xdev -type f -perm -2000 -printf '%m %u %g %p\n' 2>/dev/null
stat -c '%A %a %U %G %n' /path/to/candidate
strings -a -n 6 /path/to/candidate | head -n 40
```

- `-perm -4000` requires the SUID bit; `-perm -2000` requires SGID. The `-printf` fields show mode, owner, group, and path.
- `strings -a -n 6` is a read-only clue for embedded paths/messages; it is not proof of behavior and should not be used as a substitute for source review.

### What to look for

- Unusual lab binaries, custom wrappers, or binaries owned by root.
- Relative paths, unsafe temporary files, uncontrolled environment variables, or user-controlled input passed to privileged operations.
- Whether the binary is actually reachable and whether the suspected code path is intended by the challenge.

### Example interpretation

```text
-rwsr-xr-x 4755 root root /usr/local/bin/ctf-helper
```

The `s` in the owner execute position and `4755` identify SUID root. The next question is how `ctf-helper` handles input and files. Finding the bit is not equivalent to obtaining a root shell.

### Common mistakes and safety boundary

Do not execute an unknown SUID binary with arbitrary input. Do not copy it off the lab, alter its mode, or attempt a shell escape. Use a supplied benign input or a mentor-approved test that demonstrates only the intended boundary.

### Mini exercise and summary

Compare one standard system SUID binary with one challenge binary. Record owner, mode, purpose, input boundary, and why the challenge one is or is not risky. Next: [capabilities](#8-module-linux-capabilities).

## 8. Module — Linux capabilities

### Concepts

Linux capabilities split traditional root privilege into distinct units and are attributes of threads; examples include `CAP_DAC_OVERRIDE` (bypass discretionary file permissions), `CAP_SETUID`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN` ([`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)). File capabilities can grant a process selected powers without SUID. A capability must still be relevant to the binary’s behavior and execution context.

### Safe commands and options

```bash
getcap -r /usr /bin /sbin /opt 2>/dev/null
getcap /path/to/candidate
grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb):' /proc/<PID>/status
```

- `getcap -r` recursively prints file capabilities in the selected paths; scope the roots to the lab and expect permission-denied omissions.
- `CapEff` is the effective process capability set; the `/proc` values are hexadecimal masks and need the capability list for decoding.
- Do not run `setcap`; it changes system state and is outside enumeration.

### What to look for

- A root-owned or service-run binary with a capability that matches a sensitive operation.
- A capability that is present in the file but absent after execution because of bounding/ambient rules.
- A mismatch between the claimed capability and the actual code path.

### Example interpretation

```text
/opt/ctf/reader cap_dac_read_search=ep
```

The file has effective/permitted `CAP_DAC_READ_SEARCH`, which relates to bypassing some file-read/search checks. Prove only the challenge’s designated read boundary; do not browse unrelated private files.

### Common mistakes and safety boundary

Do not treat any capability as “root.” Do not modify extended attributes, copy capabilities to another file, or use the capability to access unrelated host data. Stop at the flag/evidence boundary.

### Mini exercise and summary

For one capability candidate, answer: who executes it, what capability is granted, what operation does that capability permit, and what exact lab file is in scope? Next: [writable scripts and PATH](#9-module-writable-scripts-and-path-resolution).

## 9. Module — writable scripts, PATH, and path resolution

### Concepts

Execution flow can be weakened when a privileged program invokes a writable script, a relative path, or an untrusted command name. MITRE documents PATH interception as [T1574.007](https://attack.mitre.org/techniques/T1574/007/). Linux path traversal requires search permission on every directory component; symlink handling and path resolution therefore matter ([`path_resolution(7)`](https://man7.org/linux/man-pages/man7/path_resolution.7.html)).

### Safe commands and options

```bash
printf '%s\n' "$PATH"
command -v <command>
type -a <command>
namei -l /path/to/script
stat -c '%A %a %U %G %n' /path/to/script /path/to/parent
grep -nE '(^|[[:space:]])(PATH|[A-Za-z_][A-Za-z0-9_]*)=' /path/to/script 2>/dev/null
```

- `command -v` reports the executable selected by the current shell; `type -a` shows all matching resolutions.
- `namei -l` follows path components for inspection; do not use it to alter links.
- The `grep` expression identifies assignments for review; it does not prove that a variable is exploitable.

### What to look for

- A root service using an unqualified command such as `tar`, `cp`, or `python`.
- A PATH directory writable by the service’s unprivileged user.
- A writable sourced file, helper script, or configuration path used by a privileged process.
- Relative paths that depend on the service working directory.

### Example interpretation

```text
PATH=/home/labuser/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
```

If a root process inherits this PATH and `/home/labuser/bin` is writable by `labuser`, that is a serious candidate. Confirm the process environment and invocation; do not create a replacement command as part of a generic lesson.

### Common mistakes and safety boundary

Never place a fake executable in a PATH directory, alter a service environment, or replace a helper during enumeration. A safe lab may demonstrate the issue with a mentor-supplied inert fixture; otherwise report the condition and stop.

### Mini exercise and summary

Trace one command from service configuration to resolved executable and list each directory’s owner/mode. Checkpoint: propose remediation—absolute paths, controlled environment, non-writable directories, and least privilege. Next: [cron and systemd](#10-module-cron-and-systemd).

## 10. Module — cron and systemd scheduling

### Concepts

Cron entries schedule commands under the owning user; the cron format and security caveats are documented in [`crontab(5)`](https://man7.org/linux/man-pages/man5/crontab.5.html). A systemd timer activates a matching service by default, and unit behavior comes from the service definition ([`systemd.timer(5)`](https://man7.org/linux/man-pages/man5/systemd.timer.5.html), [`systemd.service(5)`](https://man7.org/linux/man-pages/man5/systemd.service.5.html)). MITRE maps cron to [T1053.003](https://attack.mitre.org/techniques/T1053/003/) and systemd service modification to [T1543.002](https://attack.mitre.org/techniques/T1543/002/).

### Safe commands and options

```bash
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly 2>/dev/null
systemctl list-timers --all --no-pager
systemctl list-unit-files --type=service --no-pager
systemctl cat <unit>.service
systemctl cat <unit>.timer
systemctl show <unit>.service -p User -p Group -p ExecStart -p Environment -p WorkingDirectory
```

- `crontab -l` lists the current user’s entries; it does not edit them.
- `systemctl list-timers --all` includes inactive timers; `--no-pager` keeps evidence non-interactive.
- `systemctl cat` shows the loaded unit and drop-ins; `systemctl show -p` selects properties relevant to execution context.
- Do not use `systemctl start`, `stop`, `restart`, `enable`, `disable`, `edit`, or `daemon-reload` in this curriculum.

### What to look for

- A privileged schedule invoking a script or binary writable by the challenge user.
- A unit’s `User=`, `Group=`, `ExecStart=`, `Environment=`, and `WorkingDirectory=` values.
- Drop-ins or path dependencies under challenge-controlled directories.
- Timer cadence and last/next trigger as context, not as a reason to wait or cause repeated executions.

### Example interpretation

```text
Timer: ctf-check.timer
Service: ctf-check.service
User=root
ExecStart=/opt/ctf/check.sh
```

This creates a candidate only if `/opt/ctf/check.sh` or a dependency is writable by the lab user. Record the owner/mode and stop before modifying it.

### Common mistakes and safety boundary

Do not edit crontabs or unit files, create jobs, trigger timers, or reload systemd. Do not infer root execution from a timer name; follow the matching service. Cron’s file permissions and newline requirements matter ([`crontab(5)`](https://man7.org/linux/man-pages/man5/crontab.5.html)).

### Mini exercise and summary

For one scheduled unit, produce a five-line chain: trigger → unit → user/group → executable → writable dependency. Next: [credentials and configurations](#11-module-credentials-and-configuration-discovery).

## 11. Module — credentials and configuration discovery

### Concepts

Credentials in files and private keys are common discovery risks; MITRE describes them as [T1552.001](https://attack.mitre.org/techniques/T1552/001/) and [T1552.004](https://attack.mitre.org/techniques/T1552/004/). The Linux account files have different roles: [`passwd(5)`](https://man7.org/linux/man-pages/man5/passwd.5.html) describes account records, [`group(5)`](https://man7.org/linux/man-pages/man5/group.5.html) describes group membership, and [`shadow(5)`](https://man7.org/linux/man-pages/man5/shadow.5.html) describes protected password data. Access to a file is not permission to reuse a credential outside the lab.

### Safe commands and options

```bash
find /home /opt /srv /var/www -xdev -type f \( -name '.env' -o -name '*.conf' -o -name '*.ini' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name 'id_*' \) -print 2>/dev/null
grep -RIlE '(^|[^A-Za-z])(password|passwd|secret|token|api[_-]?key|private[_-]?key)([^A-Za-z]|$)' /home /opt /srv /var/www 2>/dev/null
find /home /opt /srv /var/www -xdev -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' \) -print 2>/dev/null
stat -c '%A %a %U %G %n' /path/to/config
```

- The first `find` lists likely files without printing contents.
- `grep -RIlE` uses recursive search, ignores binary files, and prints file names only (`-l`); use a narrow challenge directory.
- Private-key filenames are indicators, not proof that a key is readable or valid.
- If a mentor authorizes reading a specific lab file, capture only the minimum relevant lines and redact values in the report.

### What to look for

- Service credentials with excessive read permissions.
- A private key readable by an unintended account or group.
- Secrets reused as a local password, service credential, or flag—treat reuse as a finding only within the lab’s intended proof.
- Configuration values that explain an earlier service or PE lead.

### Example interpretation

```text
-rw-r----- 640 root labuser /opt/ctf/app.env
```

Membership in `labuser` may permit reading the file. Report the metadata and the specific challenge-relevant value with redaction; do not copy the whole file into a submission.

### Common mistakes and safety boundary

Do not search the entire host indiscriminately, dump `/etc/shadow`, or test discovered credentials against other services. Never submit private keys or real passwords. Do not use keys to access any host other than the assigned lab.

### Mini exercise and summary

Find one configuration file relevant to the declared service, prove its ownership/mode, and explain how the value affects the intended challenge path. Next: [service-specific enumeration](#12-module-service-specific-enumeration).

## 12. Module — service-specific enumeration

### Concepts

Network enumeration should confirm the challenge’s declared surface and connect a service to its local process/configuration. `ss(8)` and `ip(8)` provide local socket and route views; remote probing should remain on the WireGuard target IP. The portal’s Lab Space supplies the permitted target and declared ports.

### Safe commands and options

From the assigned Kali attacker:

```bash
ip -br address
ip route
ping -c 1 <TARGET_IP>
nmap -Pn --reason -sV -p <DECLARED_PORTS> <TARGET_IP>
curl -i --max-time 5 http://<TARGET_IP>:<PORT>/
ssh -o ConnectTimeout=5 <LAB_USER>@<TARGET_IP>
```

- `-Pn` skips host discovery when ICMP is filtered; it does not broaden the port list.
- `--reason` records why Nmap classified a port; `-sV` requests service/version identification. Use only the declared ports and a normal scan rate.
- `curl -i` includes response headers; `--max-time` prevents a hanging request.
- SSH is a connection check only; use credentials supplied by the challenge and do not guess passwords.

On the Ubuntu target, correlate the surface:

```bash
ss -tulpen
ps -eo user,pid,ppid,args --forest
systemctl list-units --type=service --state=running --no-pager
```

### What to look for

- Service banner/version and bind address.
- Difference between exposed port and local process identity.
- Web root, service unit, or configuration path that connects the network clue to the PE lead.
- Unexpected exposure to document for the mentor, not to exploit outside scope.

### Example interpretation

```text
80/tcp open  http Apache httpd
```

This identifies a service surface, not a vulnerability. Compare the banner to the lab hint, inspect the declared web content, and keep any later action within the challenge path.

### Common mistakes and safety boundary

Do not use `-p-`, high-rate scans, UDP-wide scans, vulnerability scripts, password guessing, directory brute force, or exploit modules unless the mentor explicitly adds that exact scope. Do not scan the WireGuard subnet; use the one assigned target IP.

### Mini exercise and summary

Create a service map: `port/protocol → banner → local process → config path → next read-only command`. Next: [evidence, validation, cleanup, and reporting](#13-module-validation-evidence-cleanup-and-reporting).

## 13. Module — validation, evidence, cleanup, and reporting

### Concepts

Evidence should be reproducible and minimal. A useful report distinguishes observation from inference and proof. `stat` records metadata; `sha256sum` can identify a file without distributing its contents; `script`/`tee` can preserve a terminal record. Do not include secrets, private keys, or unrelated user data. Sudoers itself supports event logging and I/O logging, reinforcing that privileged actions should be auditable ([`sudoers(5)`](https://man7.org/linux/man-pages/man5/sudoers.5.html)).

### Safe evidence commands

```bash
mkdir -p evidence
date -Is | tee evidence/timeline.txt
id | tee evidence/identity.txt
stat -c '%A %a %U %G %n' /path/to/candidate | tee evidence/candidate-stat.txt
namei -l /path/to/candidate | tee evidence/candidate-path.txt
sha256sum /path/to/candidate | tee evidence/candidate-sha256.txt
```

- `mkdir -p` creates the participant-owned evidence directory if it does not exist.
- `tee` displays and records output; never redirect raw secret material into the submission directory.
- `sha256sum` is an integrity identifier, not a confidentiality control.

### Minimal validation pattern

1. Re-run the baseline identity command.
2. Reproduce the observation with one narrow read-only command.
3. If a proof action is required, use only the mentor-approved fixture and stop immediately after the intended flag/evidence appears.
4. Re-run `id` or inspect the designated proof artifact. Do not create persistence.
5. Tell the mentor what, if anything, changed. If you created a file as part of an approved fixture, remove only that exact file using the lab’s documented cleanup method; do not issue broad deletion commands.

### Report template

```text
Finding: [short root-cause title]
Scope: [target IP / service / path]
Precondition: [account, group, or permission]
Observation: [command + timestamp + sanitized output]
Reasoning: [why the boundary matters]
Minimal validation: [approved proof, stopped at flag]
Impact: [what this lab account could do]
Root cause: [misconfiguration or unsafe design]
Remediation: [owner/mode/path/environment/credential fix]
Retest: [read-only check showing the fix]
Cleanup: [exact participant-created artifacts and status]
```

### Common mistakes and safety boundary

Do not claim “root” from a root-owned file, SUID bit, or group membership alone. Do not paste full terminal history with credentials. Do not repair the target during the challenge; remediation is a report deliverable unless the mentor explicitly provides a repair window.

### Mini exercise and summary

Turn one candidate into a one-page finding with a sanitized evidence chain. Checkpoint: a reviewer should be able to reproduce the observation without receiving a secret. Next: [mini-CTF lab checklist](#14-mini-ctf-lab-checklist).

## 14. Mini-CTF lab checklist

### Target-author checklist (Ubuntu)

- [ ] Target is Ubuntu 24.04 or the mentor-approved Ubuntu image.
- [ ] Target has one assigned WireGuard address and no public exposure of vulnerable services.
- [ ] Attacker and target peers are distinct; the owner cannot solve their own challenge.
- [ ] Challenge declares at least three services and the portal target IP matches the assigned target peer.
- [ ] Initial foothold is possible with the intended service and no brute force.
- [ ] At least one enumeration clue leads to a bounded PE hypothesis.
- [ ] The PE boundary is local to the challenge (sudo/SUID/SGID/capability/writable path/cron/systemd/config).
- [ ] Flag is case-sensitive and stored only at the intended endpoint.
- [ ] Intended path, evidence expectations, and remediation are documented for mentor review.
- [ ] A clean retest confirms the lab works from a fresh non-owner account.

### Attacker checklist (Kali VM/WSL)

- [ ] WireGuard is connected using the portal-generated one-time setup flow.
- [ ] Confirm the target IP and declared ports before probing.
- [ ] Capture baseline identity, OS, route, and timestamp.
- [ ] Enumerate in the order: identity → services → processes → files/config → privilege boundary.
- [ ] Validate only the intended path and stop at the flag.
- [ ] Save sanitized evidence and a concise report.

### Mentor review checklist

- [ ] Ownership and target peer are correct.
- [ ] Player-facing text does not disclose owner, intended path, PE technique, or flag location.
- [ ] All commands in the challenge are read-only or explicitly bounded.
- [ ] No persistence, destructive behavior, brute force, kernel exploit, or public target exposure is required.
- [ ] Light Check confirms target reachability, declared ports, field/flag format, and ownership.
- [ ] The reviewer can return the lab with a concrete revision note.

## 15. Original diagram specifications

These are specifications for diagrams to draw in the Week 4 slides/portal; no external image is copied.

1. **WireGuard scope boundary:** three columns—Kali attacker peer, WireGuard hub, Ubuntu target peers—with a blue tunnel line, a red “public internet cannot reach target services” boundary, and labels for portal-public versus target-private traffic.
2. **Credential transition ladder:** a vertical ladder from real UID → effective UID/GID → supplementary groups → filesystem permission check → capability check. Add a side branch for SUID/SGID `execve` transition and a stop sign at “proof, then stop.”
3. **Enumeration funnel:** wide inputs (scope, identity, network, processes, filesystem, services) narrow into “candidate,” then “minimal validation,” then “evidence/report.” Use one red “out of scope” branch for brute force/destructive actions.
4. **Privilege-boundary chain:** `trigger → privileged process → executable/script → dependency/path/config → resulting operation`; annotate each edge with the question the solver must answer.
5. **Cron/systemd relationship:** timer/cron trigger on the left, service command in the center, user/group and working directory below, file ownership on the right. Highlight the only valid finding path: privileged execution plus attacker-controlled dependency.
6. **Report evidence card:** a four-box card—Observation, Consequence, Proof, Remediation—with a lock icon over secrets and a timestamp line under every evidence item.

## 16. Source-to-claim matrix

| Source | Claims used in this curriculum | Modules |
|---|---|---|
| [Linux `credentials(7)`](https://man7.org/linux/man-pages/man7/credentials.7.html) | Real/effective/saved IDs, filesystem IDs, supplementary groups, and credential changes | 1, 3, 7 |
| [Linux `capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) | Root versus capabilities; capability meanings and per-thread model | 1, 8 |
| [Linux `inode(7)`](https://man7.org/linux/man-pages/man7/inode.7.html) | Inode ownership, mode bits, SUID/SGID/sticky bits, permission-bit masks | 1, 5, 7 |
| [Linux `path_resolution(7)`](https://man7.org/linux/man-pages/man7/path_resolution.7.html) | Directory search permission and path-component reasoning | 1, 5, 9 |
| [Linux `execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) | Executable credential transition context | 7 |
| [Linux `proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html) | `/proc` as process/system interface and read/write caution | 2, 4 |
| [Linux `proc_pid(5)`](https://www.man7.org/linux/man-pages/man5/proc_pid.5.html) | Per-process files and ownership/visibility context | 4 |
| [GNU/Linux `find(1)`](https://man7.org/linux/man-pages/man1/find.1.html) | Expression evaluation, `-xdev`, permission predicates, and scoped discovery | 2, 5, 7, 11 |
| [`sudoers(5)`](https://man7.org/linux/man-pages/man5/sudoers.5.html) | Sudo policy, arguments, environment, authentication, and logging | 6, 13 |
| [`crontab(5)`](https://man7.org/linux/man-pages/man5/crontab.5.html) | Cron ownership, format, file permission and newline caveats | 10 |
| [`systemd.timer(5)`](https://man7.org/linux/man-pages/man5/systemd.timer.5.html) | Timer-to-service relationship and activation semantics | 10 |
| [`systemd.service(5)`](https://man7.org/linux/man-pages/man5/systemd.service.5.html) | Service execution context and unit behavior | 10 |
| [`ip(8)`](https://man7.org/linux/man-pages/man8/ip.8.html) | Interface/address/route inspection | 4, 12 |
| [`ss(8)`](https://man7.org/linux/man-pages/man8/ss.8.html) | Local listening socket inspection | 4, 12 |
| [`ps(1)`](https://man7.org/linux/man-pages/man1/ps.1.html) | Process selection and controlled output columns | 4 |
| [`id(1)`](https://man7.org/linux/man-pages/man1/id.1.html) | UID/GID/group inspection command | 2, 3, 13 |
| [`passwd(5)`](https://man7.org/linux/man-pages/man5/passwd.5.html), [`group(5)`](https://man7.org/linux/man-pages/man5/group.5.html), [`shadow(5)`](https://man7.org/linux/man-pages/man5/shadow.5.html) | Account, group, and protected password-file roles | 3, 11 |
| [WireGuard Quick Start](https://www.wireguard.com/quickstart/) | Peer tunnel/key/route setup context | 0, 12 |
| [MITRE T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Local account discovery classification | 2, 4 |
| [MITRE T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Local group discovery classification | 2, 3 |
| [MITRE T1057](https://attack.mitre.org/techniques/T1057/) | Process discovery classification | 2, 4 |
| [MITRE T1016.001](https://attack.mitre.org/techniques/T1016/001/) | Network configuration discovery classification | 2, 4, 12 |
| [MITRE T1083](https://attack.mitre.org/techniques/T1083/) | File/directory discovery classification | 2, 5, 11 |
| [MITRE T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Setuid/setgid abuse classification | 7 |
| [MITRE T1574.007](https://attack.mitre.org/techniques/T1574/007/) | PATH interception classification | 9 |
| [MITRE T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron scheduled-task classification | 10 |
| [MITRE T1543.002](https://attack.mitre.org/techniques/T1543/002/) | Systemd service modification classification | 10 |
| [MITRE T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials-in-files classification | 11 |
| [MITRE T1552.004](https://attack.mitre.org/techniques/T1552/004/) | Private-key discovery classification | 11 |

All source links above are first-party or project-owned technical references: Linux man-pages, GNU/Linux command manuals, systemd documentation, WireGuard documentation, and MITRE ATT&CK. They were checked on 29 August 2026; command behavior and distribution defaults should still be verified on the exact Ubuntu/Kali image used for LAS.

## 17. Suggested next-step links for the portal

- **Learn / Identity:** link to [`credentials(7)`](https://man7.org/linux/man-pages/man7/credentials.7.html), [`id(1)`](https://man7.org/linux/man-pages/man1/id.1.html), and [`inode(7)`](https://man7.org/linux/man-pages/man7/inode.7.html).
- **Learn / Enumeration:** link to [`proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html), [`ps(1)`](https://man7.org/linux/man-pages/man1/ps.1.html), [`ip(8)`](https://man7.org/linux/man-pages/man8/ip.8.html), [`ss(8)`](https://man7.org/linux/man-pages/man8/ss.8.html), and [`find(1)`](https://man7.org/linux/man-pages/man1/find.1.html).
- **Learn / Privilege boundaries:** link to [`sudoers(5)`](https://man7.org/linux/man-pages/man5/sudoers.5.html), [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html), and [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html).
- **Learn / Scheduled execution:** link to [`crontab(5)`](https://man7.org/linux/man-pages/man5/crontab.5.html), [`systemd.timer(5)`](https://man7.org/linux/man-pages/man5/systemd.timer.5.html), and [`systemd.service(5)`](https://man7.org/linux/man-pages/man5/systemd.service.5.html).
- **Setup / Scope:** link to the [WireGuard Quick Start](https://www.wireguard.com/quickstart/) and keep the portal’s generated peer configuration authoritative.
