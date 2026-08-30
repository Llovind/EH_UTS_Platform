#!/usr/bin/env bash
set -euo pipefail

# LAS Week 4 PE practice lab. This deliberately vulnerable lab is for a local
# Ubuntu-on-WSL test machine only. It refuses to run on a normal host.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: wsl.exe -d Ubuntu-24.04 -u root -- bash /path/to/las-w4-pe-lab.sh setup" >&2
  exit 1
fi
if ! grep -Eiq 'microsoft|wsl' /proc/version 2>/dev/null; then
  echo "Refusing to install: this script is limited to Ubuntu on WSL2." >&2
  exit 1
fi

LAB_ROOT='/opt/las-w4-lab'
LAB_USER='las-trainee'
LAB_GROUP='las-audit'
EXPORTOR='/usr/local/bin/las-export'
SUDOERS='/etc/sudoers.d/las-w4-lab'
FLAG_FILE='/root/las-w4-flag.txt'

write_root_file() {
  local path="$1" mode="$2"
  install -o root -g root -m "$mode" /dev/null "$path"
  cat > "$path"
}

setup_lab() {
  # Keep a root-owned copy so the mentor reset command remains available even
  # after the repository is moved or unmounted from WSL.
  install -o root -g root -m 0700 "$0" /root/las-w4-pe-lab.sh
  rm -f /tmp/las-w4-proof.txt /tmp/las-w4-export-preview.txt
  getent group "$LAB_GROUP" >/dev/null || groupadd --system "$LAB_GROUP"
  if ! id "$LAB_USER" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$LAB_USER"
    passwd --lock "$LAB_USER" >/dev/null
  fi
  usermod --append --groups "$LAB_GROUP" "$LAB_USER"

  install -d -o root -g root -m 0755 "$LAB_ROOT"
  install -d -o root -g root -m 0755 "$LAB_ROOT/data"
  install -d -o "$LAB_USER" -g "$LAB_GROUP" -m 0775 "$LAB_ROOT/tools"
  install -d -o root -g root -m 0755 "$LAB_ROOT/evidence"

  write_root_file "$FLAG_FILE" 0600 <<'EOF'
MBC{nightly_export_boundary_2026}
EOF

  write_root_file "$LAB_ROOT/START-HERE.txt" 0644 <<'EOF'
LAS WEEK 04 · THE NIGHTLY EXPORT
================================

You are the trainee account inside an authorized local practice target.
Your objective is to recover the flag from the root-only location while
preserving an evidence trail. Do not change ownership or permissions on the
target, and do not use password guessing.

Suggested flow
-------------
1. Record your identity and group membership.
2. Inventory the local privilege boundary and read the allowed command.
3. Trace every path component used by that command.
4. Identify the dependency that a privileged process executes.
5. Prove impact with the smallest possible controlled helper.
6. Save command output under /opt/las-w4-lab/evidence/ and explain the fix.

The root-only flag is stored at a conventional location, but the intended
path is to reach it through the nightly export workflow. The owner will not
tell you which file in the workflow is the weak boundary.

Reset (mentor/host only)
------------------------
From Windows PowerShell:
  wsl.exe -d Ubuntu-24.04 -u root -- /usr/local/sbin/las-w4-reset
EOF

write_root_file "$LAB_ROOT/data/weekly-report.txt" 0644 <<'EOF'
Weekly export: 2026-W35
Owner: operations
Status: ready for the nightly archive
EOF

write_root_file "$LAB_ROOT/tools/report-helper" 0755 <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
input="${1:?report input is required}"
output="/tmp/las-w4-export-preview.txt"
{
  printf 'Export preview\n'
  cat "$input"
} > "$output"
printf 'Preview written to %s\n' "$output"
EOF

write_root_file "$EXPORTOR" 0755 <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LAB_ROOT='/opt/las-w4-lab'
echo '[export] assembling weekly report'
"$LAB_ROOT/tools/report-helper" "$LAB_ROOT/data/weekly-report.txt"
echo '[export] archive step complete'
EOF

write_root_file "$LAB_ROOT/evidence/README.txt" 0644 <<'EOF'
Store copies of relevant command output here. Keep the evidence minimal:
identity, sudo policy, path permissions, execution proof, and remediation.
EOF

cat > "$SUDOERS" <<EOF
# Deliberately vulnerable LAS Week 4 training rule. Local WSL lab only.
$LAB_USER ALL=(root) NOPASSWD: $EXPORTOR
EOF
chown root:root "$SUDOERS"
chmod 0440 "$SUDOERS"
visudo --check --file="$SUDOERS"

write_root_file /root/las-w4-solution.md 0600 <<'EOF'
# Mentor solution — The Nightly Export

The trainee can run `/usr/local/bin/las-export` as root without a password.
That script executes `/opt/las-w4-lab/tools/report-helper`. The tools
directory is writable by `las-trainee`, so the helper is a privileged writable
dependency. A controlled replacement can copy `/root/las-w4-flag.txt` to
`/tmp/las-w4-proof.txt`; restore the helper and record the evidence afterward.

Hardening: remove the broad NOPASSWD rule, make the helper and every parent
directory root-owned and non-writable by the trainee, and use an absolute,
reviewed dependency with a least-privilege service account.
EOF

cat > /root/las-w4-reset.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "$(dirname "$0")/las-w4-pe-lab.sh" setup
EOF
chmod 0700 /root/las-w4-reset.sh

install -o root -g root -m 0700 /dev/null /usr/local/sbin/las-w4-reset
cat > /usr/local/sbin/las-w4-reset <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /root/las-w4-pe-lab.sh setup
EOF
chmod 0700 /usr/local/sbin/las-w4-reset

cat > "/home/$LAB_USER/.bash_profile" <<'EOF'
if [[ -t 1 ]]; then
  printf '\nLAS Week 04 lab ready. Start with: cat /opt/las-w4-lab/START-HERE.txt\n\n'
fi
EOF
chown "$LAB_USER:$LAB_USER" "/home/$LAB_USER/.bash_profile"
chmod 0644 "/home/$LAB_USER/.bash_profile"

echo "LAS Week 4 PE lab installed for $LAB_USER."
echo "Enter it with: wsl.exe -d Ubuntu-24.04 -u $LAB_USER"
}

case "${1:-setup}" in
  setup|reset) setup_lab ;;
  *) echo "Usage: $0 setup|reset" >&2; exit 2 ;;
esac
