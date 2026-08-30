# LAS Week 4 local PE practice lab

This folder contains a deliberately vulnerable, self-contained privilege-escalation exercise for the local Ubuntu 24.04 WSL2 instance. It does not open a network listener and refuses to install on a non-WSL host.

## Install or reset

Run from Windows PowerShell as the WSL root user:

```powershell
wsl.exe -d Ubuntu-24.04 -u root -- bash /mnt/c/Ez/TelU/MBC/LAS-RECRU/LAS-W4/portal/lab/las-w4-pe-lab.sh setup
```

Enter the target as the non-owner trainee account:

```powershell
wsl.exe -d Ubuntu-24.04 -u las-trainee
```

Inside the target, start with:

```bash
cat /opt/las-w4-lab/START-HERE.txt
```

The intended path is a writable helper used by a root-only export command. The challenge is to prove the trust boundary, recover the flag through a controlled helper, record minimal evidence, and explain the hardening. The mentor reset restores the helper and removes proof artifacts:

```powershell
wsl.exe -d Ubuntu-24.04 -u root -- /usr/local/sbin/las-w4-reset
```

This exercise is for the local training machine only. Never run it on the production VPS or an Internet-facing host.
