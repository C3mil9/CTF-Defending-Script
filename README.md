# CTF Defense Kit

A Bash helper for defending your team's Linux VMs in attack/defense cybersecurity competitions. It creates an audit report, applies a small hardening baseline, changes selected local passwords, and builds a host firewall around the ports your services need.

**Start with `audit`. Read the competition service list before applying changes.** Run the script inside each assigned Linux guest. The firewall needs every scored TCP/UDP port and your actual SSH port.

## Features

| Command | What it does |
| --- | --- |
| `audit` | Reports listeners, running services, accounts, administrative groups, logins, firewall rules, cron file names, timers, and selected configuration hashes. |
| `harden` | Backs up configuration and live kernel values, applies supported hardening settings, validates SSH configuration, and reloads an active SSH service. |
| `passwords` | Opens the normal hidden password prompt for explicitly named local accounts. |
| `firewall` | Builds an IPv4/IPv6 nftables INPUT allowlist, with rollback on ordinary failure and a detached rollback timer. |
| `restore` | Restores the configuration and live settings captured by a particular hardening or firewall run. |

Hardening, password changes, firewall changes, and restoration **preview by default**. Add `--apply` to make changes. Audit writes only this tool's private report files.

## Requirements

- Linux with Bash 4 or newer. Designed for systemd hosts such as Debian, Ubuntu, and Kali Linux.
- Root access through `sudo` for auditing and applying changes.
- Standard GNU/Linux tools: `coreutils`, `findutils`, `grep`, `awk`, `util-linux` (`flock`), `procps` (`sysctl`), and `iproute2` (`ip`, `ss`).
- `nftables` and a running systemd service manager for firewall application.
- An interactive terminal for applying firewall rules or changing passwords.
- OpenSSH server for SSH hardening. Existing configuration and host keys must pass `sshd -t`.

Most tools are already present on a full Linux VM. On Debian/Ubuntu/Kali, install missing dependencies before the round if your rules allow package installation:

```bash
sudo apt-get install bash coreutils findutils grep gawk util-linux procps iproute2 nftables
```

The script checks requirements and runs locally. It does not download tools or install packages during execution. Run it on Linux; macOS's default Bash and Windows PowerShell are outside its target environment.

## Quick start

From the repository directory:

```bash
bash -n ctf-defend.sh
sudo bash ./ctf-defend.sh audit
```

Compare the audit's listening ports with the official briefing packet. Record which services must stay reachable, including dependencies and scoring requirements.

Preview and apply the baseline:

```bash
bash ./ctf-defend.sh harden
sudo bash ./ctf-defend.sh harden --apply
```

Change the passwords for your actual local accounts. Replace `kali,root` with the account names assigned to your team, and follow competition restrictions on shared or scored accounts:

```bash
bash ./ctf-defend.sh passwords --users kali,root
sudo bash ./ctf-defend.sh passwords --users kali,root --apply
```

`passwd` asks for each new password twice without displaying it. Coordinate unique passwords with your teammate through your team's private channel. Test a new login before closing your existing session. If one change fails, earlier successful changes remain in effect; password changes have no automatic rollback.

### Firewall example: SSH + a website

This example assumes SSH on TCP 22 and HTTP/HTTPS on TCP 80/443. Replace the list with **all** ports required on that VM.

```bash
# Preview the generated rules.
bash ./ctf-defend.sh firewall --tcp 22,80,443

# Apply temporarily, then confirm after testing.
sudo bash ./ctf-defend.sh firewall --tcp 22,80,443 --apply
```

While the script waits, open a **new** SSH connection from another host, test each scored service from its expected network, and check the scoring dashboard. Existing connections are permitted by the rules and cannot prove that new connections work. Type `KEEP` and press Enter within 90 seconds after your checks pass.

Any other answer or an input timeout triggers immediate restoration. A separate systemd timer also attempts restoration after 120 seconds, with about one second of additional scheduling tolerance under normal load. That timer survives a disconnected terminal or termination of the main script. A stopped service manager, reboot, or broken nftables/kernel environment can prevent execution; keep the VM console available when changing network policy.

Examples for other service lists:

```bash
# SSH, web, and DNS: DNS commonly needs BOTH TCP and UDP 53.
sudo bash ./ctf-defend.sh firewall --tcp 22,53,80,443 --udp 53 --apply

# Custom SSH port and an example FTP passive-data range.
# Use the passive range actually configured on your FTP server.
sudo bash ./ctf-defend.sh firewall --tcp 2222,21,30000-30100 --apply

# UDP-only service on a machine with no required SSH/TCP listener.
sudo bash ./ctf-defend.sh firewall --tcp none --udp 53 --apply
```

Detected `sshd` listening ports and the current SSH port, when present in `SSH_CONNECTION`, must be included. Review socket-activated SSH, custom daemons, and environment changes caused by `sudo` manually. Opening a port in the allowlist does not start a service.

### Firewall behavior

- Creates/replaces only its own `inet ctf_defend` table. Other firewall tables remain in place and can still reject traffic allowed here.
- Filters traffic addressed to the host's local processes for both IPv4 and IPv6.
- Allows loopback, established/related connections, ICMP/ICMPv6, DHCP client replies, and the specified TCP/UDP ports. Other new INPUT traffic is dropped.
- Allows listed service ports from **any source** accepted by other network controls. Use the competition's network policy when deciding what to expose.
- Leaves outbound and forwarded traffic under the existing policy. Docker-published ports and routed container/VM traffic need separate firewall rules because they can use the FORWARD path.
- Refuses application when it detects active UFW or firewalld management. Make changes through the existing firewall manager on those hosts.
- Applies for the current boot. Reapply after reboot. It creates no boot service and does not enable `nftables.service` or replace `/etc/nftables.conf`.
- Preserves established sessions, including any malicious sessions already connected. Investigate sessions and persistence separately.

## What `harden` changes

### SSH

The script prepends an idempotent managed block to `/etc/ssh/sshd_config`. With default or weaker existing limits, it looks like this:

```text
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
LogLevel VERBOSE
```

Lower existing `MaxAuthTries` and positive `LoginGraceTime` values are preserved. An unlimited login grace period (`0`) becomes 30 seconds.

It validates existing and candidate configurations before replacement and validates again before reloading `ssh.service` or `sshd.service`. It reloads an already-running recognized service. An inactive service receives the configuration for its next start.

Existing `PermitRootLogin`, `PasswordAuthentication`, key authentication, SSH ports, and user/group allowlists remain configured as before. SSH `Match` blocks and daemon command-line options may override global values; audit and candidate output are global views. `MaxAuthTries` limits attempts per connection; it provides no cross-connection ban mechanism.

The block persists across reboots. An ordinary application failure triggers restoration of backed-up files and live values. Hardening has no connectivity confirmation timer; verify a new SSH login immediately. Abrupt power loss or `SIGKILL` can interrupt hardening; use the printed run ID to restore an unfinished run.

### Kernel values

Supported keys are saved to `/etc/sysctl.d/99-ctf-defend.conf` and applied with `sysctl -p` on that file:

```text
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
```

The script also adds `accept_redirects=0` for each current IPv4/IPv6 interface, using slash-separated sysctl paths so names such as `vlan.42` work correctly. Changing only the IPv4 `all` setting would leave existing host interfaces able to accept redirects. Nonstandard interface names outside letters, numbers, dots, underscores, and hyphens are reported and skipped.

Unsupported keys are skipped. These settings restrict kernel information disclosure and unsafe link behavior, enable SYN cookies, and disable acceptance of ICMP redirects through the listed controls. They can affect diagnostics or labs deliberately exercising those features. Review them against the VM's role. Other sysctl files loaded later can override persistent values at boot.

## Reports, backups, and recovery

Audit, hardening, and firewall commands print a `RUN_ID` and store files in a root-only directory:

```text
/var/lib/ctf-defend/runs/<RUN_ID>/
```

Audit runs contain `audit.txt`. Hardening runs contain original configuration and saved live sysctl values. Firewall runs contain the previous and proposed dedicated nftables table plus the detached rollback script. Passwords and raw shadow-file contents are excluded from reports; reports still contain private infrastructure details and should stay private.

To restore a hardening or firewall run, use its actual printed ID:

```bash
# Replace RUN_ID_HERE with the ID printed by the script.
sudo bash ./ctf-defend.sh restore --run RUN_ID_HERE --apply
```

**Restore newest runs first.** An older restore can overwrite a later edit to the same configuration or dedicated firewall table. Restoration covers only changes captured by that run. Local passwords, application data, unrelated firewall tables, and application credentials require separate recovery.

If an unfinished run is detected, new hardening/firewall application stops until that run is restored or its firewall rollback completes. Audit and explicit restoration remain available after the previous process releases its operation lock.

If network access is lost, use the VM console. For an emergency removal of this helper's firewall table:

```bash
sudo nft delete table inet ctf_defend
```

This immediately removes the helper's INPUT restrictions; other firewall policies still apply. Prefer the normal restore command when recovering a previous version of this table. Retain the backup directory until recovery is complete.

## Suggested competition workflow

1. Read the briefing packet and scoring requirements. Save a VM snapshot if the rules and platform support it.
2. Run `audit` and map listeners to required services. Review unexpected UID 0 users, administrative access, SSH keys, cron jobs, and timers.
3. Coordinate account-password changes with your teammate, including restrictions on scored credentials.
4. Preview/apply `harden`; verify a new SSH login and service health.
5. Build the complete TCP/UDP allowlist. Apply it, check new connections and scoring, then confirm `KEEP`.
6. Fix application vulnerabilities and database exposure using the competition requirements. Re-run `audit` after significant changes and compare reports privately.

Patching packages, changing database/application credentials, removing suspicious accounts or keys, and stopping services need service-specific review. The helper leaves those tasks to the team so required applications can be tested as each issue is fixed.

## Validation and testing

```bash
bash -n ctf-defend.sh
bash tests/test.sh
```

Tests use temporary files and mocked system commands. They cover argument validation, port ranges and injection rejection, preservation of stricter SSH limits, interface-specific redirect settings, managed-block idempotence, hardening restoration, firewall rollback, and pending-run protection. When the util-linux `script` command is available, they also exercise the complete firewall CLI in a pseudo-terminal: KEEP, revert, timer-arm failure, and nft application failure. They leave the test host's system configuration and firewall untouched.

Optional static analysis:

```bash
shellcheck -x -P SCRIPTDIR ctf-defend.sh tests/test.sh
```

OpenSSH configuration validation was also checked with a disposable host key. Live packet filtering and real systemd timer execution require a disposable Linux VM; those integration checks have not been run for this release.

## Files and publishing

| File | Purpose |
| --- | --- |
| `ctf-defend.sh` | Main Bash script and built-in `--help` |
| `README.md` | Setup, examples, behavior, and recovery |
| `tests/test.sh` | Isolated regression tests |
| `.gitignore` | Excludes common reports, backups, and secrets |

Create your GitHub repository and add these files. Keep audit reports, team passwords, VM backups, and private competition information outside the repository. No license is included; choose one if you want to grant reuse rights explicitly.

## Technical references

- [OpenSSH server configuration](https://man.openbsd.org/sshd_config)
- [OpenSSH server validation options](https://man.openbsd.org/sshd)
- [nftables chains, hooks, and priorities](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
- [nftables command manual](https://manpages.debian.org/bookworm/nftables/nft.8.en.html)
- [systemd-run transient timers](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html)
- [Linux kernel sysctl documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/index.html)
