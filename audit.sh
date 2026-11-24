#!/usr/bin/env bash
# lib/audit.sh — Read the host inventory and write private audit reports.
# Loaded by ctf-defend.sh. Keep module loading free of host mutations;
# command functions run only after the entry point dispatches a mode.

# Format report sections consistently without adding color escape sequences.
section() { printf '\n--- %s ---\n' "$1"; }

# Treat missing tools and diagnostic failures as report entries.
# A short timeout keeps one unhealthy service from stalling the inventory.
audit_cmd() {
    local cmd=$1
    if command -v "$cmd" >/dev/null 2>&1; then
        timeout 15 "$@" || printf '[%s unavailable, failed, or timed out]\n' "$cmd"
    else
        printf '[%s not installed]\n' "$cmd"
    fi
}

# Collect an inventory for human review; do not repair accounts or services.
# Process names and empty-password account names avoid dumping credential data.
audit_body() {
    say "CTF defense audit v$VERSION | $(date -u +%FT%TZ)"
    section 'Host and addresses'
    uname -srmo
    [[ ! -r /etc/os-release ]] || cat /etc/os-release
    audit_cmd hostname
    audit_cmd ip -brief address
    audit_cmd ip route show
    section 'TCP/UDP listeners: map these to the competition service list'
    audit_cmd ss -lntup
    section 'Anonymous FTP: configuration indicators and read-only loopback login probes'
    audit_ftp
    section 'SUID/SGID files on the root filesystem'
    audit_suid
    section 'SSH authorized keys: ownership, permissions, counts, and fingerprints'
    audit_authorized_keys
    section 'Running and failed services'
    audit_cmd systemctl --no-pager --plain list-units --type=service --state=running
    audit_cmd systemctl --no-pager --plain --failed
    section 'UID 0 accounts (review unexpected names)'
    awk -F: '$3 == 0 {print $1 " uid=" $3 " shell=" $7}' /etc/passwd
    section 'Local accounts with login shells (service accounts may be legitimate)'
    awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1 " uid=" $3 " shell=" $7}' /etc/passwd
    section 'Administrative groups and sudoers syntax'
    getent group sudo wheel admin 2>/dev/null || true
    audit_cmd visudo -c
    section 'Local accounts with an empty password field (names only)'
    if [[ -r /etc/shadow ]]; then awk -F: '$2 == "" {print $1}' /etc/shadow; else say '[shadow unavailable]'; fi
    section 'Sessions and recent logins'
    audit_cmd who
    audit_cmd last -n 12 -w
    section 'Effective global SSH settings; Match blocks may change individual connections'
    if find_sshd; then
        "$SSHD" -T 2>&1 | awk '/^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|logingracetime|loglevel|authorizedkeysfile|authorizedkeyscommand|strictmodes|allowusers|allowgroups|denyusers|denygroups) /' || true
    else say '[OpenSSH server not installed]'; fi
    section 'Existing firewall: another table can still reject an allowed port'
    audit_cmd nft list ruleset
    audit_cmd iptables -S
    audit_cmd ip6tables -S
    command -v ufw >/dev/null 2>&1 && audit_cmd ufw status verbose
    command -v firewall-cmd >/dev/null 2>&1 && audit_cmd firewall-cmd --state
    section 'Processes (names only; command-line secrets excluded)'
    audit_cmd ps -eo pid,ppid,user,comm --sort=user
    section 'Cron file inventory and scheduled timers (review manually)'
    audit_cmd find /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron -maxdepth 2 -type f -ls
    audit_cmd systemctl --no-pager list-timers --all
    section 'Critical configuration hashes (store this report privately)'
    local path
    for path in /etc/passwd /etc/group /etc/sudoers /etc/crontab "$SSH_CONF" "$SYSCTL_CONF"; do
        [[ ! -f $path ]] || sha256sum -- "$path"
    done
    section 'Next steps'
    say 'Review authorized_keys, sudoers rules, cron contents, app users, and DB access manually.'
    say 'Use the scoring dashboard and a second host to verify required services after changes.'
    say 'Host INPUT filtering does not secure forwarded/Docker-published ports or fix application vulnerabilities.'
}

# Save the inventory under the same private state tree used for backups.
# Auditing writes a report but makes no service or firewall configuration changes.
audit() {
    need timeout
    init_state
    new_run audit
    # A private, root-owned directory prevents report symlink attacks.
    audit_body 2>&1 | tee "$RUN/audit.txt"
    say "Report: $RUN/audit.txt"
}
