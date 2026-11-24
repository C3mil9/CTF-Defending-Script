#!/usr/bin/env bash
# lib/harden.sh — Stage and apply SSH/kernel policy with recoverable backups.
# Loaded by ctf-defend.sh. Keep module loading free of host mutations;
# command functions run only after the entry point dispatches a mode.

# Print the proposed kernel policy; this function does not apply it.
# Reading interface names here keeps previews and applied settings consistent.
sysctl_settings() {
    cat <<'SETTINGS'
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
SETTINGS
    # Setting only conf.all does not disable redirects on existing IPv4 host
    # interfaces. Address each current interface; slash notation preserves dots
    # in interface names such as vlan.42.
    local family path interface
    for family in ipv4 ipv6; do
        for path in "$PROC_SYS_ROOT/net/$family/conf/"*/accept_redirects; do
            [[ -f $path ]] || continue
            interface=${path%/accept_redirects}; interface=${interface##*/}
            [[ $interface != all && $interface != default ]] || continue
            if [[ $interface =~ ^[A-Za-z0-9_.-]+$ ]]; then
                printf '%s=0\n' "${path#"$PROC_SYS_ROOT"/}"
            else
                printf 'Skipping nonstandard interface name: %q\n' "$interface" >&2
            fi
        done
    done
}

# Read effective sshd output rather than hand-parsing Include/Match syntax.
# Preserve stricter global limits while capping weak or unlimited defaults.
ssh_limits() {
    local auth=4 grace=30 existing
    existing=$(awk '$1 == "maxauthtries" {print $2}' "$1")
    if [[ $existing =~ ^[0-9]{1,5}$ ]] && (( 10#$existing < auth )); then auth=$((10#$existing)); fi
    existing=$(awk '$1 == "logingracetime" {print $2}' "$1")
    if [[ $existing =~ ^[0-9]{1,5}$ ]] && (( 10#$existing > 0 && 10#$existing < grace )); then grace=$((10#$existing)); fi
    printf '%s %s\n' "$auth" "$grace"
}

# Build a replacement SSH configuration without touching the live file.
# Put our global block first, and replace our previous block on repeated runs.
ssh_candidate() {
    local auth=${2:-4} grace=${3:-30}
    cat <<SSH
# BEGIN CTF-DEFEND
PermitEmptyPasswords no
MaxAuthTries $auth
LoginGraceTime $grace
LogLevel VERBOSE
# END CTF-DEFEND
SSH
    awk '
        /^# BEGIN CTF-DEFEND$/ {skip=1; next}
        /^# END CTF-DEFEND$/ {skip=0; next}
        !skip {print}
    ' "$1"
}

# Apply a staged transaction: preview, preflight, back up, validate, apply.
# Once harden.pending exists, cleanup() restores this run on ordinary failure.
harden() {
    say 'SSH: PermitEmptyPasswords=no; MaxAuthTries capped at 4; LoginGraceTime capped at 30s; LogLevel=VERBOSE.'
    say 'Lower existing SSH attempt/time limits are preserved; unlimited grace becomes 30s.'
    say 'Existing root-login and password-authentication policies remain in effect.'
    say 'Kernel settings (supported keys only):'
    sysctl_settings
    (( APPLY == 1 )) || { say 'Preview only. Add --apply to back up and apply these settings.'; return; }
    need sysctl
    init_state
    ensure_no_pending
    require_systemd
    [[ -d /etc/sysctl.d && ! -L $SYSCTL_CONF ]] || die 'Expected a regular sysctl.d configuration path.'
    [[ ! -e $SYSCTL_CONF || -f $SYSCTL_CONF ]] || die 'sysctl configuration is not a regular file.'
    local unit='' key value auth grace
    if [[ -e $SSH_CONF ]]; then
        need ss
        [[ -f $SSH_CONF && ! -L $SSH_CONF ]] || die 'SSH config must be a regular file.'
        find_sshd || die 'SSH config exists but sshd is not installed.'
        "$SSHD" -t || die 'Existing SSH configuration is invalid; fix it before hardening.'
        unit=$(ssh_unit)
        if [[ -z $unit ]] && ss -H -lntp 2>/dev/null | awk '/"sshd"/ {found=1} END {exit !found}'; then
            die 'sshd is running outside a recognized systemd service; handle its reload manually.'
        fi
    fi
    # Capture originals and live values before replacing either configuration.
    new_run harden
    printf '%s\n' "$unit" > "$RUN/ssh.unit"
    if [[ -e $SYSCTL_CONF ]]; then cp -a -- "$SYSCTL_CONF" "$RUN/sysctl.conf.before";
    else touch "$RUN/sysctl.conf.absent"; fi
    : > "$RUN/sysctl.live.before"
    printf '# Managed by ctf-defend.sh\n' > "$RUN/sysctl.conf.after"
    while IFS='=' read -r key value; do
        if sysctl -n "$key" > "$RUN/value.tmp" 2>/dev/null; then
            printf '%s=%s\n' "$key" "$(cat "$RUN/value.tmp")" >> "$RUN/sysctl.live.before"
            printf '%s=%s\n' "$key" "$value" >> "$RUN/sysctl.conf.after"
        else say "Skipping unsupported sysctl: $key"; fi
    done < <(sysctl_settings)
    chmod 644 "$RUN/sysctl.conf.after"
    if [[ -e $SSH_CONF ]]; then
        cp -a -- "$SSH_CONF" "$RUN/sshd_config.before"
        cp -a -- "$SSH_CONF" "$RUN/sshd_config.after"
        "$SSHD" -T -f "$SSH_CONF" > "$RUN/ssh.effective.before"
        read -r auth grace < <(ssh_limits "$RUN/ssh.effective.before")
        ssh_candidate "$SSH_CONF" "$auth" "$grace" > "$RUN/sshd_config.after"
        "$SSHD" -t -f "$RUN/sshd_config.after" || die 'Candidate SSH config failed validation.'
        "$SSHD" -T -f "$RUN/sshd_config.after" > "$RUN/ssh.effective.after"
    fi
    # From this point, EXIT cleanup owns recovery until the pending marker clears.
    ACTIVE_HARDEN=$RUN
    touch "$RUN/harden.pending"
    replace_config "$RUN/sysctl.conf.after" "$SYSCTL_CONF"
    sysctl -q -p "$SYSCTL_CONF"
    if [[ -f $RUN/sshd_config.after ]]; then
        replace_config "$RUN/sshd_config.after" "$SSH_CONF"
        "$SSHD" -t
        [[ -z $unit ]] || systemctl reload "$unit"
    fi
    # Commit only after kernel application and the SSH reload both succeed.
    rm -f -- "$RUN/harden.pending"
    # shellcheck disable=SC2034 # cleanup() in restore.sh consumes this shared flag.
    ACTIVE_HARDEN=''
    touch "$RUN/applied"
    say "Applied. Restore with: sudo bash ctf-defend.sh restore --run ${RUN##*/} --apply"
    say 'Verify a NEW SSH login and the scoring dashboard now. SSH Match rules can override globals.'
}
