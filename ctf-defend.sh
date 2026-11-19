#!/usr/bin/env bash
# Local Linux CTF defense helper. See README.md before applying changes.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
export SYSTEMD_PAGER=cat
export SYSTEMD_COLORS=0

VERSION=1.0.0
STATE_ROOT=/var/lib/ctf-defend
SSH_CONF=/etc/ssh/sshd_config
SYSCTL_CONF=/etc/sysctl.d/99-ctf-defend.conf
PROC_SYS_ROOT=/proc/sys
NFT_TABLE=ctf_defend
ACTIVE_HARDEN=''
ACTIVE_FIREWALL=''
RUN=''
SSHD=''
APPLY=0
TCP_PORTS=''
UDP_PORTS=none
USERS=''
RESTORE_ID=''

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Required command missing: $1"; }
require_root() { (( EUID == 0 )) || die 'Run this command with sudo.'; }

usage() {
    cat <<'HELP'
ctf-defend.sh - local Linux CTF defense helper

  sudo bash ctf-defend.sh audit
  bash ctf-defend.sh harden                         # preview
  sudo bash ctf-defend.sh harden --apply
  bash ctf-defend.sh passwords --users kali,root    # preview
  sudo bash ctf-defend.sh passwords --users kali,root --apply
  bash ctf-defend.sh firewall --tcp 22,80,443 --udp 53
  sudo bash ctf-defend.sh firewall --tcp 22,80,443 --udp 53 --apply
  sudo bash ctf-defend.sh restore --run RUN_ID --apply

Commands:
  audit      Inventory accounts, listeners, services, firewall, cron, and hashes.
             Saves a private report beneath /var/lib/ctf-defend/runs/.
  harden     Back up configs; apply selected sysctl values and SSH auth limits.
             Validate SSH config and reload an already-running SSH service.
  passwords  Run the standard hidden passwd prompt for explicitly named LOCAL
             users. Changes are sequential; earlier successes are not undone.
  firewall   Preview/apply an IPv4+IPv6 nftables host INPUT port allowlist.
             Specify ALL scored TCP/UDP ports, including SSH. Ranges supported:
             --tcp 22,80,443,30000-30100. Use --tcp none for no TCP exceptions.
             Needs nftables, systemd, and a terminal when applying. Auto-reverts
             unless you confirm KEEP within 90 seconds; detached timer at 120s.
             Runtime only: reapply after reboot. Does not filter forwarded or
             Docker-published traffic. Other firewall rules still apply.
  restore    Restore a harden/firewall run by its printed RUN_ID. Restoring old
             runs can overwrite later changes: restore newest first.

Changes require --apply. Audit only writes this tool's private report files.
Targets: systemd Linux hosts with Bash 4+, especially Debian/Ubuntu/Kali.
Read README.md for scored-service checks, dependencies, and recovery details.
HELP
}

# Reject shell/nft syntax, empty CSV elements, invalid ports, and reversed ranges.
normalize_ports() {
    local input=$1 part first last result=''
    local -a parts=()
    [[ $input == none ]] && { printf 'none'; return; }
    [[ $input =~ ^[0-9,-]+$ && $input != ,* && $input != *, && $input != *,,* ]] || return 1
    IFS=, read -r -a parts <<< "$input"
    for part in "${parts[@]}"; do
        [[ $part =~ ^([0-9]{1,5})(-([0-9]{1,5}))?$ ]] || return 1
        first=$((10#${BASH_REMATCH[1]}))
        last=$first
        [[ -z ${BASH_REMATCH[3]:-} ]] || last=$((10#${BASH_REMATCH[3]}))
        (( first >= 1 && last <= 65535 && first <= last )) || return 1
        [[ -z $result ]] || result+=,
        result+=$first
        (( first == last )) || result+="-$last"
    done
    printf '%s' "$result"
}

port_in_list() {
    local port=$1 list=$2 part lo hi
    local -a parts=()
    [[ $list == none ]] && return 1
    IFS=, read -r -a parts <<< "$list"
    for part in "${parts[@]}"; do
        lo=${part%-*}; hi=${part#*-}
        (( port >= lo && port <= hi )) && return 0
    done
    return 1
}

parse_args() {
    MODE=${1:-audit}
    (( $# == 0 )) || shift
    case "$MODE" in help|-h|--help) usage; exit 0;;
        audit|harden|passwords|firewall|restore) ;;
        *) die "Unknown command: $MODE (try --help)";;
    esac
    local seen_tcp=0 seen_udp=0 seen_users=0 seen_run=0
    while (( $# )); do
        case "$1" in
            --apply) (( APPLY == 0 )) || die 'Duplicate --apply'; APPLY=1; shift;;
            --tcp|--udp|--users|--run)
                (( $# >= 2 )) || die "Missing value for $1"
                case "$1" in
                    --tcp) (( seen_tcp == 0 )) || die 'Duplicate --tcp'; TCP_PORTS=$2; seen_tcp=1;;
                    --udp) (( seen_udp == 0 )) || die 'Duplicate --udp'; UDP_PORTS=$2; seen_udp=1;;
                    --users) (( seen_users == 0 )) || die 'Duplicate --users'; USERS=$2; seen_users=1;;
                    --run) (( seen_run == 0 )) || die 'Duplicate --run'; RESTORE_ID=$2; seen_run=1;;
                esac
                shift 2;;
            -h|--help) usage; exit 0;;
            *) die "Unknown option: $1";;
        esac
    done
    [[ $MODE == firewall ]] || (( seen_tcp + seen_udp == 0 )) || die '--tcp/--udp require firewall'
    [[ $MODE == passwords ]] || (( seen_users == 0 )) || die '--users requires passwords'
    [[ $MODE == restore ]] || (( seen_run == 0 )) || die '--run requires restore'
    case "$MODE" in
        audit) (( APPLY == 0 )) || die 'audit does not take --apply';;
        firewall)
            (( seen_tcp == 1 )) || die 'List ALL scored ports with --tcp (or --tcp none).'
            TCP_PORTS=$(normalize_ports "$TCP_PORTS") || die 'Invalid --tcp port list'
            UDP_PORTS=$(normalize_ports "$UDP_PORTS") || die 'Invalid --udp port list';;
        passwords) [[ -n $USERS ]] || die 'Specify local users with --users user1,user2';;
        restore) [[ $RESTORE_ID =~ ^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9]{8}$ ]] || die 'Use the RUN_ID printed by this tool.';;
    esac
}

init_state() {
    require_root
    local path
    # Do not follow a pre-created symlink or use a non-root-owned state tree.
    for path in /var /var/lib "$STATE_ROOT" "$STATE_ROOT/runs"; do
        [[ ! -L $path ]] || die "Refusing symlink: $path"
        if [[ -e $path ]]; then
            [[ -d $path && $(stat -c %u "$path") == 0 ]] || die "Untrusted directory: $path"
            [[ -z $(find "$path" -maxdepth 0 -perm /022 -print) ]] || die "Directory writable by other users: $path"
        fi
    done
    install -d -m 700 -- "$STATE_ROOT" "$STATE_ROOT/runs"
    need flock
    exec 9>"$STATE_ROOT/operation.lock"
    flock -n 9 || die 'Another ctf-defend operation is running.'
}

new_run() {
    RUN=$(mktemp -d "$STATE_ROOT/runs/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
    printf '%s\n' "$1" > "$RUN/mode"
    say "RUN_ID: ${RUN##*/}"
    say "Private files: $RUN"
}

ensure_no_pending() {
    local pending
    pending=$(find "$STATE_ROOT/runs" -mindepth 2 -maxdepth 2 -type f \
        \( -name harden.pending -o -name firewall.pending \) -print -quit)
    if [[ -n $pending ]]; then
        pending=${pending%/*}
        die "Unfinished run ${pending##*/}. Wait for its firewall timer or restore that run before applying again."
    fi
}

require_systemd() {
    need systemctl
    [[ -d /run/systemd/system ]] || die 'Applying changes requires a VM booted with systemd.'
    systemctl show --property=Version --value >/dev/null || die 'Cannot reach the system service manager.'
}

find_sshd() {
    SSHD=$(command -v sshd || true)
    [[ -n $SSHD ]] || return 1
}

ssh_unit() {
    local unit
    for unit in ssh.service sshd.service; do
        if systemctl is-active --quiet "$unit"; then printf '%s' "$unit"; return; fi
    done
    return 0
}

section() { printf '\n--- %s ---\n' "$1"; }
audit_cmd() {
    local cmd=$1
    if command -v "$cmd" >/dev/null 2>&1; then
        timeout 15 "$@" || printf '[%s unavailable, failed, or timed out]\n' "$cmd"
    else
        printf '[%s not installed]\n' "$cmd"
    fi
}

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
        "$SSHD" -T 2>&1 | awk '/^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|logingracetime|loglevel|authorizedkeysfile|allowusers|allowgroups|denyusers|denygroups) /' || true
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

audit() {
    need timeout
    init_state
    new_run audit
    # A private, root-owned directory prevents report symlink attacks.
    audit_body 2>&1 | tee "$RUN/audit.txt"
    say "Report: $RUN/audit.txt"
}

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

ssh_limits() {
    local auth=4 grace=30 existing
    existing=$(awk '$1 == "maxauthtries" {print $2}' "$1")
    if [[ $existing =~ ^[0-9]{1,5}$ ]] && (( 10#$existing < auth )); then auth=$((10#$existing)); fi
    existing=$(awk '$1 == "logingracetime" {print $2}' "$1")
    if [[ $existing =~ ^[0-9]{1,5}$ ]] && (( 10#$existing > 0 && 10#$existing < grace )); then grace=$((10#$existing)); fi
    printf '%s %s\n' "$auth" "$grace"
}

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

# Preserve ownership, permissions, extended attributes and SELinux context.
# The temporary file is on the target filesystem, so rename is atomic.
replace_config() {
    local source=$1 target=$2 tmp
    [[ ! -L $target ]] || { say "Refusing symlink: $target" >&2; return 1; }
    tmp=$(mktemp "$(dirname "$target")/.ctf-defend.XXXXXXXX") || return 1
    if ! cp --preserve=all -- "$source" "$tmp" || ! mv -fT -- "$tmp" "$target"; then
        rm -f -- "$tmp"
        return 1
    fi
}

restore_harden() {
    local run=$1 failed=0 key value unit
    say "Restoring hardening run: ${run##*/}"
    if [[ -f $run/sshd_config.before ]]; then
        replace_config "$run/sshd_config.before" "$SSH_CONF" || failed=1
    fi
    if [[ -f $run/sysctl.conf.before ]]; then
        replace_config "$run/sysctl.conf.before" "$SYSCTL_CONF" || failed=1
    elif [[ -f $run/sysctl.conf.absent ]]; then
        rm -f -- "$SYSCTL_CONF" || failed=1
    fi
    if [[ -f $run/sysctl.live.before ]]; then
        while IFS='=' read -r key value; do
            [[ -n $key ]] || continue
            sysctl -q -w "$key=$value" || failed=1
        done < "$run/sysctl.live.before"
    fi
    unit=$(cat "$run/ssh.unit" 2>/dev/null || true)
    if [[ -n $unit ]]; then
        case "$unit" in ssh.service|sshd.service) ;; *) return 1;; esac
        find_sshd && "$SSHD" -t && systemctl reload "$unit" || failed=1
    fi
    if (( failed == 0 )); then
        rm -f -- "$run/harden.pending"
        touch "$run/restored"
    fi
    return "$failed"
}

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
    ACTIVE_HARDEN=$RUN
    touch "$RUN/harden.pending"
    replace_config "$RUN/sysctl.conf.after" "$SYSCTL_CONF"
    sysctl -q -p "$SYSCTL_CONF"
    if [[ -f $RUN/sshd_config.after ]]; then
        replace_config "$RUN/sshd_config.after" "$SSH_CONF"
        "$SSHD" -t
        [[ -z $unit ]] || systemctl reload "$unit"
    fi
    rm -f -- "$RUN/harden.pending"
    ACTIVE_HARDEN=''
    touch "$RUN/applied"
    say "Applied. Restore with: sudo bash ctf-defend.sh restore --run ${RUN##*/} --apply"
    say 'Verify a NEW SSH login and the scoring dashboard now. SSH Match rules can override globals.'
}

passwords() {
    local name entry failures=0
    local -a accounts=()
    [[ $USERS != ,* && $USERS != *, && $USERS != *,,* ]] || die 'Invalid --users list'
    IFS=, read -r -a accounts <<< "$USERS"
    # Validate the entire list before changing the first password. Do not touch
    # LDAP/NIS identities or silently include application/database accounts.
    for name in "${accounts[@]}"; do
        [[ $name =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || die "Invalid local username: $name"
        entry=$(awk -F: -v name="$name" '$1 == name {print $1}' /etc/passwd)
        [[ $entry == "$name" ]] || die "Not a unique local account: $name"
    done
    say "Selected local users: $USERS"
    (( APPLY == 1 )) || { say 'Preview only. Add --apply for a hidden passwd prompt for each user.'; return; }
    require_root
    need passwd
    [[ -t 0 && -t 1 ]] || die 'Password changes require an interactive terminal.'
    for name in "${accounts[@]}"; do
        say "Changing password for $name"
        if passwd -- "$name"; then say "Changed: $name";
        else say "FAILED: $name" >&2; failures=1; fi
    done
    (( failures == 0 )) || die 'Some password changes failed. Earlier successes remain in effect.'
    say 'Passwords are not stored by this script. Verify a new login before closing your session.'
}

render_firewall() {
    cat <<'NFT'
table inet ctf_defend {
    chain input {
        type filter hook input priority 10; policy drop;
        iifname "lo" counter accept
        ct state established,related counter accept
        ct state invalid counter drop
        meta l4proto icmp counter accept
        meta l4proto ipv6-icmp counter accept
        meta nfproto ipv4 udp sport 67 udp dport 68 counter accept
        meta nfproto ipv6 udp sport 547 udp dport 546 counter accept
NFT
    [[ $TCP_PORTS == none ]] || printf '        tcp dport { %s } counter accept\n' "$TCP_PORTS"
    [[ $UDP_PORTS == none ]] || printf '        udp dport { %s } counter accept\n' "$UDP_PORTS"
    printf '    }\n}\n'
}

check_ssh_ports() {
    local port address
    local -a connection=()
    if [[ -n ${SSH_CONNECTION:-} ]]; then
        read -r -a connection <<< "$SSH_CONNECTION"
        [[ ${#connection[@]} == 4 && ${connection[3]} =~ ^[0-9]+$ ]] || die 'Malformed SSH_CONNECTION'
        port=${connection[3]}
        port_in_list "$port" "$TCP_PORTS" || die "Current SSH port $port is missing from --tcp."
    fi
    # Catch directly launched sshd instances and multiple listening ports too.
    while read -r address; do
        port=${address##*:}
        [[ $port =~ ^[0-9]+$ ]] || continue
        port_in_list "$port" "$TCP_PORTS" || die "Listening SSH port $port is missing from --tcp."
    done < <(ss -H -lntp | awk '/"sshd"/ {print $4}')
}

restore_firewall() {
    local run=$1 tmp unit
    need nft
    # Both the detached watchdog and main process use this lock. Commit and
    # rollback cannot interleave; a late confirmation cannot undo a rollback.
    (
        flock -x 8
        if [[ ${2:-manual} == pending && ! -e $run/firewall.pending ]]; then exit 0; fi
        tmp=$(mktemp "$run/restore.XXXXXXXX.nft")
        if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            printf 'delete table inet %s\n' "$NFT_TABLE" > "$tmp"
        fi
        cat "$run/firewall.before.nft" >> "$tmp"
        if [[ -s $tmp ]]; then
            nft --check --file "$tmp" && nft --file "$tmp" || { rm -f -- "$tmp"; exit 1; }
        fi
        rm -f -- "$tmp" "$run/firewall.pending"
        touch "$run/restored"
    ) 8>"$run/firewall.lock" || return 1
    unit=$(cat "$run/timer.unit" 2>/dev/null || true)
    if [[ $unit =~ ^ctf-defend-rollback-[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9]{8}$ ]]; then
        systemctl stop "$unit.timer" 2>/dev/null || true
    fi
    say "Firewall restored: ${run##*/}"
}

write_watchdog() {
    # Standalone script: systemd owns its process, so SSH disconnects and SIGKILL
    # of the main script do not cancel the scheduled rollback.
    # File paths below are generated by root's mktemp under a private directory.
    {
        printf '#!/usr/bin/env bash\nset -euo pipefail\numask 077\n'
        printf 'export PATH=/usr/sbin:/usr/bin:/sbin:/bin\n'
        printf 'run=%q\n' "$RUN"
        cat <<'WATCHDOG'
exec 8>"$run/firewall.lock"
flock -x 8
[[ -e $run/firewall.pending ]] || exit 0
tmp=$(mktemp "$run/watchdog.XXXXXXXX.nft")
if nft list table inet ctf_defend >/dev/null 2>&1; then
    printf 'delete table inet ctf_defend\n' > "$tmp"
fi
cat "$run/firewall.before.nft" >> "$tmp"
if [[ -s $tmp ]]; then nft --check --file "$tmp"; nft --file "$tmp"; fi
rm -f -- "$tmp" "$run/firewall.pending"
touch "$run/restored"
WATCHDOG
    } > "$RUN/rollback-firewall.sh"
    chmod 700 "$RUN/rollback-firewall.sh"
}

firewall() {
    say "TCP allowlist: $TCP_PORTS | UDP allowlist: $UDP_PORTS"
    render_firewall
    say 'Allows loopback, established flows, ICMP/ICMPv6, DHCP replies, and the listed ports.'
    say 'Other new host INPUT traffic is dropped. Existing sessions remain accepted.'
    say 'All listed ports are reachable from any source permitted by other firewalls.'
    say 'Runtime only. Forwarded and Docker-published traffic require separate rules.'
    (( APPLY == 1 )) || { say 'Preview only. Add --apply after listing ALL scored ports.'; return; }
    need nft
    need ss
    need systemd-run
    init_state
    ensure_no_pending
    require_systemd
    [[ -t 0 && -t 1 ]] || die 'Firewall apply requires an interactive terminal.'
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
        die 'UFW is active. Manage its existing policy rather than layering this helper over it.'
    fi
    if systemctl is-active --quiet firewalld.service; then
        die 'firewalld is active. Manage its existing policy rather than layering this helper over it.'
    fi
    # Verify nft can inspect the current network namespace before taking backups.
    nft list ruleset >/dev/null
    check_ssh_ports
    new_run firewall
    if ! nft list table inet "$NFT_TABLE" > "$RUN/firewall.before.nft" 2>"$RUN/nft-inspect.txt"; then
        : > "$RUN/firewall.before.nft"
    fi
    if [[ -s $RUN/firewall.before.nft ]]; then
        printf 'delete table inet %s\n' "$NFT_TABLE" > "$RUN/firewall.after.nft"
    else : > "$RUN/firewall.after.nft"; fi
    render_firewall >> "$RUN/firewall.after.nft"
    nft --check --file "$RUN/firewall.after.nft"
    write_watchdog
    local unit="ctf-defend-rollback-${RUN##*/}" response=''
    printf '%s\n' "$unit" > "$RUN/timer.unit"
    ACTIVE_FIREWALL=$RUN
    touch "$RUN/firewall.pending"
    systemd-run --quiet --unit="$unit" --on-active=120s \
        --timer-property=AccuracySec=1s --property=Type=oneshot \
        /bin/bash "$RUN/rollback-firewall.sh"
    systemctl is-active --quiet "$unit.timer" || die 'Rollback timer failed to arm; firewall was not applied.'
    (
        flock -x 8
        [[ -e $RUN/firewall.pending ]] || exit 1
        nft --file "$RUN/firewall.after.nft"
    ) 8>"$RUN/firewall.lock"
    say 'Test a NEW SSH login and all scored services from another host NOW.'
    say 'Type KEEP within 90 seconds only after those checks pass.'
    if read -r -t 90 response && [[ $response == KEEP ]]; then
        (
            flock -x 8
            [[ -e $RUN/firewall.pending && ! -e $RUN/restored ]] || exit 1
            rm -f -- "$RUN/firewall.pending"
            touch "$RUN/applied"
        ) 8>"$RUN/firewall.lock" || die 'Rollback already ran; apply again if needed.'
        systemctl stop "$unit.timer" || true
        ACTIVE_FIREWALL=''
        say "Firewall kept for this boot. Restore: sudo bash ctf-defend.sh restore --run ${RUN##*/} --apply"
    else
        restore_firewall "$RUN" pending || die "Rollback failed. Use the VM console and backups in $RUN"
        ACTIVE_FIREWALL=''
        die 'Firewall was reverted because KEEP was not confirmed.'
    fi
}

restore() {
    say "Restore run: $RESTORE_ID (restore newest runs first)."
    (( APPLY == 1 )) || { say 'Preview only. Add --apply to restore backed-up settings.'; return; }
    init_state
    require_systemd
    local run="$STATE_ROOT/runs/$RESTORE_ID" mode
    [[ -d $run && ! -L $run && $(stat -c %u "$run") == 0 ]] || die 'Run not found or untrusted.'
    [[ -z $(find "$run" -maxdepth 0 -perm /077 -print) ]] || die 'Run directory must be private to root.'
    mode=$(cat "$run/mode")
    case "$mode" in
        harden) restore_harden "$run" || die 'Restore was incomplete; review the console output.';;
        firewall) restore_firewall "$run" || die 'Firewall restore failed; use the VM console.';;
        *) die 'This run does not contain restorable hardening or firewall changes.';;
    esac
    say 'Restored. Verify new logins and scored services.'
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n $ACTIVE_HARDEN && -e $ACTIVE_HARDEN/harden.pending ]]; then
        if ! restore_harden "$ACTIVE_HARDEN"; then
            say "Automatic hardening restore was incomplete. Backups: $ACTIVE_HARDEN" >&2
            status=1
        fi
    fi
    if [[ -n $ACTIVE_FIREWALL && -e $ACTIVE_FIREWALL/firewall.pending ]]; then
        if ! restore_firewall "$ACTIVE_FIREWALL" pending; then
            say "Immediate firewall rollback failed; the detached timer will also try. Backups: $ACTIVE_FIREWALL" >&2
            status=1
        fi
    fi
    exit "$status"
}

main() {
    (( BASH_VERSINFO[0] >= 4 )) || die 'Bash 4 or newer is required.'
    [[ $(uname -s) == Linux ]] || die 'Run this inside a Linux CTF VM.'
    parse_args "$@"
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    case "$MODE" in
        audit) audit;; harden) harden;; passwords) passwords;; firewall) firewall;; restore) restore;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
