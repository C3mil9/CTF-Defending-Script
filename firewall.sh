#!/usr/bin/env bash
# lib/firewall.sh — Generate and apply the dedicated host INPUT allowlist.
# Loaded by ctf-defend.sh. Keep module loading free of host mutations;
# command functions run only after the entry point dispatches a mode.

# Print an IPv4/IPv6 host INPUT policy using validated port lists.
# This is a pure rules generator: no nft invocation or network changes occur here.
# Forwarded traffic and unrelated firewall tables keep their existing policy.
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

# Refuse an allowlist that omits the current or a detected SSH listener.
# Socket activation/custom daemons still need the manual checks in the README.
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

# Firewall transaction: back up our table, arm independent recovery, then apply.
# KEEP commits only while the run is pending; every other path requests rollback.
# The per-run lock makes confirmation and timer-driven rollback mutually exclusive.
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
    # Snapshot only our own table; other firewall owners keep their rules.
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
    # Arm and verify detached recovery BEFORE the first nft policy change.
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
    # Confirmation shares the watchdog lock: a late KEEP cannot win a rollback.
    if read -r -t 90 response && [[ $response == KEEP ]]; then
        (
            flock -x 8
            [[ -e $RUN/firewall.pending && ! -e $RUN/restored ]] || exit 1
            rm -f -- "$RUN/firewall.pending"
            touch "$RUN/applied"
        ) 8>"$RUN/firewall.lock" || die 'Rollback already ran; apply again if needed.'
        systemctl stop "$unit.timer" || true
        # shellcheck disable=SC2034 # cleanup() in restore.sh consumes this shared flag.
        ACTIVE_FIREWALL=''
        say "Firewall kept for this boot. Restore: sudo bash ctf-defend.sh restore --run ${RUN##*/} --apply"
    else
        restore_firewall "$RUN" pending || die "Rollback failed. Use the VM console and backups in $RUN"
        # shellcheck disable=SC2034 # cleanup() in restore.sh consumes this shared flag.
        ACTIVE_FIREWALL=''
        die 'Firewall was reverted because KEEP was not confirmed.'
    fi
}
