#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# lib/common.sh — Shared configuration, validation, and transaction utilities.
# Loaded by ctf-defend.sh. Keep module loading free of host mutations;
# command functions run only after the entry point dispatches a mode.

# SC2034 is disabled only in this shared-state module: sibling modules consume
# its configuration and recovery flags. Other ShellCheck diagnostics stay on.
# Shared state is initialized once for each CLI invocation. Tests source
# the entry point, then redirect these paths to isolated fixtures.
VERSION=1.2.0
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

# Validate a CSV of ports/ranges before it can enter nftables syntax.
# Input: one CSV argument, or "none". Output: canonical CSV; status 1 on error.
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
        result+="$first"
        (( first == last )) || result+="-$last"
    done
    printf '%s' "$result"
}

# Test a single port against an already-normalized CSV allowlist.
# Used to keep detected SSH listeners reachable before applying the firewall.
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

# Open the private state tree and take the operation lock on file descriptor 9.
# Keeping this descriptor open serializes audits, hardening, and firewall changes.
# The watchdog uses a separate per-run lock so it can recover a killed process.
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

# Create a unique, private backup directory and print its recovery ID.
# Call this before changing configuration; restore.sh consumes these files.
new_run() {
    RUN=$(mktemp -d "$STATE_ROOT/runs/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
    printf '%s\n' "$1" > "$RUN/mode"
    say "RUN_ID: ${RUN##*/}"
    say "Private files: $RUN"
}

# Refuse new changes while an older transaction needs recovery.
# This prevents an old firewall timer from reverting a newer application.
ensure_no_pending() {
    local pending
    pending=$(find "$STATE_ROOT/runs" -mindepth 2 -maxdepth 2 -type f \
        \( -name harden.pending -o -name firewall.pending \) -print -quit)
    if [[ -n $pending ]]; then
        pending=${pending%/*}
        die "Unfinished run ${pending##*/}. Wait for its firewall timer or restore that run before applying again."
    fi
}

# Applying service changes requires a reachable system service manager.
# In particular, the firewall timer must run independently of this terminal.
require_systemd() {
    need systemctl
    [[ -d /run/systemd/system ]] || die 'Applying changes requires a VM booted with systemd.'
    systemctl show --property=Version --value >/dev/null || die 'Cannot reach the system service manager.'
}

# Resolve the SSH daemon for audit, configuration checks, and restoration.
find_sshd() {
    SSHD=$(command -v sshd || true)
    [[ -n $SSHD ]] || return 1
}

# Return only an already-running, recognized SSH service; never start one.
ssh_unit() {
    local unit
    for unit in ssh.service sshd.service; do
        if systemctl is-active --quiet "$unit"; then printf '%s' "$unit"; return; fi
    done
    return 0
}

# Atomically replace a configuration on its own filesystem.
# Preserve source metadata, including permissions and SELinux context.
# Refuse symlink targets so recovery cannot overwrite an unexpected file.
replace_config() {
    local source=$1 target=$2 tmp
    [[ ! -L $target ]] || { say "Refusing symlink: $target" >&2; return 1; }
    tmp=$(mktemp "$(dirname "$target")/.ctf-defend.XXXXXXXX") || return 1
    if ! cp --preserve=all -- "$source" "$tmp" || ! mv -fT -- "$tmp" "$target"; then
        rm -f -- "$tmp"
        return 1
    fi
}
