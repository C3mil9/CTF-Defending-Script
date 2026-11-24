#!/usr/bin/env bash
# Local exposure checks for audit.sh. Findings are evidence for manual review;
# these functions never remove keys, change permissions, or alter FTP policy.

# Attempt anonymous login and FTP metadata access on a fixed loopback endpoint.
# --head avoids downloading files; --disable ignores potentially unsafe curlrc
# commands, and --noproxy prevents a proxy from receiving the local probe.
# Allow normal server/PAM login delays while keeping every probe bounded.
audit_ftp_probe() {
    local url=$1 status
    if ! command -v curl >/dev/null 2>&1; then
        say '[INCONCLUSIVE] curl is unavailable; anonymous FTP was not probed.'
        return 0
    fi
    if curl --disable --noproxy '*' --proto '=ftp' --globoff \
        --connect-timeout 5 --max-time 10 --silent --head --output /dev/null \
        --user 'anonymous:ctf-audit@localhost' "$url" 2>/dev/null; then
        say "[REVIEW] Anonymous FTP login and metadata access succeeded: $url"
    else
        status=$?
        case "$status" in
            67) say "[INFO] Anonymous FTP login was rejected: $url" ;;
            7) say "[INCONCLUSIVE] No reachable FTP listener at $url" ;;
            28) say "[INCONCLUSIVE] Anonymous FTP probe timed out: $url" ;;
            *) say "[INCONCLUSIVE] FTP probe failed (curl exit $status): $url" ;;
        esac
    fi
}

# Configuration is supporting evidence, not a complete parser for includes or
# per-user overrides. Read selected non-secret directives without sourcing files.
audit_ftp() {
    local config_root=${1:-/etc} file
    say 'Read-only probes: IPv4/IPv6 loopback TCP 21; other bindings, ports, and FTPS require review.'
    for file in "$config_root/vsftpd.conf" "$config_root/vsftpd/vsftpd.conf" \
        "$config_root/proftpd/proftpd.conf" "$config_root/proftpd/conf.d/"*.conf; do
        [[ -f $file && ! -L $file ]] || continue
        awk '
            {line=$0; sub(/[[:space:]]*#.*/, "", line); lower=tolower(line)}
            lower ~ /^[[:space:]]*(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable|anon_other_write_enable|write_enable|listen|listen_ipv6|listen_port|ssl_enable|anon_root)[[:space:]]*=/ ||
            lower ~ /^[[:space:]]*(<anonymous[[:space:]>]|useralias[[:space:]]+anonymous|anonrequirepassword[[:space:]])/ {
                print FILENAME ":" FNR ": " line
            }
        ' "$file"
    done
    audit_ftp_probe 'ftp://127.0.0.1:21/'
    audit_ftp_probe 'ftp://[::1]:21/'
}

# Enumerate privilege-bearing files without executing them or following links.
# -xdev avoids crossing into network/pseudo filesystems; other mounts need their
# own review. A time limit makes partial results explicit on very large disks.
audit_suid() {
    local scan_root=${1:-/} status
    printf 'SUID/SGID inventory on %q only (-xdev; 30-second limit).\n' "$scan_root"
    if timeout 30 find "$scan_root" -xdev -type f -perm /6000 -ls; then
        say '[INFO] SUID/SGID scan completed. Review unexpected paths, owners, or writable files.'
    else
        status=$?
        say "[INCONCLUSIVE] SUID/SGID scan returned $status; results may be partial."
    fi
}

# OpenSSH StrictModes is sensitive to ownership and group/other write access.
# Root ownership is also accepted. This reports metadata without changing it.
audit_ssh_path() {
    local path=$1 expected_uid=$2 metadata mode owner
    if [[ -L $path ]]; then
        printf '[REVIEW] Symlink requires manual target review: %q\n' "$path"
        return 0
    fi
    metadata=$(stat -c '%a %u' -- "$path" 2>/dev/null) || {
        printf '[INCONCLUSIVE] Cannot stat SSH path: %q\n' "$path"
        return 0
    }
    read -r mode owner <<< "$metadata"
    printf '  mode=%s uid=%s path=%q\n' "$mode" "$owner" "$path"
    if [[ $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) != 0 )); then
        printf '[REVIEW] SSH path is writable by group or others: %q\n' "$path"
    fi
    if [[ $owner != 0 && $owner != "$expected_uid" ]]; then
        printf '[REVIEW] SSH path owner differs from account/root: %q\n' "$path"
    fi
}

# Inspect conventional authorized_keys locations for every local passwd entry.
# Print counts/fingerprints, never key bodies, key options, or key comments.
# Custom AuthorizedKeysFile/Command settings remain visible in the main audit.
audit_authorized_keys() {
    local passwd_file=${1:-/etc/passwd} account uid home ssh_dir key_file entries
    local _password _gid _gecos _shell found=0 fingerprints parsed
    say 'Conventional local-account paths only; review custom AuthorizedKeysFile/Command and Match rules separately.'
    while IFS=: read -r account _password uid _gid _gecos home _shell; do
        [[ $uid =~ ^[0-9]+$ && $home == /* && -d $home ]] || continue
        ssh_dir="${home%/}/.ssh"
        [[ -d $ssh_dir || -L $ssh_dir ]] || continue
        printf 'Account: %q (uid=%s)\n' "$account" "$uid"
        audit_ssh_path "$home" "$uid"
        audit_ssh_path "$ssh_dir" "$uid"
        # Avoid traversing a symlinked home/.ssh tree when running as root.
        if [[ -L $home || -L $ssh_dir ]]; then
            say '[REVIEW] Symlinked SSH directory skipped; inspect its target manually.'
            continue
        fi
        for key_file in "$ssh_dir/authorized_keys" "$ssh_dir/authorized_keys2"; do
            [[ -e $key_file || -L $key_file ]] || continue
            found=1
            audit_ssh_path "$key_file" "$uid"
            if [[ -L $key_file || ! -f $key_file || ! -r $key_file ]]; then
                say '[INCONCLUSIVE] Key file is a symlink, unreadable, or not a regular file; content skipped.'
                continue
            fi
            entries=$(awk '!/^[[:space:]]*#/ && !/^[[:space:]]*$/ {n++} END {print n+0}' "$key_file")
            printf '  Key entries: %s\n' "$entries"
            (( entries > 0 )) || continue
            if command -v ssh-keygen >/dev/null 2>&1; then
                if fingerprints=$(timeout 5 ssh-keygen -lf "$key_file" -E sha256 2>/dev/null | \
                    awk '{print "    " $1 " " $2 " " $NF}'); then
                    printf '%s\n' "$fingerprints"
                    parsed=$(printf '%s\n' "$fingerprints" | awk 'NF {n++} END {print n+0}')
                    if (( parsed < entries )); then say '[REVIEW] Some non-comment entries could not be fingerprinted.'; fi
                else
                    say '[REVIEW] Key fingerprints could not be parsed or timed out; inspect file formatting.'
                fi
            else
                say '[INCONCLUSIVE] ssh-keygen is unavailable; fingerprints were not checked.'
            fi
        done
    done < "$passwd_file"
    if (( found == 0 )); then say '[INFO] No conventional authorized_keys files found in the inspected homes.'; fi
}
