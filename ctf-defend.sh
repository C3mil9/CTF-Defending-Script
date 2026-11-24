#!/usr/bin/env bash
# CTF Defense Kit entry point. Run this file; keep the lib/ folder beside it.
# All host changes live in command modules, so startup can validate the complete
# installation before dispatching anything that needs root privileges.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
export SYSTEMD_PAGER=cat
export SYSTEMD_COLORS=0

# Check the platform before using GNU path resolution or importing Linux helpers.
if (( BASH_VERSINFO[0] < 4 )); then
    printf 'ERROR: Bash 4 or newer is required.\n' >&2
    exit 1
fi
if [[ $(uname -s) != Linux ]]; then
    printf 'ERROR: Run this inside a Linux CTF VM.\n' >&2
    exit 1
fi

# Anchor imports to this script, including a symlinked entry point. Using the
# current working directory here could load the wrong code when run elsewhere.
CTF_ENTRY_PATH=$(readlink -f -- "${BASH_SOURCE[0]}") || {
    printf 'ERROR: Cannot resolve the entry point path.\n' >&2
    exit 1
}
CTF_ROOT=${CTF_ENTRY_PATH%/*}
unset CTF_ENTRY_PATH

# Validate the whole module set first. A partial download must fail before it
# creates reports, starts a transaction, or changes any host configuration.
for CTF_MODULE in common banner cli audit_checks audit harden passwords restore firewall; do
    if [[ ! -f $CTF_ROOT/lib/$CTF_MODULE.sh || ! -r $CTF_ROOT/lib/$CTF_MODULE.sh ]]; then
        printf 'ERROR: Missing or unreadable module: %s/lib/%s.sh\nKeep the complete project folder together.\n' "$CTF_ROOT" "$CTF_MODULE" >&2
        exit 1
    fi
done
unset CTF_MODULE

# Explicit imports make dependencies easy to inspect and let ShellCheck follow
# every module. common initializes state; the other modules define functions.
# shellcheck source=lib/common.sh
source "$CTF_ROOT/lib/common.sh"
# shellcheck source=lib/banner.sh
source "$CTF_ROOT/lib/banner.sh"
# shellcheck source=lib/cli.sh
source "$CTF_ROOT/lib/cli.sh"
# shellcheck source=lib/audit_checks.sh
source "$CTF_ROOT/lib/audit_checks.sh"
# shellcheck source=lib/audit.sh
source "$CTF_ROOT/lib/audit.sh"
# shellcheck source=lib/harden.sh
source "$CTF_ROOT/lib/harden.sh"
# shellcheck source=lib/passwords.sh
source "$CTF_ROOT/lib/passwords.sh"
# shellcheck source=lib/restore.sh
source "$CTF_ROOT/lib/restore.sh"
# shellcheck source=lib/firewall.sh
source "$CTF_ROOT/lib/firewall.sh"

# Parse once, then install recovery traps before entering a command module.
main() {
    show_banner
    parse_args "$@"
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    case "$MODE" in
        audit) audit ;;
        harden) harden ;;
        passwords) passwords ;;
        firewall) firewall ;;
        restore) restore ;;
    esac
}

# Tests source this file to load the same implementation without dispatching it.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
