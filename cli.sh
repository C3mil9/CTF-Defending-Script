#!/usr/bin/env bash
# lib/cli.sh — Help text and command-line parsing; no host changes.
# Loaded by ctf-defend.sh. Keep module loading free of host mutations;
# command functions run only after the entry point dispatches a mode.

# Keep examples and option descriptions next to their parser.
# The root entry point supplies these functions with the unchanged CLI arguments.
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
  audit      Inventory accounts, listeners, FTP exposure, SUID/SGID files,
             authorized keys, services, firewall, cron, and hashes.
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

# Validate the command and all options before dispatch.
# APPLY starts at zero in common.sh; only an explicit --apply enables changes.
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
