#!/usr/bin/env bash
# lib/passwords.sh — Explicit local-account password changes through passwd.
# Loaded by ctf-defend.sh. Keep module loading free of host mutations;
# command functions run only after the entry point dispatches a mode.

# Rotate only explicitly named local accounts through the standard passwd UI.
# Validate the entire list before the first prompt. Passwords stay out of Bash
# variables and backup files; successful changes cannot be automatically undone.
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
