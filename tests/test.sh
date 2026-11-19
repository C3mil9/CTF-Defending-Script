#!/usr/bin/env bash
# Isolated tests: no root, network changes, package installs, or system writes.
set -Eeuo pipefail
TEST_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../ctf-defend.sh
source "$TEST_DIR/../ctf-defend.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
CHECKS=0
PROC_SYS_ROOT="$TEST_ROOT/proc/sys"
for fixture in ipv4/conf/eth0 ipv4/conf/vlan.42 ipv6/conf/eth0; do
    mkdir -p "$PROC_SYS_ROOT/net/$fixture"
    touch "$PROC_SYS_ROOT/net/$fixture/accept_redirects"
done

pass() { CHECKS=$((CHECKS + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
eq() { [[ $1 == "$2" ]] || fail "${3:-values differ}: expected [$2], got [$1]"; pass; }
yes() { "$@" || fail "Expected success: $*"; pass; }
no() { if ( "$@" ) >"$TEST_ROOT/rejected.out" 2>&1; then fail "Expected rejection: $*"; fi; pass; }
has() { grep -qE -- "$2" "$1" || fail "Missing pattern [$2] in $1"; pass; }

for pair in '22:22' '00022:22' '1,65535:1,65535' '22,80-90:22,80-90' '80-80:80' 'none:none'; do
    eq "$(normalize_ports "${pair%%:*}")" "${pair#*:}" 'port normalization'
done
# shellcheck disable=SC2016 # The shell syntax here is intentionally literal.
for input in '' 0 65536 999999 80-20 -22 22- '22,,80' ',22' '22,' '22;echo BAD' '22 80' '$(id)' '22/udp' 'all' 'none,22'; do
    no normalize_ports "$input"
done
yes port_in_list 2222 '22,2200-2300'
yes port_in_list 22 22
no port_in_list 2222 '22,80'
no port_in_list 22 none

no parse_args unknown
no parse_args firewall
no parse_args firewall --tcp 22 --tcp 80
no parse_args harden --tcp 22
no parse_args audit --apply
no parse_args passwords --users
no parse_args restore --run ../../etc
no parse_args firewall --tcp 22 --udp '53;id'
(
    parse_args firewall --tcp 022,80-81 --udp 53
    [[ $TCP_PORTS == 22,80-81 && $UDP_PORTS == 53 && $APPLY == 0 ]]
) || fail 'valid CLI normalization'
pass

cat > "$TEST_ROOT/ssh.original" <<'SSH'
# Original SSH config
Port 2222
PermitRootLogin yes
PasswordAuthentication yes
Match User demo
    X11Forwarding no
SSH
ssh_candidate "$TEST_ROOT/ssh.original" > "$TEST_ROOT/ssh.first"
ssh_candidate "$TEST_ROOT/ssh.first" > "$TEST_ROOT/ssh.second"
yes cmp -s "$TEST_ROOT/ssh.first" "$TEST_ROOT/ssh.second"
eq "$(grep -c '^# BEGIN CTF-DEFEND$' "$TEST_ROOT/ssh.second")" 1 'single managed block'
has "$TEST_ROOT/ssh.second" '^PermitRootLogin yes$'
has "$TEST_ROOT/ssh.second" '^PasswordAuthentication yes$'
has "$TEST_ROOT/ssh.second" '^Match User demo$'
eq "$(head -n 1 "$TEST_ROOT/ssh.second")" '# BEGIN CTF-DEFEND' 'managed block is global'
printf 'maxauthtries 2\nlogingracetime 10\n' > "$TEST_ROOT/ssh.effective"
eq "$(ssh_limits "$TEST_ROOT/ssh.effective")" '2 10' 'stricter existing SSH limits preserved'
printf 'maxauthtries 6\nlogingracetime 0\n' > "$TEST_ROOT/ssh.effective"
eq "$(ssh_limits "$TEST_ROOT/ssh.effective")" '4 30' 'default and unlimited SSH limits capped'
ssh_candidate "$TEST_ROOT/ssh.original" 2 10 > "$TEST_ROOT/ssh.strict"
has "$TEST_ROOT/ssh.strict" '^MaxAuthTries 2$'
has "$TEST_ROOT/ssh.strict" '^LoginGraceTime 10$'
sysctl_settings > "$TEST_ROOT/sysctl.settings"
has "$TEST_ROOT/sysctl.settings" '^net/ipv4/conf/eth0/accept_redirects=0$'
has "$TEST_ROOT/sysctl.settings" '^net/ipv4/conf/vlan\.42/accept_redirects=0$'
has "$TEST_ROOT/sysctl.settings" '^net/ipv6/conf/eth0/accept_redirects=0$'

TCP_PORTS=22,80-90
UDP_PORTS=53
render_firewall > "$TEST_ROOT/rules.nft"
has "$TEST_ROOT/rules.nft" 'table inet ctf_defend'
has "$TEST_ROOT/rules.nft" 'hook input priority 10; policy drop;'
has "$TEST_ROOT/rules.nft" 'tcp dport \{ 22,80-90 \}'
has "$TEST_ROOT/rules.nft" 'udp dport \{ 53 \}'
has "$TEST_ROOT/rules.nft" 'ct state established,related'
has "$TEST_ROOT/rules.nft" 'meta l4proto ipv6-icmp'
no grep -qE 'flush ruleset|hook (forward|output)' "$TEST_ROOT/rules.nft"
TCP_PORTS=none
UDP_PORTS=none
render_firewall > "$TEST_ROOT/no-ports.nft"
no grep -qE '^        (tcp|udp) dport' "$TEST_ROOT/no-ports.nft"

# From here, every privileged integration point is a mock. Configuration paths
# are redirected to TEST_ROOT before any harden/restore function is called.
MOCK_ROOT="$TEST_ROOT/mock"
STATE_ROOT="$TEST_ROOT/state"
SSH_CONF="$TEST_ROOT/etc/ssh/sshd_config"
SYSCTL_CONF="$TEST_ROOT/etc/sysctl.d/99-ctf-defend.conf"
mkdir -p "$MOCK_ROOT/sysctl" "$STATE_ROOT/runs" "$(dirname "$SSH_CONF")" "$(dirname "$SYSCTL_CONF")"
cp "$TEST_ROOT/ssh.original" "$SSH_CONF"
chmod 640 "$SSH_CONF"
printf '# original sysctl config\n' > "$SYSCTL_CONF"
cp "$SYSCTL_CONF" "$TEST_ROOT/sysctl.original"
while IFS='=' read -r key value; do
    mkdir -p "$(dirname "$MOCK_ROOT/sysctl/$key")"
    printf '0\n' > "$MOCK_ROOT/sysctl/$key"
done < <(sysctl_settings)

init_state() { mkdir -p "$STATE_ROOT/runs"; }
require_systemd() { :; }
find_sshd() { SSHD=mock_sshd; }
mock_sshd() {
    if [[ $1 == -T ]]; then
        printf 'port 2222\npermitemptypasswords no\nmaxauthtries 4\n'
    fi
}
systemctl() {
    printf '%s\n' "$*" >> "$MOCK_ROOT/systemctl.calls"
    if [[ $1 == is-active ]]; then
        if [[ ${*: -1} == *.timer ]]; then [[ ! -e $MOCK_ROOT/fail-timer ]];
        else [[ ${*: -1} == ssh.service ]]; fi
        return
    fi
    if [[ $1 == reload && -e $MOCK_ROOT/fail-reload ]]; then
        rm "$MOCK_ROOT/fail-reload"
        return 1
    fi
    return 0
}
sysctl() {
    local key value
    if [[ $1 == -n ]]; then
        [[ -f $MOCK_ROOT/sysctl/$2 ]] || return 1
        cat "$MOCK_ROOT/sysctl/$2"
    elif [[ $1 == -q && $2 == -w ]]; then
        key=${3%%=*}; value=${3#*=}
        printf '%s\n' "$value" > "$MOCK_ROOT/sysctl/$key"
    elif [[ $1 == -q && $2 == -p ]]; then
        while IFS='=' read -r key value; do
            [[ -n $key && $key != \#* ]] || continue
            sysctl -q -w "$key=$value"
            if [[ -e $MOCK_ROOT/fail-sysctl ]]; then rm "$MOCK_ROOT/fail-sysctl"; return 1; fi
        done < "$3"
    else
        printf 'Unexpected mocked sysctl invocation\n' >&2
        return 1
    fi
}
SS_FIXTURE=''
ss() { [[ -z $SS_FIXTURE ]] || printf '%s\n' "$SS_FIXTURE"; return 0; }
nft() {
    local file
    if [[ $1 == --check && $2 == --file ]]; then
        [[ ! -e $MOCK_ROOT/fail-nft-check ]]
    elif [[ $1 == --file ]]; then
        [[ ! -e $MOCK_ROOT/fail-nft-apply ]] || return 1
        if [[ -e $MOCK_ROOT/fail-nft-once ]]; then rm "$MOCK_ROOT/fail-nft-once"; return 1; fi
        file=$2
        cp "$file" "$MOCK_ROOT/nft.last-transaction"
        if grep -q '^delete table inet ctf_defend$' "$file"; then rm -f "$MOCK_ROOT/nft.table"; fi
        if grep -q '^table inet ctf_defend' "$file"; then sed -n '/^table inet ctf_defend/,$p' "$file" > "$MOCK_ROOT/nft.table"; fi
    elif [[ $1 == list && $2 == table ]]; then
        [[ -f $MOCK_ROOT/nft.table ]] || return 1
        cat "$MOCK_ROOT/nft.table"
    elif [[ $1 == list && $2 == ruleset ]]; then
        [[ ! -f $MOCK_ROOT/nft.table ]] || cat "$MOCK_ROOT/nft.table"
    else
        printf 'Unexpected mocked nft invocation\n' >&2
        return 1
    fi
}

APPLY=1
harden > "$TEST_ROOT/harden.out"
FIRST_RUN=$RUN
has "$SSH_CONF" '^MaxAuthTries 4$'
has "$SSH_CONF" '^PermitRootLogin yes$'
eq "$(stat -c %a "$SSH_CONF")" 640 'preserved SSH permissions'
eq "$(cat "$MOCK_ROOT/sysctl/kernel.kptr_restrict")" 2 'live sysctl applied'
yes test -f "$RUN/sshd_config.before"
yes test -f "$RUN/applied"
no test -e "$RUN/harden.pending"
has "$MOCK_ROOT/systemctl.calls" '^reload ssh.service$'
harden > "$TEST_ROOT/harden-again.out"
SECOND_RUN=$RUN
eq "$(grep -c '^# BEGIN CTF-DEFEND$' "$SSH_CONF")" 1 'repeated hardening'
restore_harden "$SECOND_RUN" > /dev/null
has "$SSH_CONF" '^MaxAuthTries 4$'
restore_harden "$FIRST_RUN" > /dev/null
yes cmp -s "$SSH_CONF" "$TEST_ROOT/ssh.original"
yes cmp -s "$SYSCTL_CONF" "$TEST_ROOT/sysctl.original"
eq "$(cat "$MOCK_ROOT/sysctl/kernel.kptr_restrict")" 0 'live sysctl restored'

# The actual EXIT cleanup is exercised with errexit enabled in a subshell.
touch "$MOCK_ROOT/fail-reload"
set +e
(
    set -e
    trap cleanup EXIT
    harden
) > "$TEST_ROOT/reload-failure.out" 2>&1
STATUS=$?
set -e
[[ $STATUS != 0 ]] || fail 'reload failure should fail application'
pass
yes cmp -s "$SSH_CONF" "$TEST_ROOT/ssh.original"
yes cmp -s "$SYSCTL_CONF" "$TEST_ROOT/sysctl.original"
eq "$(cat "$MOCK_ROOT/sysctl/kernel.kptr_restrict")" 0 'reload failure rolls back sysctl'
yes ensure_no_pending

touch "$MOCK_ROOT/fail-sysctl"
set +e
(
    set -e
    trap cleanup EXIT
    harden
) > "$TEST_ROOT/sysctl-failure.out" 2>&1
STATUS=$?
set -e
[[ $STATUS != 0 ]] || fail 'partial sysctl failure should fail application'
pass
eq "$(cat "$MOCK_ROOT/sysctl/fs.protected_hardlinks")" 0 'partial live change rolled back'
yes cmp -s "$SYSCTL_CONF" "$TEST_ROOT/sysctl.original"
yes cmp -s "$SSH_CONF" "$TEST_ROOT/ssh.original"
yes ensure_no_pending

rm "$SYSCTL_CONF"
harden > "$TEST_ROOT/new-sysctl-file.out"
yes test -f "$SYSCTL_CONF"
restore_harden "$RUN" > /dev/null
no test -e "$SYSCTL_CONF"

ln -s "$SSH_CONF" "$TEST_ROOT/config-link"
no replace_config "$TEST_ROOT/ssh.first" "$TEST_ROOT/config-link"
yes cmp -s "$SSH_CONF" "$TEST_ROOT/ssh.original"

TCP_PORTS=22
export SSH_CONNECTION='192.0.2.10 50000 192.0.2.20 2222'
no check_ssh_ports
TCP_PORTS=22,2222
yes check_ssh_ports
unset SSH_CONNECTION
SS_FIXTURE='LISTEN 0 128 [::]:2022 [::]:* users:(("sshd",pid=99,fd=3))'
no check_ssh_ports
TCP_PORTS=2000-2030
yes check_ssh_ports
SS_FIXTURE=''

new_run firewall > /dev/null
touch "$RUN/firewall.pending"
no ensure_no_pending
rm "$RUN/firewall.pending"
yes ensure_no_pending

# Rollback with no previous dedicated table removes the newly created one.
TCP_PORTS=22,80
UDP_PORTS=none
render_firewall > "$MOCK_ROOT/nft.table"
printf 'other firewall stays\n' > "$MOCK_ROOT/nft.other-table"
: > "$RUN/firewall.before.nft"
touch "$RUN/firewall.pending"
restore_firewall "$RUN" pending > /dev/null
no test -e "$MOCK_ROOT/nft.table"
yes test -f "$RUN/restored"
no test -e "$RUN/firewall.pending"
eq "$(cat "$MOCK_ROOT/nft.other-table")" 'other firewall stays' 'unrelated table untouched'

# A previous version is recreated atomically in the same nft input transaction.
new_run firewall > /dev/null
cat > "$RUN/firewall.before.nft" <<'NFT'
table inet ctf_defend {
    chain input { type filter hook input priority 10; policy accept; }
}
NFT
render_firewall > "$MOCK_ROOT/nft.table"
touch "$RUN/firewall.pending"
restore_firewall "$RUN" pending > /dev/null
yes cmp -s "$RUN/firewall.before.nft" "$MOCK_ROOT/nft.table"
has "$MOCK_ROOT/nft.last-transaction" '^delete table inet ctf_defend$'

# Failed validation leaves the live table and pending recovery marker intact.
new_run firewall > /dev/null
: > "$RUN/firewall.before.nft"
render_firewall > "$MOCK_ROOT/nft.table"
cp "$MOCK_ROOT/nft.table" "$TEST_ROOT/current-table"
touch "$RUN/firewall.pending" "$MOCK_ROOT/fail-nft-check"
no restore_firewall "$RUN" pending
yes cmp -s "$MOCK_ROOT/nft.table" "$TEST_ROOT/current-table"
yes test -e "$RUN/firewall.pending"
rm "$MOCK_ROOT/fail-nft-check"

# Execute the generated detached rollback script using an exported mock nft.
export MOCK_ROOT
export -f nft
write_watchdog
/bin/bash "$RUN/rollback-firewall.sh"
no test -e "$MOCK_ROOT/nft.table"
yes test -f "$RUN/restored"
no test -e "$RUN/firewall.pending"

# A timer firing after a confirmed commit must be a no-op.
render_firewall > "$MOCK_ROOT/nft.table"
/bin/bash "$RUN/rollback-firewall.sh"
yes cmp -s "$MOCK_ROOT/nft.table" "$TEST_ROOT/current-table"
no grep -q 'flush ruleset' "$RUN/rollback-firewall.sh"

# Exercise the complete CLI confirmation/error flow in a real pseudo-terminal.
# All firewall and service commands inside the child remain mocked.
if command -v script >/dev/null 2>&1; then
    systemd-run() { printf '%s\n' "$*" >> "$MOCK_ROOT/systemd-run.calls"; }
    ufw() { printf 'Status: inactive\n'; }
    RUNNER="$TEST_ROOT/firewall-cli.sh"
    {
        printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n'
        printf 'source %q\n' "$TEST_DIR/../ctf-defend.sh"
        declare -f init_state require_systemd find_sshd mock_sshd systemctl ss nft systemd-run ufw
        printf 'MOCK_ROOT=%q\nSTATE_ROOT=%q\nSS_FIXTURE=""\n' "$MOCK_ROOT" "$STATE_ROOT"
        printf 'main firewall --tcp 22,80,443 --apply\n'
        # shellcheck disable=SC2016 # Variables belong to the generated child script.
        printf 'printf "%%s\\n" "$RUN" > "$MOCK_ROOT/last-run"\n'
    } > "$RUNNER"
    printf -v RUNNER_COMMAND '/bin/bash %q' "$RUNNER"
    script --quiet --return --command "$RUNNER_COMMAND" "$TEST_ROOT/keep.typescript" <<< KEEP > /dev/null
    CLI_RUN=$(cat "$MOCK_ROOT/last-run")
    yes test -f "$CLI_RUN/applied"
    no test -e "$CLI_RUN/firewall.pending"
    has "$MOCK_ROOT/nft.table" 'tcp dport \{ 22,80,443 \}'
    has "$MOCK_ROOT/systemd-run.calls" '--on-active=120s --timer-property=AccuracySec=1s'
    cp "$MOCK_ROOT/nft.table" "$TEST_ROOT/kept-table"

    set +e
    script --quiet --return --command "$RUNNER_COMMAND" "$TEST_ROOT/revert.typescript" <<< REVERT > /dev/null
    STATUS=$?
    set -e
    [[ $STATUS != 0 ]] || fail 'non-KEEP response must fail and revert'
    pass
    yes cmp -s "$MOCK_ROOT/nft.table" "$TEST_ROOT/kept-table"
    yes ensure_no_pending

    touch "$MOCK_ROOT/fail-timer"
    set +e
    script --quiet --return --command "$RUNNER_COMMAND" "$TEST_ROOT/timer-failure.typescript" <<< KEEP > /dev/null
    STATUS=$?
    set -e
    rm "$MOCK_ROOT/fail-timer"
    [[ $STATUS != 0 ]] || fail 'unarmed timer must prevent application'
    pass
    yes cmp -s "$MOCK_ROOT/nft.table" "$TEST_ROOT/kept-table"
    yes ensure_no_pending

    touch "$MOCK_ROOT/fail-nft-once"
    set +e
    script --quiet --return --command "$RUNNER_COMMAND" "$TEST_ROOT/nft-failure.typescript" <<< KEEP > /dev/null
    STATUS=$?
    set -e
    [[ $STATUS != 0 ]] || fail 'failed nft application must fail and restore'
    pass
    yes cmp -s "$MOCK_ROOT/nft.table" "$TEST_ROOT/kept-table"
    yes ensure_no_pending
else
    printf 'SKIP: pseudo-terminal CLI checks (util-linux script is unavailable)\n'
fi

# Invalid user lists are validated before any password prompt can start.
APPLY=0
USERS=root,,root
no passwords
USERS=definitely_missing_ctf_defense_account_987654
no passwords
USERS='root;id'
no passwords

printf 'PASS: %s isolated checks\n' "$CHECKS"
