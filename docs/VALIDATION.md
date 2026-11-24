# Validation - CTF Defense Kit 1.2.0

Completed 2026-11-18 (America/Los_Angeles).

## Environment

| Component | Verified value |
| --- | --- |
| Guest | Ubuntu 24.04.5 LTS, official Noble cloud image |
| Kernel | 6.8.0-147-generic |
| Init | systemd 255 (255.4-1ubuntu8.18) |
| Firewall | nftables v1.0.9 (Old Doc Yak #3) |
| Virtualization | QEMU 7.2.22, TCG, 2 vCPUs, 2 GiB RAM |
| Image SHA-256 | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` |

The VM ran its own Linux kernel with systemd as PID 1. Packet and service tests used real guest commands and services; the isolated tests use mocks.

## Results

| Check group | Passed | Evidence |
| --- | ---: | --- |
| Core isolated regression checks | 125 | `bash tests/test.sh` |
| Isolated audit checks | 35 | `bash tests/test-audit.sh`, also called by `test.sh` |
| Real packet, SSH, and timer checks | 44 | `tests/live-vm.py` and the JSON report |
| Real audit and service checks | 6 | `tests/live-audit-vm.sh` |
| Static analysis | Clean | Entry point, `lib/*.sh`, and `tests/*.sh` explicitly linted with ShellCheck 0.9.0 |

The live packet suite verified baseline reachability, allowed and blocked TCP/UDP ports over IPv4 and IPv6, new authenticated SSH connections through the allowlist, KEEP confirmation, restoration of a previous helper table, and preservation of an unrelated table. It then killed the main Bash process with SIGKILL and verified that a real detached systemd timer restored the previous policy. Recovery was observed 119.47 seconds after SIGKILL; the timer was configured for 120 seconds from activation.

The service suite verified anonymous FTP access and authentication rejection using vsftpd 3.0.5, read-only SUID inventory, SSH key counts/fingerprints, actual SSH configuration reload, kernel hardening, and restoration of the SSH file and live kernel value. This live run exposed a too-short curl connection/authentication timeout; the probe now allows five seconds for connection/authentication and ten seconds overall.

## Reproduce

On a fresh disposable systemd VM, install the documented dependencies plus OpenSSH server, Python 3, and vsftpd. Review the test scripts before running:

```bash
bash tests/test.sh
bash tests/lint.sh
sudo python3 tests/live-vm.py --disposable-vm --report /tmp/ctf-live-validation.json
sudo bash tests/live-audit-vm.sh --disposable-vm
```

The live tests deliberately change networking and service configuration. They create temporary fixtures and an SSH account, then restore/remove them. Use a disposable VM and retain console access. Live tests are never started by the isolated test command.

## Limits

- Ubuntu 24.04.5 LTS only; Kali and other distributions were not live-tested.
- Firewall is host INPUT only and runtime-only; forwarded/Docker traffic needs separate policy.
- Anonymous FTP probe covers loopback TCP 21; custom ports/bindings/FTPS require separate review.
- SUID/SGID root-filesystem scan is bounded and excludes other mounts.
- Authorized-key checks cover conventional local-account paths; custom key commands/paths require separate review.

Existing connections are permitted by the firewall, so testing fresh connections is required. No claim is made about complete compromise recovery, application patching, Windows support, reboot persistence, or forwarded/container traffic. Audit results require review against competition rules.
