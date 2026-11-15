# Shadowborn validation

## Repair and executable DNS/client checks — 2026-11-15

Baseline: `5f72f29` plus unfinished edits to core config/render and Cargo files;
those edits did not compile. The Pi-hole draft contained invalid keys, mismatched
DNS ports and an unverified logging lifecycle; its generator is removed. This is
not a general claim that a RAM cache is forbidden or Pi-hole can never be adapted.

| Check | Executed result |
| --- | --- |
| Full local validation | PASS: `scripts/validate.sh`, format, Clippy `-D warnings`, **77 workspace tests**, release build, CLI/packaging tests, 10 legacy integration checks and both namespace labs. |
| DNS configuration | PASS: pinned DoH stamp validation (including truncation, injection, VLP certificate pins and rejected bootstrap fields), offline dry-run/import/default restore, unchanged state after invalid input. |
| Actual encrypted upstream | PASS: dnscrypt-proxy 2.1.20 + Unbound 1.26.2 against synthetic authenticated HTTPS; A/AAAA, UDP/TCP, domain block, restart, proxy outage and wrong TLS name/hash. No plaintext fallback response. |
| Scoped no-history evidence | PASS: DoH lab process stdout/stderr empty; all fixture files identical before/after traffic and failures. No service/journal/reboot/swap certification. |
| Client egress policy | PASS: real WG endpoint with fwmark, output blocked before WG exists, physical IPv4/IPv6 and TCP/UDP DNS denied, fallback route denied, table survives WG removal and preserves unrelated rules on reload. Boot/suspend/provider integration remain untested. |
| Generated configurations | PASS: actual unbound-checkconf and systemd-analyze verify for DNS/proxy/client/server firewall units. Executable paths relocated to extracted tools; syntax is not runtime sandbox certification. |
| QR/keys and legacy | PASS: encrypted QR independently decoded, protected file/state operations and revocation-safe offline restore; all legacy smoke checks. No workstation changes. |
| Shell / diff | PASS: ShellCheck 0.11.0 and diff whitespace checks. |
| Rust advisory query | OSV querybatch for all 62 crates.io package versions in Cargo.lock returned no advisories on 2026-11-15. cargo-audit unavailable; this does not cover kernel, native tools or future advisories. |

Reproduction: `scripts/validate.sh` now includes the guarded namespace suite.
Use the test overrides documented below, plus `SHADOWBORN_DNSCRYPT`. CI fetches
upstream 2.1.20 using tests/tools/fetch_dnscrypt.py and a fixed SHA-256 archive
digest; no distro proxy service is installed. Initial experiments used Debian 2.1.18+ds1-1; final configuration requires
2.1.20 for certificate hash checking on every connection. CI itself has not been executed here.

**Open release gates:** automatic transactional server apply/SSH rollback,
reboot-safe live peer reconciliation, verified strict boot/provider activation,
Debian/Ubuntu/aarch64 VM acceptance, service/journal/reboot no-history audit,
real VPS/phone enrollment and performance. Optional portal/MFA/application adapters
are not implemented. Current code is usable for protected provisioning and
isolated/manual VM evaluation; it is not a completed production release.

## Mistborn filtering continuation

Baseline `7a4be2d`, clean checkout; same isolated Kali x86_64 lab and extracted
Unbound 1.26.2 used below. The added features are offline provisioning policy,
not live gateway administration or a complete Mistborn deployment.

| Check | Result / scope |
| --- | --- |
| Workspace and packaging | PASS: `scripts/validate.sh`, 74 workspace tests, Clippy, release build, generated service syntax, protected provisioning/QR tests and 10 legacy integration checks. Added compatibility/FIFO assertions also passed targeted core/platform tests. |
| Repository checks | PASS: ShellCheck, diff whitespace and common private-key pattern scan across 88 text files (not a complete secret audit). |
| Policy parsing/validation | PASS: domain/hosts/IP imports, normalization, injection/malformed input refusal, size/entry bounds, DNS exception boundaries, private namespace/address restrictions, safe regular-file reads. |
| Offline CLI | PASS: check, full and selected-list import, dry-run, canonical-state planning, setup with policy, unchanged state on invalid input, deployed-host refusal. |
| Domain filtering | PASS: actual Unbound over the kernel WG lab; blocked A/AAAA and TCP requests, descendants, private record resolution and unknown private-name NXDOMAIN. |
| Synthetic authenticated DoT | PASS: allowed exception resolves through a local TLS fixture; wrong authenticated name fails. No public Quad9 or Internet test is implied. |
| Resolver restart / file-output scope | PASS: policy survives process restart, blocked/private queries never reach the synthetic upstream, no additional lab files and no tested query/client values in captured process output. This is not a systemd/journal/reboot no-log certification. |
| IPv4 filter and replacement | PASS: denied synthetic destination and overlapping intervals; replace policy to block a previously reachable destination, restore access, preserve unrelated table. |
| Regression discovered/fixed | Old `flush table` rendering retained nft set elements; owned tables now replaced atomically. Added explicit removed-element regression. |
| Production / optional apps | NOT TESTED / NOT IMPLEMENTED: real VM lifecycle, strict client, live durable revoke, private portal/MFA, Pi-hole, DNSCrypt and application adapters. |

Namespace command: `SHADOWBORN_UNBOUND=/path/to/extracted/usr/sbin/unbound python3
tests/namespaces/shadowborn.py` (or install Unbound in the disposable CI runner).
The generated config's directory, trust store and upstream addresses are relocated
to synthetic fixtures; TLS authentication, ACL and filtering directives remain.
No host network/service settings or customer traffic are used. The helper rejects
direct developer-host execution before opening sockets.

## Continuation validation — 2026-11-14

Starting checkout `b7e5057` was clean. Environment: Kali x86_64, kernel
`7.2.15+kali-amd64`, Rust 1.97.1, ordinary user. The pre-change workspace tests
passed (66). No installed workstation service, route, firewall, DNS or legacy
client state was changed. Privileged CLI checks ran inside disposable
chroot/user/network namespaces; real WG traffic used synthetic namespace peers.

| Check | Result / scope |
| --- | --- |
| `scripts/validate.sh` | PASS: formatting, Clippy with warnings denied, 67 workspace tests, release build, package/provisioning/configuration checks and 10 legacy integration checks. |
| `setup` and QR enrollment | PASS: dry-run without writes; explicit key-generation opt-in; encrypted profile/PNG, unique peer keys, no client private key in state, 0700/0600 permissions, deployed-host refusal. |
| Failure paths | PASS: missing encoder, occupied export, duplicate identity/output and invalid inputs fail; authorization is unchanged and newly created artifacts are cleaned on tested failures. |
| Independent QR decoder | PASS: qrencode 4.1.1 → age 1.3.2 → ZBar 0.23.93 returns the complete profile byte-for-byte; no QR/profile/key echoed to terminal. |
| Generated Unbound/systemd | PASS: Unbound 1.26.2 syntax and systemd unit verification; extracted executable paths relocated for checking. |
| Isolated kernel WG regression | PASS: handshake, generated firewall, scoped NAT/return, host/metadata/spoofed-source denial, traffic stops on explicit kernel peer removal. |
| ShellCheck and diff whitespace | PASS: ShellCheck 0.11.0 on repository shell scripts; `git diff --check`. |
| Actual phone scan/import | NOT TESTED: independent decoding does not certify Android/iOS app compatibility. |
| Runtime no-log policy, real Internet/DoT, VM boot, SSH recovery, strict client | UNKNOWN / NOT TESTED; earlier release gates remain open. |
| Pi-hole | NOT IMPLEMENTED; no runtime compliance claim. |

Missing local tools were downloaded from the configured distro repository and
extracted under a private temporary directory, not installed on the host. Test
overrides: `SHADOWBORN_AGE`, `SHADOWBORN_AGE_KEYGEN`, `SHADOWBORN_ZBARIMG`,
`SHADOWBORN_UNBOUND`, `SHADOWBORN_UNBOUND_CHECKCONF`; these relocate tools for the
tests only. The production executable uses fixed system-tool paths. CI now
installs qrencode and zbar-tools for these checks. No CI run is claimed here.

Reproduce with `scripts/validate.sh`, `python3 tests/namespaces/shadowborn.py`,
`shellcheck scripts/*.sh` and `git diff --check` after installing the documented
test prerequisites. Real service no-log compliance is still **UNKNOWN**.

## Previous baseline — 2026-10-30

Baseline: clean tracked checkout e06bf37; four legacy crates, no server code.
Environment: Kali x86_64, Rust/Cargo 1.97.1; ordinary user. No developer-host
network, installed client, resolver, route, firewall or service changes.
The legacy regression suite remains part of workspace validation; its results
do not certify the new server. Obsolete draft reports have been removed.

All claims refer only to their stated scope; actual supported server OS versions remain NOT TESTED.

| Check | Result / scope |
| --- | --- |
| Formatting, Clippy, workspace tests, release build | PASS; 66 tests (54 legacy + 12 new) |
| Pure configuration/authorization/storage tests | PASS; permissions, conflicts, tombstones, policy and no-history schema |
| Staged server/legacy installation lifecycle | PASS; server documentation links, legacy-only package, retained prior manifest ownership and 10 legacy smoke checks |
| Root CLI in disposable chroot/user/network namespace | PASS; init/enroll, encrypted issue/backup, restore with revocation, deployed-host refusal |
| Generated Unbound / systemd syntax | PASS; Unbound 1.26.1, systemd verify; paths relocated for validation |
| Namespace test entry guard | PASS; absent/current outer-namespace marker rejected before any network command |
| Kernel WG + generated nft NAT in isolated namespaces | PASS: synthetic IPv4 ping/return, owned-table reload |
| Host/metadata/spoofed-source denial | PASS: tested synthetic namespace cases only |
| Explicit kernel peer removal | PASS: traffic stops; does not implement CLI live revoke |
| Real HTTPS, Internet egress IP, public DNS ACL | NOT TESTED |
| Actual authenticated DoT / certificate failure / no-log runtime | NOT TESTED / UNKNOWN |
| Strict client, boot, sleep, multiple NICs, alternate routes, IPv6 bypass | NOT IMPLEMENTED / NOT TESTED |
| VM restart/recovery, SSH lockout, live durable revoke | NOT IMPLEMENTED / NOT TESTED |
| Peer-to-peer and Docker/corporate VPN integration | NOT TESTED |
| aarch64 runtime, Debian/Ubuntu VM acceptance | NOT TESTED |
| Dependency CVE audit, signed release, complete SBOM | NOT TESTED |
| Performance | NOT TESTED |
| Pre-commit repository checks | PASS; relative documentation links, diff whitespace, default server-only Cargo members, no common private-key/token patterns in 78 text files |

Activity-history schema/configuration tests are not a substitute for real
service observations after ordinary traffic, failure, revoke, restart and reboot.
Kernel tests use invented addresses and ephemeral keys, with no customer data,
Internet traffic or persistent packet capture. Namespace exit removes test links.

Commands: scripts/validate.sh; cargo build --locked -p shadowborn-core --example
render_lab; python3 tests/namespaces/shadowborn.py; python3
tests/integration/provisioning.py; python3 tests/integration/generated.py.
Missing optional dependencies are explicitly SKIPPED. No script existence alone
counts as PASS. Tests/vm/README.md lists the outstanding acceptance matrix.

Phase 0 is implemented. Phase 1 provisioning and manual lab generation exist;
automatic activation, network rollback/recovery and live peer lifecycle remain
unfinished. Phase 2 strict activation is rejected. Phase 3 full VM validation and
Phase 4 production hardening/performance are not complete. This is a reviewable
intermediate implementation, not a release candidate.

Extra tools were downloaded from configured distro repositories and extracted
under a temporary directory, never system-installed: Unbound 1.26.1, age 1.3.2,
ShellCheck 0.11.0. ShellCheck passed for all shell scripts. No runtime DoT or
complete service sandbox claim follows from these syntax checks.
