# Isolated network validation

Build `cargo build --locked -p shadowborn-core --example render_lab`, then run
`python3 tests/namespaces/shadowborn.py` as an ordinary user. It uses disposable
user/network namespaces, synthetic addresses and ephemeral keys. It never runs
privileged commands in the developer host's network namespace.

Executed coverage: actual kernel WireGuard handshake, generated nft syntax and
owned-table replacement, scoped IPv4 NAT/return traffic, host/metadata/spoofed
source denial, and traffic loss after explicit kernel peer removal. This is not
a test of automatic CLI live revoke, real Internet, DNS/DoT, strict client,
boot/recovery or actual VM portability. Missing kernel capabilities/tools are
SKIPPED or explicit failures, never converted into VERIFIED protection.

The filtering continuation also tests IPv4 deny sets, overlapping CIDRs, adding
and removing a block on reload, and preservation of an unrelated table. If
Unbound and openssl are available, it starts a resolver plus a synthetic TLS
upstream entirely inside the isolated lab. A/AAAA/TCP DNS blocks, allow exceptions,
private names, WAN denial, restart and TLS-name failure are checked. No external
DNS/Internet is used. `SHADOWBORN_UNBOUND` may point at an extracted test binary.
The run checks for extra lab files and query/client values in captured process
output; real systemd/journal/reboot no-log compliance remains UNKNOWN.
