# Isolated network validation

Build `cargo build --locked -p shadowborn-core --example render_lab`, then run
`python3 tests/namespaces/shadowborn.py` as an ordinary user. It uses disposable
user/network namespaces, synthetic addresses and ephemeral keys. It never runs
privileged commands in the developer host's network namespace.

Two independently authorized peers reach a controlled origin through kernel WG
and scoped IPv4 NAT. They cannot reach each other, host management or metadata.
Spoofed source addresses are dropped. Tests exercise the strict client across a
second veth uplink, direct fallback routes and deletion of the WG interface.
Missing kernel capabilities or tools are reported as skips or explicit failures.

The filtering continuation also tests IPv4 deny sets, overlapping CIDRs, adding
and removing a block on reload, and preservation of an unrelated table. If
Unbound and openssl are available, it starts a resolver plus a synthetic TLS
upstream entirely inside the isolated lab. A/AAAA/TCP DNS blocks, allow exceptions,
private names, WAN denial, restart and TLS-name failure are checked. No external
DNS/Internet is used. `SHADOWBORN_UNBOUND` may point at an extracted test binary.
The run checks for extra lab files and query/client values in captured process
output. Service output and reboots are tested separately in [QEMU](../vm/README.md).

Client policy is now exercised before WG creation and after route/interface loss,
including physical IPv4/IPv6 and TCP/UDP DNS denial.
Run `python3 tests/namespaces/dnscrypt.py` for the real proxy + Unbound synthetic
HTTPS path; set `SHADOWBORN_DNSCRYPT` and `SHADOWBORN_UNBOUND` if extracted binaries
are used. This test fails (rather than passes) when its required tools are absent.
