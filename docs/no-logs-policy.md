# No retained activity logs

This is mandatory for Shadowborn-owned components, not an anonymity guarantee.
Configuration rejects enabling telemetry, peer activity storage or query logging.

Never collect or persist browsing URLs, DNS queries, destination-flow history,
packet payloads/captures, connection history, observed source IPs, location,
handshake timelines or per-peer traffic series. No analytics, metrics exporter,
crash reporting, remote collector or persistent troubleshooting mode exists.
The CLI performs no periodic recording. A privileged `status` inspects current
interface, firewall and service state. DNS privacy and egress requiring an
independent client observation remain unknown or untested.

Filtering lists contain domains and CIDRs deliberately chosen by the operator,
plus private service-name configuration. They are never populated from queries,
flows or counters. `policy show` reveals configuration only. The domain/IP
filters do not produce query logs, hit statistics or historical reports.
Mistborn-style firewall histories and recording SIEM/IDS integrations remain
incompatible with this policy; optional applications need separate verification.

Necessary persistent configuration: server private/public key, peer public keys,
per-peer PSKs, assigned tunnel addresses, names, active/disabled/revoked state,
validated server policy. Revoked entries lose their PSK but keep a tombstone to
prevent reuse/restore. Managed activation also stores its current rollback
configuration and hashes of owned rules. An empty pending-authorization marker
wakes systemd if a writer exits during a peer change. It contains no identity or
timestamp and is removed after reconciliation. The strict client stores the pinned
endpoint, allowed DHCP interfaces, transaction state and configuration hashes.
Temporary LAN exceptions expire in the kernel. Secret directories are 0700
and secret files 0600. Configuration
backups are age encrypted with an explicit recipient; retained copies contain
secrets and authorization inventory, never traffic. The operator controls backup
retention and must retire outdated exported profiles/bundles. Memory buffers are
not guaranteed to be securely erased; no SSD erasure promise is made.

Convenience enrollment and `setup` generate a device key in server memory only
after explicit opt-in. Its importable profile and optional PNG QR are encrypted
with age before file creation. Neither plaintext keys/QRs nor device private keys
are saved in authorization state, stdout/stderr, subprocess arguments or service
logs. These encrypted credentials are configuration/security artifacts, not
activity records. The QR viewer/client OS and operator-managed decrypted copies
are outside the server policy; avoid screenshots, browser upload and thumbnail
history. Encryption at rest is not proof of memory/swap erasure.

Generated Unbound disables query/reply/SERVFAIL logs, syslog and periodic
statistics; no cache-dump or remote-control service is enabled. Its volatile
cache necessarily holds current DNS data in RAM. Service stdout/stderr are null
and core dumps disabled per service. Generated nft rules have no log/nflog or
counters. WG service output is suppressed by a per-instance drop-in. No global
journald, SSH, kernel or security auditing settings are changed.

The OS/systemd manager may record unit lifecycle and administrator actions.
The VPS/cloud provider, ISP, upstream Quad9 resolver and websites can retain
their own metadata. WireGuard and conntrack retain live operational state in
kernel memory. Shadowborn does not control these boundaries. Legacy Shadow Mist
has its own existing status/event semantics and is not covered by this new
server-owned-service claim.

On 2026-11-19 the Debian 13 and Ubuntu 24.04 KVM tests sent synthetic DNS and
HTTPS traffic, interrupted the tunnel and resolver, revoked a peer and rebooted.
The tests checked the service-process journal streams for the scoped WG instance
and Shadowborn units, the project configuration/state inventory, and file names
under `/var/log` and `/var/cache`. The inspected streams were empty and the
expected gateway files contained no test query. PID 1 can record unit starts
and stops. Host swap, third-party services, provider records and other resolver
versions remain outside these observations. This policy limits retrospective
diagnosis: there is no per-device history to recover after an incident.
[Test scope and reproduction](validation.md).

The optional dnscrypt-proxy adapter has no query/NX log sinks, source downloads,
disk cache or system DNS bootstrap. Its loopback upstream and static DoH stamp
are configuration only. The namespace test confirms empty process output and
unchanged fixture files through traffic, proxy restart/outage and TLS failure.
This is not a journal/reboot/swap certification. See dnscrypt.md. The unfinished
Pi-hole generator was removed; no FTL compliance is claimed. RAM caches alone
do not violate this policy, but retained activity timelines do.
