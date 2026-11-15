# Optional pinned DoH upstream

The default remains Unbound → Quad9 DoT. The optional adapter uses
WireGuard → VPN-bound Unbound → loopback `127.0.0.1:5354` dnscrypt-proxy →
authenticated HTTPS to one explicitly selected resolver. The hop over loopback
is local plaintext. The network-facing upstream hop uses TLS; no direct DoT or
plaintext fallback is generated. Blocking/private records still run in Unbound.

This adapter currently supports **DoH stamps (protocol 2)**, not DNSCrypt protocol
1, ODoH, relays or automatic provider lists. dnscrypt-proxy is the program name.
The pinned IPv4 address, TLS hostname and path must come from an authenticated
provider source. Certificate verification stays enabled. Optional certificate
hash lists follow the upstream VLP encoding. Embedded bootstrap resolvers,
hostname-only addresses and malformed/trailing stamp data are rejected. Provider
claims encoded in a stamp are not proof of its no-log or DNSSEC behavior.

## Configure before deployment

Save the public `sdns://…` stamp as one line in a local file. For a fresh setup,
add `--dnscrypt-stamp /root/upstream.stamp` to `shadowborn setup`. For an already
initialized **offline** gateway:

```sh
sudo shadowborn dns configure --stamp-file /root/upstream.stamp --dry-run
sudo shadowborn dns configure --stamp-file /root/upstream.stamp --confirm
sudo shadowborn render --output /root/new-dns-bundle
sudo shadowborn dns status
```

Return to the default with `shadowborn dns configure --quad9-dot --confirm`,
then render again. Configuration changes do not start services or edit live DNS.
The canonical state governs existing-gateway operations; editing the original
TOML after initialization does not update that state. Do not keep old bundles as
an alternative mutable configuration. `dns status` reports configuration and
UNKNOWN runtime health; it does not silently probe DNS or retain activity.

For config-first initialization, set `[dns] upstream = "dnscrypt-proxy"` and
`[addons.dnscrypt] stamp = "sdns://…"` together. Either setting without its match
is rejected. Do not paste the placeholder as a working stamp.

## Disposable VM activation

Follow installation-server.md first. In a fresh VM install a reviewed distro
package for dnscrypt-proxy. Its distro service/socket may auto-start: inspect
bindings and stop/disable those only on a dedicated VM where unused and approved.
The generated service is independent, uses DynamicUser and no persistent state.
Check for conflicts on loopback TCP/UDP 5354. Install these non-secret files as
root-owned 0644 under the already reviewed `/etc/shadowborn` and systemd paths:

- `dnscrypt-proxy.toml` → `/etc/shadowborn/dnscrypt-proxy.toml`
- `shadowborn-dnscrypt.service` → `/etc/systemd/system/shadowborn-dnscrypt.service`
- generated `unbound.conf` and `shadowborn-dns.service` as in the server guide

Validate with `dnscrypt-proxy -check -config /etc/shadowborn/dnscrypt-proxy.toml`,
`unbound-checkconf /etc/shadowborn/unbound.conf`, and `systemd-analyze verify`
before activation. Start/reload only through the reviewed VM procedure. Unbound
Wants/After starts the proxy; a proxy outage leaves Unbound's private/block rules
available and external queries fail. Restarting the proxy restores service.
No public port is added. There is no web/API endpoint.

The generator supplies no query/NX/access logs, syslog, source downloads, disk
cache or TLS key log. Program logs go to `/dev/null`; service stdout/stderr and
core dumps are suppressed. OS service lifecycle records remain outside scope.
Volatile DNS caches are operational state, not a stored activity timeline.

## Evidence and limits

Final target: upstream dnscrypt-proxy **2.1.20**, Unbound **1.26.2**, x86_64.
The adapter enables `doh_check_cert_hashes_on_connect`, available in 2.1.20,
so supplied stamp certificate hashes are checked on every new connection.
Older releases are not compatible with the final generated configuration. `tests/namespaces/dnscrypt.py` exercises real processes against
a synthetic HTTPS server with a temporary CA: UDP/TCP, A/AAAA, blocking, proxy
outage/restart and wrong TLS hostname/certificate hash. It compares all fixture files before/after
and asserts empty process output. No Internet provider, systemd boot, swap,
crash dump handling or actual VPS has been certified by that test. Other package
versions must pass the checks; no version-independent compliance claim is made.

References: [stamp format](https://dnscrypt.info/stamps-specifications/) and
[versioned proxy configuration](https://github.com/DNSCrypt/dnscrypt-proxy/blob/2.1.20/dnscrypt-proxy/example-dnscrypt-proxy.toml).
