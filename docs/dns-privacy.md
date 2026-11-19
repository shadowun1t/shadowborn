# DNS path

Generated path: device -> WireGuard -> tunnel-bound Unbound -> authenticated
Quad9 TCP/853. Upstream addresses and certificate name are pinned. The resolver
has explicit tunnel-prefix ACL and server firewall admits only authorized peer
addresses over WG. Plaintext forwarded client DNS to external port 53 is denied;
application DoH inside the tunnel remains possible.

Native [domain filtering and private names](filtering.md) are now configurable
without adding another resolver. Domain deny/allow rules use Unbound local zones;
unknown private names stay local. Policy includes no query history or hit counters.
This is not a Pi-hole installation and does not certify future Pi-hole defaults.

The renderer uses forward-first=no, a CA bundle, zero verbosity, disabled
query/reply/SERVFAIL logs, disabled syslog, disabled remote control and no periodic
statistics/cache persistence. Verify with the installed unbound-checkconf and
actual service/journal observations. Transport privacy, DNS availability and
DNSSEC are different: local DNSSEC validation is not enabled in this preview;
Quad9 performs its upstream policy. The namespace suite tests synthetic DoT
authentication and rejects the wrong name. The VM suite exercises the tunnel
resolver under systemd and AppArmor on Debian and Ubuntu. Public Quad9 service
and reachability from a specific hosting provider require a separate check.

The strict client firewall blocks physical DNS, including while the resolver or
tunnel is down. The standard import alone requires separate host firewall policy
for that protection. See the [VM and namespace tests](validation.md).
The upstream resolver sees requested names; external logging cannot be controlled.
See the [official Unbound configuration reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).

## Optional Pi-hole after the core VPN

Mistborn's gateway and convenient device enrollment are design inspiration; no
code or service stack is imported. The current build deliberately has no Pi-hole
dependency. Each additional resolver needs its own runtime packet, output and
retention tests before inclusion.

The proposed later path is client → WireGuard → VPN-only Pi-hole → local Unbound
→ authenticated DoT upstream. Pi-hole would add blocking; it would not add
client-to-server transport encryption, which WireGuard already provides. The
client and server resolver still know the query; encryption does not hide it
from those endpoints. HTTPS application content has a separate protection scope.

The [Pi-hole FTL configuration reference](https://docs.pi-hole.net/ftldns/configfile/)
checked 2026-11-14 documents query logging, long-term query retention and separate
log destinations. Its defaults do not satisfy Shadowborn's policy. A future
version-specific adapter must set `dns.queryLogging=false`, `database.maxDBdays=0`,
`database.DBimport=false` and `misc.privacylevel=3`, and independently disable
network/client inventory, query analysis, packet capture, diagnostic logs,
web access logs and every debug output path. These are design requirements,
**not a validated configuration**; four settings alone do not certify compliance.

Before integration, test synthetic traffic, failure, restart and reboot against
the exact packaged version. Inspect disk, journal, API/history responses and
shared-memory behavior; verify no query/client/connection history is retained.
Keep persistent blocklist/configuration data separate from forbidden activity
records. Limit listener access to authorized tunnel peers, avoid resolver loops,
and expose no public dashboard. If any activity sink cannot be disabled, do not
ship the integration. Current Pi-hole integration/compliance: **NOT IMPLEMENTED /
UNKNOWN**. Disabling statistics means losing the usual per-client query charts.

The optional [dnscrypt-proxy adapter](dnscrypt.md) supports pinned DoH without
bootstrap resolvers or transport fallback. It is selected explicitly per gateway.
