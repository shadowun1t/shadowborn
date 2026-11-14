# Domain and IP filtering without activity history

Shadowborn now prepares domain blocking, DNS exceptions, private names and IPv4
destination filters. All inputs are deliberate administrator configuration. No
visited domain/IP is learned, counted, recorded or automatically added to a list.
This provides the blocking functions associated with Pi-hole and Coppercloud
using the existing Unbound/nftables stack. Pi-hole itself is not installed.

## Prepare a policy

Use `config/filtering.example.toml` as a standalone policy file:

```toml
blocked_domains = ["ads.example", "telemetry.example"]
allowed_domains = ["updates.telemetry.example"]
blocked_ipv4 = ["198.18.1.0/24"]

[[local_records]]
name = "gateway.shadowborn.home.arpa"
address = "10.89.0.1"
```

These are invented example names/benchmark addresses, not an included production
blocklist. Select and review your own lists; their licensing and provenance matter.
Shadowborn performs no remote downloads or automatic scheduled list updates.

For a fresh gateway, add `--policy /absolute/path/filtering.toml` to `setup` and
its `--dry-run`. Alternatively put the fields under `[filtering]` and
`[[filtering.local_records]]` in server TOML before `init`. Existing configuration
and state without `filtering` retain empty lists. Optional private records must
use usable addresses within the configured tunnel subnet.

Check a standalone policy without privileges/state creation:

```bash
shadowborn --config config/server.example.toml policy check \
  --input config/filtering.example.toml
```

## Update offline provisioning state

For a gateway initialized at the default paths:

```bash
sudo shadowborn policy import --input /root/filtering.toml --dry-run
sudo shadowborn policy import --input /root/filtering.toml --confirm
sudo shadowborn policy show
sudo shadowborn plan --json
sudo shadowborn render --output /root/shadowborn-filtered-review
```

`policy import` replaces the **entire filtering section**. `policy show` shows
configuration, not queried names. After initialization, `plan` reads canonical
state (and requires root), so a changed policy cannot be hidden behind the old
input config. `validate`/`policy check` still check the explicitly selected config
file; they do not validate live enforcement. For `setup` output, pass
`--state-dir /root/shadowborn-prepared/state` to state operations.

All mutations refuse a detected deployed gateway. Importing a policy does not
reload Unbound or nftables. Retire stale exports; activate the new reviewed
bundle only under the [manual VM procedure](installation-server.md). Live policy
updates and automatic rollback are still unfinished. Config/key backups include
this necessary policy; restore refuses mismatched gateway policy, so it cannot
silently replace the current filtering section with an older backup.

## Import existing local lists

Domain input supports one domain per line, comments beginning with `#`, or hosts
lines with `0.0.0.0`, `127.0.0.1`, `::` or `::1` followed by domains. Conventional
localhost aliases are skipped. Names are lowercased, a trailing dot is removed,
and duplicates collapse. Wildcards, URLs, Adblock syntax and arbitrary hosts
redirects are rejected. Convert unsupported lists explicitly before import.

```bash
sudo shadowborn policy import-blocklist --kind domains \
  --input /root/reviewed-domains.txt --dry-run
sudo shadowborn policy import-blocklist --kind domains \
  --input /root/reviewed-domains.txt --confirm
sudo shadowborn policy import-blocklist --kind ipv4 \
  --input /root/reviewed-networks.txt --confirm
```

Each command replaces only the selected deny list, preserving DNS exceptions
and local records. Exceptions that no longer match a blocked parent reject the
change: adjust the complete policy rather than silently discarding exceptions.
IPv4 input accepts canonical CIDRs or individual addresses (converted to `/32`).
Prefixes with host bits are rejected rather than expanded. Overlapping prefixes
are merged by nftables. There is no IP allowlist that overrides metadata/LAN
isolation. An explicit `0.0.0.0/0` filter blocks all forwarded IPv4 for peers.

Input is limited to 4 MiB and the complete policy to 20,000 entries; the existing
protected-state size limit also applies. Any invalid line rejects the complete
import and leaves authorization state unchanged. Errors identify line numbers
without reflecting raw input. Symlinks, devices and FIFOs are refused as input.

## Enforcement boundaries

Unbound returns NXDOMAIN for blocked names and their descendants, for A and AAAA
as well as other record types. The most specific zone wins; an explicit allow
wins when allow and block name are identical. Exceptions forward normally over
the configured authenticated DoT path. A more specific blocked descendant remains
blocked. This is DNS-name filtering, not a browser content filter or inspection
of every CNAME target in upstream answers. Application-owned DoH, cached answers,
direct IPs and shared CDN destinations impose limits; no universal ad/telemetry
blocking claim is made.

The private `shadowborn.home.arpa` zone is authoritative and unknown names return
NXDOMAIN locally. Private records create names only: server/peer isolation still
applies and no service port is opened. Lists cannot override that namespace.

The nftables filter drops matching destinations before peer forwarding and matching
return sources before established replies. It applies to all protocols from VPN
peers, including traffic independent of DNS; it does not filter the server's own
output or modify the WireGuard UDP/SSH ingress exceptions. IPv6 forwarding stays
blocked. Lists can break legitimate applications; policy changes require review.

Generated updates replace the two owned tables in one nft batch. The former
`flush table` approach was insufficient because it retained set elements; a
removed block could stay active. The namespace regression now proves adding
and removing a block and preserving an unrelated table. This fixes bundle
replacement semantics; host ownership checks and safe live activation remain
manual/release-gated.

No logging, hit counters, persistent statistics, telemetry or browser dashboard
is added. Namespace tests exercise actual Unbound and kernel forwarding, but VM
service/journal behavior and full runtime no-log certification remain UNKNOWN.

Semantics follow the [Unbound local-zone reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#local-zone)
and [nftables set reference](https://www.netfilter.org/projects/nftables/manpage.html).
