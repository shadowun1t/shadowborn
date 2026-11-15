# Persistent client firewall — VM review bundle

`shadowborn client lockdown render --output /root/client-review` now exports
nftables policy, a systemd unit and a WG unit drop-in using `--config`. This is
file preparation; no policy is applied. Run on a trusted administration machine
with the intended server configuration, then review on the client VM. The client
needs only nftables, wg-quick and systemd, not a Shadowborn daemon.

The owned `inet shadowborn_client` table denies output except loopback, the
configured WG interface, explicitly marked UDP to the pinned server IP/port, and
IPv4 DHCP broadcast (68 → 67). The fixed client `FwMark = 51820` must be placed in
its profile's `[Interface]`; verify it does not collide with other routing marks.
IPv6 physical traffic is denied. IPv6 WAN connectivity/NDP/DHCPv6 is unsupported;
use an IPv4 WAN/static address or DHCPv4. DHCP unicast renewal is not excepted and
may require broadcast rebinding. No LAN, captive portal, physical DNS, or arbitrary
UDP endpoint exception is provided. Forwarding is denied, including container
traffic; do not install on a router or a host needing forwarding.

The table exists before WG and survives WG down/interface deletion. Stopping the
firewall unit deliberately does not delete it. Another firewall's accept rule
cannot undo this table's drop; privileged rule changes can. Table name collisions
must be refused, not treated as ownership. Atomic reloading may replace only a
table already established as owned. No nft log/nflog/counter is generated.

## VM installation review

Use a disposable client VM with a working local/provider console and a snapshot.
Do not use a remote SSH session to enable this on the existing workstation.
Before applying: inspect nft/UFW/firewalld/Docker policy, routing marks, DNS
managers (NetworkManager/resolved/resolvconf and legacy Shadow Mist), early boot
networking and conflicting WG names. Review resolver hookup for the standard
client's `DNS =` setting; no existing DNS manager configuration is overwritten.

Install the reviewed firewall as `/etc/shadowborn-client/lockdown.nft` and unit
as `/etc/systemd/system/shadowborn-client-lockdown.service`, root-owned, without
replacing existing files. Install the WG drop-in for the selected unit instance.
Run `nft -c -f` and `systemd-analyze verify` first. The unit orders before
network-pre.target and WG, but **Before alone does not prevent a network manager
from starting if firewall initialization fails**. Each network provider needs an
explicit Requires/After dependency on the lockdown service. Test its startup
failure and initramfs/pre-systemd network behavior before enabling boot startup.
An installer that safely detects and configures those providers is not shipped.
`enable`/`disable` remain rejected; render is not a verified strict activation.

For manual VM experiments, arm an independently reviewed rollback timer before
applying. Such rollback removes strict protection and must be disclosed. Commit
only after successful policy checks through the console. Emergency recovery from
the console removes only `inet shadowborn_client` and the reviewed provider/WG
drop-ins; preserve all unrelated tables. Never use a global ruleset flush.

## Executed coverage

The namespace lab installs the generated table **before** a WG client interface,
then tests actual WG/NAT traffic using its mark, physical IPv4/IPv6 denial, TCP/UDP
DNS denial, fallback route denial, reload preserving an unrelated table, server
peer removal and interface deletion. None of these tests certify boot, suspend,
multiple live NICs, DHCP/PF_PACKET behavior or remote rollback. PF_PACKET and
privileged processes can bypass ordinary IP hooks. Local ARP and necessary link
control are not encrypted. Hardware/kernel compromise is outside scope.

A server cannot enforce this on a laptop. Do not label a standard import or a
rendered bundle as a verified strict client. Complete boot/failure/provider tests
in tests/vm/README.md before making that claim.
