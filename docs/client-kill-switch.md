# Persistent Linux client firewall

Use a separate Linux client with a tested local console and a standard
WireGuard profile. The helper needs Python 3, systemd, nftables,
wireguard-tools, iproute2 and working `resolvconf` integration. The server and
client packages install independently. Python runs for administrative commands
and once at boot. The kernel enforces the firewall while the helper is stopped.

## Prepare and review on the client

On the gateway, export a Linux profile with the fixed WireGuard routing mark.

```bash
sudo shadowborn client profile --name laptop --strict --output /root/laptop.template
```

Transfer the template over an authenticated encrypted channel. Complete the
private-key field on the laptop. From a trusted checkout on that laptop, install
the completed file and the optional client helper.

```bash
sudo install -d -m 0700 /etc/wireguard
sudo install -m 0600 /path/to/completed/profile.conf /etc/wireguard/wg-shadowborn.conf
./scripts/install-client-lockdown.sh --dry-run
sudo ./scripts/install-client-lockdown.sh
sudo shadowborn-client-lockdown plan
```

Use `--interface NAME` for a custom WG instance. The plan reads the profile and
checks a literal IPv4 endpoint, full IPv4/IPv6 routes, the tunnel DNS address and
`FwMark = 51820`. Profiles containing hooks or custom route tables fail validation.
Review route table 51820, early networking, provider conflicts and resolver
ownership. The helper checks NetworkManager, systemd-networkd and ifupdown. It
refuses an active/enabled Shadow Mist service. A working Kali DoT installation
needs separate compatibility testing.

The default assumes a static uplink. For DHCPv4 add
`--dhcp-interface INTERFACE` to both plan and enable, once per approved uplink.
This permits broadcast UDP from client port 68 to server port 67 on those
interfaces. Unicast renewal may need to wait for broadcast rebinding. ARP and
packet sockets used by some DHCP clients operate at link layer. These frames can
be visible to the LAN. IPv6 WAN bootstrap and routed IPv6 egress are unsupported.

## Try, verify and commit

An outage during the trial interrupts direct connectivity, including remote SSH.
Use the console. The trial lasts **120 seconds**. Timeout restores the prior
ability to send direct traffic and stops a WG service started for that trial.
WG must be stopped with automatic startup disabled before the trial. The helper
suppresses WG service output before its first start. A pending trial also arms
rollback at boot. A reboot before commit returns the client to its prior direct
network access. A completed commit makes the firewall persistent.

```bash
sudo shadowborn-client-lockdown enable --confirm --console-verified
sudo systemctl start wg-quick@wg-shadowborn.service
sudo shadowborn-client-lockdown status
# From the laptop, test DNS and HTTPS to your controlled origin and verify the VPS exit IP.
sudo shadowborn-client-lockdown commit --transaction TRIAL_ID --egress-verified --confirm
sudo systemctl enable wg-quick@wg-shadowborn.service
```

Use the transaction ID printed by enable. The server activation has its own
transaction ID. The `shadowborn client lockdown` subcommands call the same
file-installed helper when the Rust CLI is present.

The output chain drops physical IPv4 and IPv6 traffic by default. It accepts
loopback, the selected WireGuard interface, marked UDP to the exact endpoint
and approved DHCP broadcasts. Forwarding is dropped. At boot the provider and
WG units have explicit Requires/After dependencies on the firewall unit. A
failed load blocks their startup. After systemd sleep returns, a short-lived helper
checks whether the network provider discarded the WG routing rules. It asks
systemd to restart an already active tunnel when those rules are missing. Stopping WG leaves the table in the kernel.
Status compares its rules with the trial fingerprint and inspects installed boot
dependencies. A mismatch or failed inspection yields an unknown enforcement
state. Local DNS changes, external firewall reloads by root, initramfs networking,
privileged raw sockets, containers and physical suspend need separate validation. [WireGuard routing](https://www.wireguard.com/netns/) · [systemd network targets](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html#network-pre.target)

## Time-limited LAN or captive portal access

From a committed client, allow HTTP/HTTPS to a single directly attached IPv4
address with `sudo shadowborn-client-lockdown temporary-lan --uplink INTERFACE
--address PORTAL_IP --seconds 120 --confirm`. Status displays `NOT_STRICT` during
the exception. The kernel expires it within the selected interval (maximum five
minutes), including if the helper exits. No DNS exception is added. Portals
requiring DNS redirects or multiple hosts can remain unreachable.

## Recovery

From the console, stop the tunnel if needed. Disabling the firewall permits
direct access again.

```bash
sudo systemctl stop wg-quick@wg-shadowborn.service
sudo shadowborn-client-lockdown disable --confirm
sudo ./scripts/install-client-lockdown.sh --uninstall
```

The helper removes its own table, unit and dependency files after checking
ownership. A changed file/table stops automatic removal. Inspect it from the
console. An interrupted uncommitted trial can also be cleared with the confirmed
disable command. To migrate a pinned endpoint, stop the connection and review the
new profile on an offline link before starting a new trial. Actual coverage is
recorded in the [validation matrix](validation.md).
