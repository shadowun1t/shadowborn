# Design references

The owner's expanded reference is [harlequin516/mistborn](https://gitlab.com/harlequin516/mistborn).
Its README, base service composition and license were inspected for the
[feature coverage plan](mistborn-parity.md). The fork's LICENSE is MIT with
Steven Foerster's notice; this does not resolve this repository's separate
license provenance issue. No upstream source/configuration was imported.

Mistborn is architectural inspiration for an owned VPN gateway plus DNS, not a
source dependency. No code, web stack, license or old defaults were imported.
Pi-hole and dnscrypt-proxy are deferred; any future integration must independently
pass the no-query-history/no-database/no-telemetry gate for its exact version.

Primary references used for fresh configuration design:

- [WireGuard quick start and key generation](https://www.wireguard.com/quickstart/)
- [wg-quick routing and DNS behavior](https://manpages.debian.org/bookworm/wireguard-tools/wg-quick.8.en.html)
- [nftables manual](https://www.netfilter.org/projects/nftables/manpage.html)
- [Netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)
- [Unbound configuration](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [systemd service execution/sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

Online documentation is design input, not proof of installed-version behavior.
Actual namespace and VM results are recorded separately in validation.md.

QR continuation: [qrencode CLI reference](https://github.com/fukuchi/libqrencode/blob/master/qrencode.1.in)
and the installed 4.1.1 help were checked for stdin input and PNG output to a pipe.
The optional future DNS stack is assessed against the
[Pi-hole FTL reference](https://docs.pi-hole.net/ftldns/configfile/), not historical
Mistborn defaults. No QR or DNS-addon source code was copied.
