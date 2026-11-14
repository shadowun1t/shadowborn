# Shadowborn migration plan

## Mistborn feature expansion

The next continuation starts from a clean tracked checkout with the QR/setup
work already committed. The requested reference is now specifically
`https://gitlab.com/harlequin516/mistborn`; its README, base composition and MIT
license were inspected. No upstream source or old image versions are imported.

Preserve existing server and legacy modules. Add an optional, backwards-compatible
filtering policy to server configuration: domain deny/allow lists, private DNS
records and IPv4 destination CIDRs. Compile that policy into the existing Unbound
and nftables bundle, with bounded list import, offline CLI management and real
namespace DNS/firewall tests. These lists are administrator configuration, never
observed query/traffic history. No automatic list download or activity recorder.

Track the entire requested feature set in `mistborn-parity.md`, including the
remaining gateway lifecycle, private portal/MFA and optional applications. Each
integration needs its own isolation, secret custody, version and no-log tests.
Historical traffic/SIEM features remain incompatible with the mandatory policy;
do not silently relax it. Host deployment and existing client changes still
require explicit operator action.

Baseline inspected on 2026-10-30: clean tracked checkout at `e06bf37`, four
`shadowmist-*` workspace crates, a local NetworkManager/resolved privacy client,
no WireGuard server implementation. `origin` already points to
`git@github.com:shadow-alpha01/shadowborn.git`. No remote change is necessary.
The supplied AGENTS.md is included in the new repository; its old ignore rule
was removed.

1. Preserve the four legacy crates, commands, systemd units, configuration and
   installer. Archive their documentation under explicitly named legacy pages.
2. Add independent `shadowborn-core`, `shadowborn-platform`, `shadowborn-cli`
   crates. No dependency on NetworkManager or legacy host discovery.
3. Implement validated server configuration, minimal peer authorization state,
   native WireGuard key generation, protected provisioning bundles, a separate
   installer, encrypted backups and conservative recovery.
4. Generate server firewall, DNS and service configuration for disposable VM
   evaluation. Keep automated live apply and strict client activation unsupported
   until rollback, boot and packet-level failure gates are demonstrated.
5. Publish separate server and standard client instructions and explicit gates.
   Never describe generated configuration or mocked tests as a validated VPN.

No existing workstation service, DNS configuration, firewall, routes, keys or
installed application is changed by this migration. No push, remote publication
or Git history rewrite is part of this task.

## Continuation: simple server preparation and QR enrollment

Baseline re-inspected 2026-11-14 at `b7e5057`: clean working tree, seven workspace
crates, existing offline provisioning and manual VM deployment. Live apply,
live peer reconciliation and strict client activation remain unsupported. The
previously recorded namespace results are historical, not new VM acceptance.

Extend the existing three server crates, preserving the four legacy crates:

1. Add a file-only `setup` workflow using the existing validated policy and
   protected storage, with explicit endpoint/WAN/admin inputs and a dry-run.
2. Add opt-in per-device QR export. The QR contains the same standard WireGuard
   profile as the encrypted file; both are age-encrypted to the administrator.
   No plaintext QR, key-bearing command arguments or terminal QR output.
3. Test QR decoding against the profile, failure cleanup, permissions, isolated
   provisioning and absence of retained activity fields/files. Keep runtime
   service/reboot claims UNKNOWN until measured in VMs.
4. Document local import and the deferred Pi-hole acceptance gates. First finish
   safe activation/recovery, live revocation and persistent client enforcement;
   DNS add-ons must pass the same no-activity-history policy before integration.

Licensing: the root LICENSE contains AGPLv3 while legacy Cargo metadata says
MIT. Preserve both historical evidence and older source; do not infer ownership
or a relicensing grant. See licensing.md before distributing a release.

## Pre-commit cleanup

The owner confirmed retaining the legacy client while removing unnecessary draft
material. Operational legacy guides now live only under docs/legacy. Superseded
roadmaps, historical incident/test reports, duplicate guides, a static file list,
unused fixtures and placeholder-only directories were removed. Default Cargo
members select Shadowborn; explicit --workspace checks retain legacy coverage.
The legacy installer builds only its two binaries and ships its own guide and
documentation, not the server manual. No installed host files are changed.
