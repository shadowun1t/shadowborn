# Shadowborn migration plan

## Gateway and client acceptance, 2026-11-19

The clean checkout at `599701f` has three Shadowborn crates, four Shadow Mist
crates, an initial server activation transaction, an nftables client renderer
and a QEMU transport. All 77 existing Rust tests passed before this work.
The earlier preview guides predate the server transaction. The checkout remote
points to `shadowun1t/shadowborn`; this work leaves Git hosting settings to the owner.
For an older clone still pointing to `shadow-mist`, the owner can first confirm
the intended GitHub account and then use
`git remote set-url origin git@github.com:shadow-alpha01/shadowborn.git`.

1. Exercise the installed CLI on a disposable systemd guest. Repair activation,
   interrupted transactions and authorization reconciliation at their normal
   entry points. Keep the canonical peer state authoritative across restart.
2. Extend the client renderer with a separately installed, explicitly confirmed
   lockdown workflow. Bind network-provider startup to firewall success and
   verify rollback, tunnel loss and boot in an isolated client.
3. Record actual packet, service and privacy checks, with separate commands for
   fresh servers and standard clients. Keep external/provider and hardware
   acceptance gates open until tested on those systems.

Server packaging and client activation remain independent. The working Kali
installation, its resolver, the four legacy crates and the Git remote are
outside the migration.

## Transactional activation and VM acceptance — 2026-11-15

Baseline `01692a9`, clean checkout. Implement a fresh-server-only Linux activation
transaction with protected intent/state, independently armed systemd rollback,
explicit commit after an operator test peer, and boot-time recovery. No network
changes on the Kali workstation. Add canonical-state reconciliation before each
WG start and after peer changes; revocation must be durable before live removal.
Client lockdown needs provider startup dependencies and a separate confirmed
installation flow. Test the real release binary in disposable QEMU VMs, including
rollback on interruption/reboot, live revoke/restart, and suspend/resume where
the virtual hardware supports it. Preserve all legacy packages and user data.


## Optional modules without retained activity history

Baseline `055ff66` is clean and includes the filtering/QR work. The owner now
explicitly excludes history-retaining modules and authorizes optional services
where activity collection can be disabled. No such services are installed yet;
there are no project-owned SIEM/history modules or data to delete.

Implement an independent, opt-in dnscrypt-proxy adapter with an explicitly pinned resolver, no bootstrap
fallback or downloaded resolver lists. Preserve Unbound/filtering and the default
DoT path. Validate actual binaries in disposable namespace/chroot labs; expose
no new public ports, API or web dashboard. Config/state and service generation
must reject weakened logging policies and report remaining VM gates as UNKNOWN.
Remove recording SIEM/IDS/metrics modules from the supported product scope;
document reasons rather than erasing host logs or existing user data. Additional
applications remain gated by evidence, not assumed compliant from one log flag.

## Completion repair — 2026-11-15

Baseline 5f72f29 plus unfinished addon edits in Cargo.lock/core config/render.
Repair the broken compile and stamp format, remove the unverified Pi-hole draft,
finish pinned DoH rendering/CLI/tests, and add a separately exported client
firewall with namespace leak tests. Preserve existing state/default Quad9 and
legacy packages. No live workstation/network changes are authorized here.
Pi-hole is not rejected just because it has a RAM cache: the draft failed startup,
logging, binding and lifecycle verification and contained invalid configuration.

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
no WireGuard server implementation. At that revision the documented `origin` was
`git@github.com:shadow-alpha01/shadowborn.git`.
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
