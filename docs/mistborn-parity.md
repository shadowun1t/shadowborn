# Mistborn feature coverage

Requested reference: [harlequin516/mistborn README](https://gitlab.com/harlequin516/mistborn/-/raw/master/README.md),
with its [base service composition](https://gitlab.com/harlequin516/mistborn/-/raw/master/base.yml),
reviewed against clean Shadowborn checkout `7a4be2d`. This is a coverage plan,
not a claim that the complete platform has been implemented. No upstream source,
container pins, credentials, install script or screenshots were imported.

## Gateway and privacy features

| Reference capability | Shadowborn implementation / remaining work |
| --- | --- |
| WireGuard and per-device profiles | Separate device keys and PSKs, encrypted imports, kernel tunnel and scoped IPv4 NAT exercised on Debian and Ubuntu VMs. |
| Mobile QR | Encrypted QR/profile issuance and independent decode tests; actual phone app acceptance remains untested. |
| Installation and upgrades | Independent server/client packages, managed activation, timed rollback and recovery of pending gateway deployments at boot. |
| Live peer management | Committed gateway changes reconcile authorization, WG and the firewall. Revocation survives a service restart and gateway reboot. |
| DNS ad/malware blocking | Implemented through Unbound local policy, hosts/domain imports and allow exceptions; actual namespace DNS tests. This does not install Pi-hole. |
| Coppercloud IP filtering | Implemented as configured IPv4 destination sets in owned nftables tables; synthetic block/reload tests. IPv6 is currently blocked as a whole. |
| Private service names | Implemented under `shadowborn.home.arpa`; names do not grant network access or install an application. |
| Pi-hole | Planned optional blocking UI/backend; exact-version no-history, network inventory, API, file and journal gates remain. |
| dnscrypt-proxy | Pinned DoH adapter implemented and namespace tested; DNSCrypt protocol 1/ODoH remain unavailable. No bootstrap plaintext fallback. See dnscrypt.md. |
| Web management portal | Planned separate VPN-only surface after safe backend lifecycle; no public management listener, Docker socket access or root web process. |
| MFA Internet access | Planned second-factor policy gate tied to the individual WG identity; fail closed on expiry/reboot, no stored session timeline. |
| Users/groups and delegated administration | Planned minimal authorization configuration with separate device identities and scoped permissions. |
| Client-to-client access | Default isolation implemented; explicit narrow peer/service grants require additional policy and tests. |
| Alternate egress gateway | Planned explicit topology mode; extra routing/MTU and failure tests required. No streaming-availability promise. |
| TLS/private certificates | Planned for private applications; certificate renewal, name validation and secret custody gates. |
| Configurable UDP ports | A single explicit `--listen-port` already exists; no random per-device ports, port hopping or implicit alternate-port listeners. Port changes require reviewed client migration. |
| Service start/stop/update/reset | Standard WG systemd lifecycle is documented; optional-app lifecycle, version pinning, rollback and deliberate data removal remain to implement. |
| SSH and OS maintenance | Explicit SSH allowlist in generated policy; guarded host hardening/update guidance, no automatic password-policy changes or global firewall-manager disablement. |
| Backup/recovery | Encrypted configuration backup and offline authorization-safe restore; live disaster recovery remains unimplemented. |
| Firewall history/metrics | Historical activity recording excluded by the mandatory no-logs policy. Current scoped diagnostics may be added without retention. |
| Wazuh / Suricata security center | Original activity collection/IDS histories conflict with no-logs. Do not bundle those recording paths or silently label them compliant. |

## Optional application integrations

All rows below are **NOT IMPLEMENTED**. Listing an application is not deployment
support. Each adapter needs reviewed version/image digests, a private network
boundary, service-specific no-log configuration, secret initialization and tested
update/backup/removal. No shared master password or automatic public port binding.

| Application | Acceptance work before bundling |
| --- | --- |
| Vaultwarden | Unique administrator credentials, private TLS, access/error log suppression, encrypted data backup. |
| Syncthing | Explicit devices, private discovery/relay policy, no unexpected external discovery or usage reporting. |
| Nextcloud | Private TLS/database, background jobs, activity/audit/access logging review and user-content backup. |
| OnlyOffice | Authenticated document-service access, token custody, temporary document and request-log policy. |
| Rocket.Chat | Private account/authentication configuration, telemetry/access logging review and deliberate message retention. |
| Jitsi | Signaling/media reachability through approved paths, TURN secrets and no meeting/session history. |
| Jellyfin | Private service access, no playback/access history or telemetry; explicit media storage. |
| Home Assistant | Private access, recorder/history/analytics review; device discovery cannot override VPN isolation. |
| Guacamole | Private authentication and target allowlists; no session recordings or connection-history database. |
| RaspAP | Explicit owned hardware target and separate AP policy; never repurpose the existing laptop. |
| Tor | Optional, separately described egress mode with loop/leak tests; never an anonymity guarantee. |
| Cockpit | Private administrative scope and authentication; review host-management permissions and log boundaries. |

User-requested files, vault items, documents and chat messages are intentional
application content, distinct from VPN activity logs. Each optional service must
state what it stores; it cannot inherit a no-retained-activity certification from
the gateway. If required service behavior cannot meet the policy, keep that
integration unavailable and document the conflict.

## Implementation order and release gates

1. Reproduce the tested gateway activation, independent rollback, SSH access
   and reboot-safe live revocation on the operator's intended VPS.
2. Verify the strict client on the intended physical laptop, including its real
   network provider, uplink switches and sleep transitions.
3. Add the VPN-only portal, minimal authorization and second-factor gate on top
   of the verified local control plane; browser sessions remain current security
   state, never a historical access journal.
4. Add the selected DNS backend (Pi-hole and/or DNSCrypt as separately tested
   options). The native domain/IP filtering can already be provisioned today.
5. Add application adapters independently, starting with a small service such
   as Vaultwarden; verify each no-log configuration before integration is enabled.

Private HTTP routes/reverse-proxy middleware are part of the portal gate, not a
reason to expose ports publicly. Container integration must account for DNAT and
forwarding paths explicitly. Keep package updates separate from network policy;
replacing upstream tags and restarting services blindly is not an update strategy.

Public provider and hardware acceptance and the optional application adapters
remain open. Use [validation](validation.md) for measured gateway and client behavior and
[filtering](filtering.md) for the functions implemented in this continuation.
