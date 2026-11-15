//! Persistent Linux client policy. Rendering never modifies the workstation.
use crate::Config;
use anyhow::Result;
use std::collections::BTreeMap;
pub const CLIENT_FWMARK: u32 = 51820;
pub fn client_lockdown(config: &Config) -> Result<BTreeMap<String, String>> {
    config.validate()?;
    let wg = &config.server.interface;
    let rules = format!(
        r#"# Owned CLIENT table only; do not install on the server.
# Persists independently of WireGuard. No counters, captures or logs.
add table inet shadowborn_client
delete table inet shadowborn_client
table inet shadowborn_client {{
    chain output {{
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        oifname "{wg}" accept
        meta mark {mark} ip daddr {endpoint} udp dport {port} accept
        ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
}}
"#,
        mark = CLIENT_FWMARK,
        endpoint = config.server.endpoint,
        port = config.server.listen_port
    );
    let unit = format!(
        r#"[Unit]
Description=Shadowborn persistent Linux client egress lock
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target wg-quick@{wg}.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/sbin/nft -c -f /etc/shadowborn-client/lockdown.nft
ExecStart=/usr/sbin/nft -f /etc/shadowborn-client/lockdown.nft
StandardOutput=null
StandardError=null
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
"#
    );
    let dropin = "[Unit]\nRequires=shadowborn-client-lockdown.service\nAfter=shadowborn-client-lockdown.service\n\n[Service]\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n";
    Ok(BTreeMap::from([
        ("lockdown.nft".into(), rules),
        ("shadowborn-client-lockdown.service".into(), unit),
        ("wg-quick-client-lockdown.conf".into(), dropin.into()),
        ("CLIENT-REVIEW.txt".into(), format!("REVIEW BUNDLE; NOT ACTIVATED OR BOOT-CERTIFIED.\nLinux client interface: {wg}\nAdd FwMark = {CLIENT_FWMARK} to the client profile [Interface].\nRequires console access, firewall conflict review and docs/client-kill-switch.md.\nOnly DHCPv4 broadcast is excepted; static IPv4 also works. No IPv6 WAN bootstrap.\nPF_PACKET/DHCP clients, privileged processes, initramfs networking and host suspend/boot require separate verification.\nStopping the unit or wg-quick does not remove this firewall.\n")),
    ]))
}
