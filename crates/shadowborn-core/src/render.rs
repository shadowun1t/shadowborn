use crate::{PeerStatus, State};
use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub stage: &'static str,
    pub network_mutations: bool,
    pub interface: String,
    pub wan_interface: String,
    pub listen_port: u16,
    pub endpoint: String,
    pub tunnel_ipv4: String,
    pub ssh_port: u16,
    pub ssh_admin_cidr: String,
    pub active_peers: Option<usize>,
    pub ipv6: &'static str,
    pub no_activity_logs: &'static str,
    pub live_apply: &'static str,
    pub files: Vec<&'static str>,
    pub required_operator_checks: Vec<&'static str>,
    pub policy_entries: BTreeMap<&'static str, usize>,
    pub optional_addons: Vec<&'static str>,
}
pub fn plan(config: &crate::Config, state: Option<&State>) -> Result<Plan> {
    config.validate()?;
    if let Some(state) = state {
        state.validate()?;
    }
    let mut files = vec![
        "WireGuard config (secret)",
        "server.nft",
        "unbound.conf",
        "shadowborn-firewall.service",
        "shadowborn-dns.service",
        "WireGuard service drop-in",
        "99-shadowborn.conf",
    ];
    if config.addons.dnscrypt.is_some() {
        files.extend(["dnscrypt-proxy.toml", "shadowborn-dnscrypt.service"]);
    }
    Ok(Plan {
        schema_version: 1,
        stage: "PROVISIONING_ONLY",
        network_mutations: false,
        interface: config.server.interface.clone(),
        wan_interface: config.server.wan_interface.clone(),
        listen_port: config.server.listen_port,
        endpoint: config.server.endpoint.to_string(),
        tunnel_ipv4: config.server.tunnel_ipv4.clone(),
        ssh_port: config.server.ssh_port,
        ssh_admin_cidr: config.server.admin_ipv4.clone(),
        active_peers: state.map(|s| {
            s.peers
                .iter()
                .filter(|p| p.status == PeerStatus::Active)
                .count()
        }),
        policy_entries: BTreeMap::from([
            ("blocked_domains", config.filtering.blocked_domains.len()),
            ("allowed_domains", config.filtering.allowed_domains.len()),
            ("blocked_ipv4", config.filtering.blocked_ipv4.len()),
            ("local_records", config.filtering.local_records.len()),
        ]),
        optional_addons: [config.addons.dnscrypt.is_some().then_some("dnscrypt-proxy")]
            .into_iter()
            .flatten()
            .collect(),
        ipv6: "BLOCKED_ON_SERVER; CLIENT_ENFORCEMENT_NOT_VERIFIED",
        no_activity_logs: "CONFIGURED; RUNTIME_UNKNOWN",
        live_apply: "UNSUPPORTED: timed rollback, reboot recovery and SSH gates not met",
        files,
        required_operator_checks: vec![
            "WAN/default routes and tunnel subnet collisions",
            "existing nftables/UFW/firewalld/Docker ownership",
            "SSH admin CIDR/port and tested out-of-band console",
            "UDP endpoint/cloud firewall and public addressing",
            "DNS port binding conflict and Unbound version",
            "nft syntax and isolated packet-level tests",
            "no activity logs across restart/failure/reboot",
        ],
    })
}
pub fn server_wireguard(state: &State) -> Result<String> {
    state.validate()?;
    let s = &state.config.server;
    let mut text = format!(
        "[Interface]\nAddress = {}\nListenPort = {}\nPrivateKey = {}\nSaveConfig = false\n",
        s.tunnel_ipv4,
        s.listen_port,
        state.server_private_key.expose()
    );
    for peer in state
        .peers
        .iter()
        .filter(|p| p.status == PeerStatus::Active)
    {
        text.push_str(&format!(
            "\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}/32\n",
            peer.public_key,
            peer.psk
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing PSK"))?
                .expose(),
            peer.address
        ));
    }
    Ok(text)
}
pub fn server_firewall(state: &State) -> Result<String> {
    state.validate()?;
    let s = &state.config.server;
    let prefix = state.config.prefix()?;
    let peers = state
        .peers
        .iter()
        .filter(|p| p.status == PeerStatus::Active)
        .map(|p| p.address.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let elements = if peers.is_empty() {
        String::new()
    } else {
        format!("elements = {{ {peers} }};")
    };
    let blocked = if state.config.filtering.blocked_ipv4.is_empty() {
        String::new()
    } else {
        format!(
            "elements = {{ {} }};",
            state.config.filtering.blocked_ipv4.join(", ")
        )
    };
    Ok(format!(
        r#"# Owned tables only. Review collisions before the FIRST VM activation.
# A single nft batch replaces these owned tables atomically. No activity logging.
add table inet shadowborn
delete table inet shadowborn
add table ip shadowborn_nat
delete table ip shadowborn_nat
table inet shadowborn {{
  set peers {{ type ipv4_addr; {elements} }}
  set blocked_v4 {{ type ipv4_addr; flags interval; auto-merge; {blocked} }}
  set forbidden {{ type ipv4_addr; flags interval; elements = {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }}; }}
  chain vpn_input {{
    ip saddr @peers ip daddr {dns} udp dport 53 accept
    ip saddr @peers ip daddr {dns} tcp dport 53 accept
    drop
  }}
  chain input {{
    type filter hook input priority filter; policy drop;
    ct state invalid drop
    iifname "{wg}" jump vpn_input
    iifname "lo" accept
    ct state established,related accept
    iifname "{wan}" ip saddr {admin} tcp dport {ssh} ct state new accept
    iifname "{wan}" udp dport {port} meta nfproto ipv4 accept
    iifname "{wan}" udp sport 67 udp dport 68 accept
    ip protocol icmp icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state invalid drop
    meta nfproto ipv6 drop
    iifname "{wg}" ip daddr @blocked_v4 drop
    oifname "{wg}" ip saddr @blocked_v4 drop
    iifname "{wg}" ip daddr @forbidden drop
    iifname "{wg}" udp dport 53 drop
    iifname "{wg}" tcp dport 53 drop
    iifname "{wg}" oifname "{wan}" ip saddr @peers accept
    iifname "{wan}" oifname "{wg}" ip daddr @peers ct state established,related accept
  }}
}}
table ip shadowborn_nat {{
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    iifname "{wg}" oifname "{wan}" ip saddr {subnet} masquerade
  }}
}}
"#,
        dns = prefix.address,
        wg = s.interface,
        wan = s.wan_interface,
        admin = s.admin_ipv4,
        ssh = s.ssh_port,
        port = s.listen_port,
        subnet = prefix.cidr()
    ))
}
pub fn unbound(config: &crate::Config) -> Result<String> {
    config.validate()?;
    let prefix = config.prefix()?;
    let upstream = if config.addons.dnscrypt.is_some() {
        "127.0.0.1@5354"
    } else {
        "9.9.9.9@853#dns.quad9.net\n    forward-addr: 149.112.112.112@853#dns.quad9.net"
    };
    Ok(format!(
        r#"# Dedicated VPN resolver. No includes, persistent cache, remote control or logging.
server:
    interface: {address}
    access-control: 0.0.0.0/0 refuse
    access-control: {subnet} allow
    do-not-query-localhost: {deny_localhost}
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    do-daemonize: no
    username: ""
    chroot: ""
    directory: "/etc/shadowborn"
    pidfile: ""
    verbosity: 0
    use-syslog: no
    logfile: "/dev/null"
    log-queries: no
    log-replies: no
    log-servfail: no
    log-tag-queryreply: no
    statistics-interval: 0
    extended-statistics: no
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    minimal-responses: yes
    prefetch: no
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    # Local DNSSEC validation is NOT claimed; evaluate the selected upstream.
    module-config: "iterator"
{filtering}remote-control:
    control-enable: no
forward-zone:
    name: "."
    forward-tls-upstream: {tls}
    forward-first: no
    forward-addr: {upstream}
"#,
        address = prefix.address,
        subnet = prefix.cidr(),
        filtering = config.filtering.unbound_rules(),
        upstream = upstream,
        tls = if config.addons.dnscrypt.is_some() {
            "no"
        } else {
            "yes"
        },
        deny_localhost = if config.addons.dnscrypt.is_some() {
            "no"
        } else {
            "yes"
        }
    ))
}
pub fn client_template(state: &State, name: &str) -> Result<String> {
    Ok(format!("# STANDARD profile; strict kill switch is NOT installed.\n# Replace PrivateKey locally; protect this PSK-bearing template as a secret.\n# IPv6 is routed into the tunnel and dropped at the IPv4-only server.\n{}", client_config(state, name, "<DEVICE_PRIVATE_KEY>")?))
}

/// Compact, complete profile for standard file import and QR encoding.
/// The caller must protect the returned secret; it must never be printed.
pub fn client_profile(state: &State, name: &str, private: &crate::Secret) -> Result<String> {
    crate::validate_key(private.expose())?;
    client_config(state, name, private.expose())
}

fn client_config(state: &State, name: &str, private: &str) -> Result<String> {
    state.validate()?;
    let peer = state.peer(name)?;
    if peer.status != PeerStatus::Active {
        bail!("client export requires an active peer")
    }
    Ok(format!("[Interface]\nPrivateKey = {private}\nAddress = {}/32\nDNS = {}\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = {}:{}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",peer.address,state.config.prefix()?.address,state.server_public_key,peer.psk.as_ref().ok_or_else(||anyhow::anyhow!("missing PSK"))?.expose(),state.config.server.endpoint,state.config.server.listen_port))
}
pub fn bundle(state: &State) -> Result<BTreeMap<String, String>> {
    state.validate()?;
    let wg = &state.config.server.interface;
    let mut files = BTreeMap::new();
    files.insert(format!("{wg}.conf"), server_wireguard(state)?);
    files.insert("server.nft".into(), server_firewall(state)?);
    files.insert("unbound.conf".into(), unbound(&state.config)?);
    if let Some(dnscrypt) = &state.config.addons.dnscrypt {
        files.insert("dnscrypt-proxy.toml".into(), dnscrypt.render()?);
        files.insert(
            "shadowborn-dnscrypt.service".into(),
            include_str!("../../../packaging/systemd/shadowborn-dnscrypt.service").into(),
        );
    }
    files.insert(
        "99-shadowborn.conf".into(),
        "# IPv4 forwarding only; do not change unrelated sysctls.\nnet.ipv4.ip_forward = 1\n"
            .into(),
    );
    files.insert("shadowborn-firewall.service".into(),format!("[Unit]\nDescription=Shadowborn owned server firewall\nBefore=wg-quick@{wg}.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/shadowborn/server.nft\nStandardOutput=null\nStandardError=null\nLimitCORE=0\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nCapabilityBoundingSet=CAP_NET_ADMIN\n\n[Install]\nWantedBy=multi-user.target\n"));
    files.insert("shadowborn-dns.service".into(),format!("[Unit]\nDescription=Shadowborn VPN-only Unbound resolver\nRequires=wg-quick@{wg}.service\nAfter=wg-quick@{wg}.service\nBindsTo=wg-quick@{wg}.service\n\n[Service]\nType=simple\nUser=unbound\nGroup=unbound\nExecStart=/usr/sbin/unbound -d -c /etc/shadowborn/unbound.conf\nRestart=on-failure\nRestartSec=5\nStandardOutput=null\nStandardError=null\nLimitCORE=0\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_INET AF_UNIX\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n"));
    files.insert("wg-quick-shadowborn.conf".into(),"[Unit]\nRequires=shadowborn-firewall.service\nAfter=shadowborn-firewall.service\n\n[Service]\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n".into());
    if state.config.addons.dnscrypt.is_some() {
        let unit = files
            .get_mut("shadowborn-dns.service")
            .expect("DNS unit was inserted");
        *unit = unit.replacen(
            "[Unit]",
            "[Unit]\nWants=shadowborn-dnscrypt.service\nAfter=shadowborn-dnscrypt.service",
            1,
        );
    }
    Ok(files)
}
