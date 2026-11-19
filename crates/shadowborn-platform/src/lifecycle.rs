//! Fresh-server transactions. Configuration/security intent only, never activity.
use crate::{run, Store};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use shadowborn_core::{PeerStatus, State};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
const ROOT: &str = "/var/lib/shadowborn";
const JOURNAL: &str = "/var/lib/shadowborn/deployment.json";
const AUTH_PENDING: &str = "/var/lib/shadowborn/authorization.pending";
const CLI: &str = "/usr/local/bin/shadowborn";
const MAX_ARTIFACT: u64 = 4 * 1024 * 1024;
const MAX_INTENT: u64 = 32 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Artifact {
    text: String,
    mode: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    version: u32,
    transaction: String,
    interface: String,
    phase: String,
    boot_id: String,
    forwarding_before: String,
    files: BTreeMap<String, Artifact>,
    previous: Option<BTreeMap<String, Artifact>>,
    #[serde(default)]
    firewall_signature: Option<String>,
    #[serde(default)]
    wan_networks: Vec<String>,
}
fn command(program: &str, args: &[&str]) -> Result<String> {
    String::from_utf8(run(program, args, b"")?).context("invalid system tool output")
}
fn system(args: &[&str]) -> Result<()> {
    command("systemctl", args).map(|_| ())
}
fn exists(path: &str) -> bool {
    fs::symlink_metadata(path).is_ok()
}
fn parent(path: &Path) -> Result<()> {
    for dir in path.parent().context("missing parent")?.ancestors() {
        let m = fs::symlink_metadata(dir)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted installation directory"
        );
    }
    Ok(())
}
fn read(path: &str) -> Result<Option<Artifact>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("cannot read owned configuration"),
    };
    parent(Path::new(path))?;
    let m = file.metadata()?;
    let limit = if path == JOURNAL {
        MAX_INTENT
    } else {
        MAX_ARTIFACT
    };
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0 && m.len() <= limit,
        "unsafe owned file"
    );
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    ensure!(text.len() as u64 <= limit, "owned file exceeds size limit");
    Ok(Some(Artifact {
        text,
        mode: m.mode() & 0o777,
    }))
}
fn replace(path: &str, before: Option<&Artifact>, after: Option<&Artifact>) -> Result<()> {
    ensure!(
        read(path)?.as_ref() == before,
        "configuration changed; refusing overwrite"
    );
    let path = Path::new(path);
    parent(path)?;
    if let Some(after) = after {
        let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("missing parent")?)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(after.mode))?;
        temp.write_all(after.text.as_bytes())?;
        temp.as_file().sync_all()?;
        if before.is_none() {
            temp.persist_noclobber(path)
                .map_err(|_| anyhow::anyhow!("installation conflict"))?;
        } else {
            temp.persist(path)
                .map_err(|_| anyhow::anyhow!("atomic configuration update failed"))?;
        }
    } else if before.is_some() {
        fs::remove_file(path)?;
    }
    File::open(path.parent().context("missing parent")?)?.sync_all()?;
    Ok(())
}
fn journal() -> Result<Option<Deployment>> {
    let Some(data) = read(JOURNAL)? else {
        return Ok(None);
    };
    ensure!(data.mode == 0o600, "deployment state must be private");
    let value: Deployment = serde_json::from_str(&data.text)
        .map_err(|_| anyhow::anyhow!("invalid deployment intent"))?;
    ensure!(
        value.version == 1 && shadowborn_core::valid_interface(&value.interface),
        "invalid deployment schema/interface"
    );
    ensure!(
        value.transaction.len() == 32 && value.transaction.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid deployment transaction"
    );
    let allowed = paths(&value.interface);
    for file in value
        .files
        .keys()
        .chain(value.previous.iter().flat_map(|p| p.keys()))
    {
        ensure!(allowed.contains(file), "invalid owned path in intent");
    }
    Ok(Some(value))
}
fn save(value: &Deployment) -> Result<()> {
    let text = serde_json::to_string(value)?;
    ensure!(
        text.len() as u64 <= MAX_INTENT
            && value
                .files
                .values()
                .all(|f| f.text.len() as u64 <= MAX_ARTIFACT),
        "rendered deployment exceeds file limits"
    );
    replace(
        JOURNAL,
        read(JOURNAL)?.as_ref(),
        Some(&Artifact { text, mode: 0o600 }),
    )
}
fn service(body: &str, execution: &str) -> String {
    format!("[Unit]\n{body}\n[Service]\nType=oneshot\n{execution}\nStandardOutput=null\nStandardError=null\nLimitCORE=0\nNoNewPrivileges=yes\nProtectHome=yes\nPrivateTmp=yes\n\n[Install]\nWantedBy=multi-user.target\n")
}
fn files(
    state: &State,
    transaction: &str,
    wan_networks: &[String],
) -> Result<BTreeMap<String, Artifact>> {
    let wg = &state.config.server.interface;
    let mut result = BTreeMap::new();
    for (name, text) in shadowborn_core::bundle(state)? {
        let (path, mode) = if name == format!("{wg}.conf") {
            (format!("/etc/wireguard/{name}"), 0o600)
        } else if name == "wg-quick-shadowborn.conf" {
            (
                format!("/etc/systemd/system/wg-quick@{wg}.service.d/shadowborn.conf"),
                0o644,
            )
        } else if name.ends_with(".service") {
            (format!("/etc/systemd/system/{name}"), 0o644)
        } else if name == "unbound.conf" {
            ("/etc/unbound/shadowborn.conf".into(), 0o644)
        } else if name == "99-shadowborn.conf" {
            // Managed forwarding starts only after the owned firewall loads.
            // The sysctl.d file is for the manually activated review bundle.
            continue;
        } else {
            (format!("/etc/shadowborn/{name}"), 0o644)
        };
        result.insert(path, Artifact { text, mode });
    }
    let policy = result
        .get_mut("/etc/shadowborn/server.nft")
        .context("missing firewall")?;
    if !wan_networks.is_empty() {
        for network in wan_networks {
            shadowborn_core::V4Prefix::parse(network)?;
        }
        let marker = format!("iifname \"{wg}\" ip daddr @blocked_v4 drop");
        let local = format!(
            "iifname \"{wg}\" ip daddr {{ {} }} drop",
            wan_networks.join(", ")
        );
        policy.text = policy
            .text
            .replace(&marker, &format!("{local}\n    {marker}"));
    }
    for table in ["inet shadowborn", "ip shadowborn_nat"] {
        let head = format!("table {table} {{");
        policy.text = policy.text.replace(
            &head,
            &format!("{head}\n  comment \"shadowborn-{transaction}\""),
        );
    }
    let firewall = result
        .get_mut("/etc/systemd/system/shadowborn-firewall.service")
        .context("missing firewall unit")?;
    firewall.text = firewall
        .text
        .replace(
            "[Unit]",
            "[Unit]\nRequires=shadowborn-recovery.service\nAfter=shadowborn-recovery.service",
        )
        .replace(
            "ExecStart=/usr/sbin/nft -f /etc/shadowborn/server.nft",
            &format!("ReadWritePaths={ROOT}\nExecStart={CLI} deployment firewall-load"),
        );
    let recovery = service(
        "Description=Shadowborn interrupted deployment recovery\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target shadowborn-reconcile.service",
        &format!("ExecStart={CLI} deployment recover --boot-only"),
    );
    let reconcile = service(
        &format!("Description=Shadowborn current authorization reconciliation\nRequires=shadowborn-recovery.service\nAfter=shadowborn-recovery.service\nBefore=shadowborn-firewall.service wg-quick@{wg}.service"),
        &format!("ExecStart={CLI} deployment reconcile"),
    );
    let activate = service(
        "Description=Shadowborn bounded activation worker",
        &format!("TimeoutStartSec=60\nKillMode=control-group\nExecStart={CLI} deployment activate"),
    );
    for (name, text) in [
        ("recovery", recovery),
        ("reconcile", reconcile),
        ("activate", activate),
    ] {
        result.insert(
            format!("/etc/systemd/system/shadowborn-{name}.service"),
            Artifact { text, mode: 0o644 },
        );
    }
    // A killed peer command may have renamed state.json before updating the
    // kernel. PID 1 independently retries reconciliation from canonical state.
    result.insert("/etc/systemd/system/shadowborn-authorization.path".into(), Artifact {
        text: format!("[Unit]\nDescription=Reconcile current Shadowborn authorization\nAfter=shadowborn-recovery.service\n\n[Path]\nPathExists={AUTH_PENDING}\nUnit=shadowborn-reconcile.service\n\n[Install]\nWantedBy=multi-user.target\n"),
        mode: 0o644,
    });
    let dropin = result
        .get_mut(&format!(
            "/etc/systemd/system/wg-quick@{wg}.service.d/shadowborn.conf"
        ))
        .context("WG dependency missing")?;
    dropin.text = dropin.text.replacen(
        "[Unit]",
        "[Unit]\nRequires=shadowborn-reconcile.service\nAfter=shadowborn-reconcile.service",
        1,
    );
    Ok(result)
}
fn paths(wg: &str) -> Vec<String> {
    let mut paths = vec![
        format!("/etc/wireguard/{wg}.conf"),
        format!("/etc/systemd/system/wg-quick@{wg}.service.d/shadowborn.conf"),
        "/etc/sysctl.d/99-shadowborn.conf".into(),
        "/etc/unbound/shadowborn.conf".into(),
        "/etc/systemd/system/shadowborn-authorization.path".into(),
    ];
    paths.extend(["server.nft", "dnscrypt-proxy.toml"].map(|n| format!("/etc/shadowborn/{n}")));
    paths.extend(
        [
            "firewall",
            "dns",
            "dnscrypt",
            "recovery",
            "reconcile",
            "activate",
        ]
        .map(|n| format!("/etc/systemd/system/shadowborn-{n}.service")),
    );
    paths
}
pub fn host(state_path: &Path) -> Result<()> {
    crate::require_root()?;
    ensure!(
        state_path == Path::new(ROOT),
        "live operations require canonical /var/lib/shadowborn state"
    );
    ensure!(
        fs::read_to_string("/proc/1/comm")?.trim() == "systemd",
        "live operations require systemd as PID 1"
    );
    let os = fs::read_to_string("/etc/os-release")?;
    ensure!(
        os.lines().any(|l| matches!(
            l,
            "ID=debian" | "ID=ubuntu" | "ID=\"debian\"" | "ID=\"ubuntu\""
        )),
        "live server supports Debian/Ubuntu only; workstation refused"
    );
    ensure!(
        !exists("/.dockerenv") && !exists("/run/.containerenv"),
        "container activation unsupported"
    );
    parent(Path::new(CLI))?;
    let m = fs::symlink_metadata(CLI)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "install a root-owned CLI before live activation"
    );
    ensure!(
        fs::read(std::env::current_exe()?)? == fs::read(CLI)?,
        "running CLI differs from recovery executable"
    );
    Ok(())
}
fn directories(wg: &str) -> Result<()> {
    for (path, mode) in [
        ("/etc/shadowborn".to_owned(), 0o755),
        ("/etc/wireguard".to_owned(), 0o700),
        (
            format!("/etc/systemd/system/wg-quick@{wg}.service.d"),
            0o755,
        ),
    ] {
        if !exists(&path) {
            parent(Path::new(&path))?;
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        }
        parent(&Path::new(&path).join("placeholder"))?;
    }
    let m = fs::metadata("/etc/wireguard")?;
    ensure!(m.mode() & 0o077 == 0, "/etc/wireguard must be 0700");
    Ok(())
}
fn validate_files(state: &State) -> Result<()> {
    run(
        "nft",
        &["-c", "-f", "/dev/stdin"],
        shadowborn_core::server_firewall(state)?.as_bytes(),
    )?;
    command("wg-quick", &["strip", &state.config.server.interface])?;
    command("unbound-checkconf", &["/etc/unbound/shadowborn.conf"])?;
    Ok(())
}
fn ensure_files(d: &Deployment) -> Result<()> {
    for (path, file) in &d.files {
        ensure!(
            read(path)?.as_ref() == Some(file),
            "owned configuration drift detected"
        );
    }
    Ok(())
}
fn wan_networks(wan: &str) -> Result<Vec<String>> {
    let rows: serde_json::Value = serde_json::from_str(&command(
        "ip",
        &["-j", "-4", "route", "show", "dev", wan, "scope", "link"],
    )?)?;
    let mut prefixes = Vec::new();
    for row in rows.as_array().context("invalid WAN link routes")? {
        if let Some(dst) = row["dst"].as_str().filter(|s| *s != "default") {
            let cidr = if dst.contains('/') {
                dst.to_owned()
            } else {
                format!("{dst}/32")
            };
            let p = shadowborn_core::V4Prefix::parse(&cidr)?;
            ensure!(p.bits > 0, "ambiguous on-link route");
            // A /32 route to the default router may be contained in a wider link prefix.
            prefixes.push(p);
        }
    }
    prefixes.sort_by_key(|p| p.bits);
    let mut merged: Vec<shadowborn_core::V4Prefix> = Vec::new();
    for p in prefixes {
        if !merged.iter().any(|net| net.contains(p.address)) {
            merged.push(p);
        }
    }
    Ok(merged.into_iter().map(|p| p.cidr()).collect())
}
pub fn check_host(state_path: &Path, state: &State) -> Result<()> {
    host(state_path)?;
    preflight(state)
}
fn preflight(state: &State) -> Result<()> {
    ensure!(
        journal()?.is_none(),
        "deployment already exists; use deployment status/recover"
    );
    for path in paths(&state.config.server.interface) {
        ensure!(
            !exists(&path),
            "existing configuration is not owned by this deployment"
        );
    }
    crate::require_offline(&state.config)?;
    for procfile in ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"] {
        if let Ok(names) = fs::read_to_string(procfile) {
            ensure!(
                names.trim().is_empty(),
                "legacy iptables overlap requires review"
            );
        }
    }
    let nft: serde_json::Value =
        serde_json::from_str(&command("nft", &["-j", "list", "ruleset"])?)?;
    for row in nft["nftables"].as_array().context("invalid nft ruleset")? {
        ensure!(
            row["chain"]["hook"].is_null() && row["flowtable"].is_null(),
            "existing firewall hooks overlap gateway policy"
        );
        ensure!(
            !matches!(
                (
                    row["table"]["family"].as_str(),
                    row["table"]["name"].as_str()
                ),
                (Some("inet"), Some("shadowborn")) | (Some("ip"), Some("shadowborn_nat"))
            ),
            "firewall table name is already owned"
        );
    }
    for manager in [
        "nftables.service",
        "ufw.service",
        "firewalld.service",
        "docker.service",
    ] {
        let active = command(
            "systemctl",
            &["show", "-p", "ActiveState", "--value", manager],
        )?;
        let enabled = command(
            "systemctl",
            &["show", "-p", "UnitFileState", "--value", manager],
        )?;
        ensure!(
            !matches!(active.trim(), "active" | "activating")
                && !matches!(enabled.trim(), "enabled" | "enabled-runtime"),
            "conflicting firewall/container manager is active or enabled"
        );
    }
    let route = command("ip", &["-j", "-4", "route", "show", "default"])?;
    let routes: serde_json::Value = serde_json::from_str(&route)?;
    let routes = routes.as_array().context("invalid route result")?;
    ensure!(
        routes.len() == 1 && routes[0]["dev"].as_str() == Some(&state.config.server.wan_interface),
        "WAN must match a single IPv4 default route"
    );
    let addresses: serde_json::Value =
        serde_json::from_str(&command("ip", &["-j", "-4", "address", "show"])?)?;
    let prefix = state.config.prefix()?;
    for interface in addresses.as_array().context("invalid addresses")? {
        if let Some(values) = interface["addr_info"].as_array() {
            for a in values {
                if let (Some(ip), Some(bits)) = (a["local"].as_str(), a["prefixlen"].as_u64()) {
                    let p = shadowborn_core::V4Prefix::parse(&format!("{ip}/{bits}"))?;
                    ensure!(
                        !p.contains(prefix.address) && !prefix.contains(p.address),
                        "tunnel prefix overlaps host network"
                    );
                }
            }
        }
    }
    let routes: serde_json::Value = serde_json::from_str(&command(
        "ip",
        &["-j", "-4", "route", "show", "table", "all"],
    )?)?;
    for route in routes.as_array().context("invalid route inventory")? {
        if let Some(dst) = route["dst"].as_str().filter(|dst| *dst != "default") {
            let cidr = if dst.contains('/') {
                dst.to_owned()
            } else {
                format!("{dst}/32")
            };
            let other = shadowborn_core::V4Prefix::parse(&cidr)?;
            ensure!(
                !other.contains(prefix.address) && !prefix.contains(other.address),
                "tunnel prefix overlaps an existing route"
            );
        }
    }
    if let Ok(connection) = std::env::var("SSH_CONNECTION") {
        let parts: Vec<_> = connection.split_whitespace().collect();
        ensure!(
            parts.len() == 4
                && parts[3].parse::<u16>().ok() == Some(state.config.server.ssh_port)
                && parts[0]
                    .parse()
                    .is_ok_and(|ip| shadowborn_core::V4Prefix::parse(
                        &state.config.server.admin_ipv4
                    )
                    .is_ok_and(|net| net.contains(ip))),
            "current SSH connection is outside the proposed allowlist/port"
        );
    }
    // Bound sockets are configuration/current state, never saved in intent or output.
    let sockets = command("ss", &["-H", "-lntu"])?;
    let mut ssh_listening = false;
    let dns = format!("{}:53", prefix.address);
    for line in sockets.lines() {
        let bind = line.split_whitespace().nth(4).unwrap_or("");
        if line.starts_with("tcp")
            && bind.rsplit_once(':').is_some_and(|(ip, port)| {
                port.parse::<u16>() == Ok(state.config.server.ssh_port)
                    && (ip == "*"
                        || ip
                            .parse::<std::net::Ipv4Addr>()
                            .is_ok_and(|ip| !ip.is_loopback()))
            })
        {
            ssh_listening = true;
        }
        ensure!(
            !["0.0.0.0:53", "*:53", "[::]:53", dns.as_str()].contains(&bind),
            "VPN DNS port conflicts with an existing listener"
        );
        ensure!(
            !(state.config.addons.dnscrypt.is_some() && bind.ends_with(":5354")),
            "proxy port already bound"
        );
        ensure!(
            !(line.starts_with("udp")
                && bind.ends_with(&format!(":{}", state.config.server.listen_port))),
            "WireGuard UDP port already bound"
        );
    }
    ensure!(
        ssh_listening,
        "configured SSH port has no non-loopback IPv4 listener"
    );
    let instance = format!("wg-quick@{}.service", state.config.server.interface);
    let enabled = command(
        "systemctl",
        &["show", "-p", "UnitFileState", "--value", &instance],
    )?;
    ensure!(
        enabled.trim() == "disabled",
        "fresh installation requires an unused disabled wg-quick instance"
    );
    ensure!(
        state.peers.iter().any(|p| p.status == PeerStatus::Active),
        "enroll a test peer before activation"
    );
    run(
        "nft",
        &["-c", "-f", "/dev/stdin"],
        shadowborn_core::server_firewall(state)?.as_bytes(),
    )?;
    Ok(())
}
pub fn apply(state_path: &Path, console: bool) -> Result<String> {
    host(state_path)?;
    ensure!(
        console,
        "--console-verified is required before a fresh network transaction"
    );
    let transaction;
    {
        let store = Store::open(state_path, false)?;
        let state = store.load()?;
        preflight(&state)?;
        directories(&state.config.server.interface)?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        transaction = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let wan_networks = wan_networks(&state.config.server.wan_interface)?;
        let d = Deployment {
            version: 1,
            transaction: transaction.clone(),
            interface: state.config.server.interface.clone(),
            phase: "pending".into(),
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
            forwarding_before: fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?
                .trim()
                .into(),
            files: files(&state, &transaction, &wan_networks)?,
            wan_networks,
            previous: None,
            firewall_signature: None,
        };
        save(&d)?;
        // No network mutation occurs before durable recovery + independent timer.
        const RECOVERY: &str = "/etc/systemd/system/shadowborn-recovery.service";
        replace(RECOVERY, None, d.files.get(RECOVERY))?;
        system(&["daemon-reload"])?;
        system(&["enable", "shadowborn-recovery.service"])?;
        command(
            "systemd-run",
            &[
                "--quiet",
                "--collect",
                &format!("--unit=shadowborn-rollback-{transaction}"),
                "--on-active=120s",
                "--timer-property=AccuracySec=1s",
                "--property=StandardOutput=null",
                "--property=StandardError=null",
                "--property=Restart=on-failure",
                "--property=RestartSec=2s",
                CLI,
                "deployment",
                "recover",
                "--transaction",
                &transaction,
            ],
        )?;
        for (path, file) in &d.files {
            if path != RECOVERY {
                replace(path, None, Some(file))?;
            }
        }
        system(&["daemon-reload"])?;
        validate_files(&state)?;
    }
    if system(&["start", "shadowborn-activate.service"]).is_err() {
        let _ = recover(state_path, false, None);
        bail!("activation failed; rollback requested, inspect deployment status");
    }
    Ok(transaction)
}
pub fn activate(state_path: &Path) -> Result<()> {
    host(state_path)?;
    let interface;
    {
        let store = Store::open(state_path, false)?;
        let state = store.load()?;
        let d = journal()?.context("no pending activation")?;
        ensure!(d.phase == "pending", "activation is not pending");
        ensure_files(&d)?;
        validate_files(&state)?;
        interface = d.interface;
    }
    // WG dependencies invoke reconcile separately: never hold its lock here.
    system(&["start", "shadowborn-firewall.service"])?;
    system(&["start", &format!("wg-quick@{interface}.service")])?;
    system(&["start", "shadowborn-dns.service"])?;
    health(&interface)
}
fn health(interface: &str) -> Result<()> {
    for unit in [
        format!("wg-quick@{interface}.service"),
        "shadowborn-firewall.service".into(),
        "shadowborn-dns.service".into(),
    ] {
        system(&["is-active", "--quiet", &unit])?;
    }
    command("wg", &["show", interface, "public-key"])?;
    let state = Store::decode(&crate::read_secret(&Path::new(ROOT).join("state.json"))?)?;
    let dns_bind = format!("{}:53", state.config.prefix()?.address);
    for _ in 0..12 {
        let sockets = command("ss", &["-H", "-lntu"])?;
        let bound = |transport: &str| {
            sockets.lines().any(|line| {
                line.starts_with(transport)
                    && line.split_whitespace().nth(4) == Some(dns_bind.as_str())
            })
        };
        if bound("udp") && bound("tcp") {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    bail!("resolver did not bind both tunnel-side DNS sockets")
}
pub fn commit(
    state_path: &Path,
    transaction: &str,
    peer: &str,
    egress_verified: bool,
) -> Result<()> {
    host(state_path)?;
    ensure!(
        egress_verified,
        "--egress-verified required after testing Internet and DNS from the enrolled device"
    );
    let store = Store::open(state_path, false)?;
    let state = store.load()?;
    let mut d = journal()?.context("no deployment")?;
    ensure!(
        d.phase == "pending" && d.transaction == transaction,
        "pending transaction does not match"
    );
    ensure_files(&d)?;
    health(&d.interface)?;
    let peer = state.peer(peer)?;
    ensure!(
        peer.status == PeerStatus::Active,
        "test peer must be active"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let handshakes = command("wg", &["show", &d.interface, "latest-handshakes"])?;
    ensure!(
        handshakes.lines().any(|line| {
            let mut parts = line.split_whitespace();
            parts.next() == Some(&peer.public_key)
                && parts
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_some_and(|t| t > 0 && t <= now && now - t < 180)
        }),
        "recent handshake from the opted-in test peer required; no values retained"
    );
    checked_tables(&d)?.context("owned runtime firewall missing")?;
    system(&["enable", "--now", "shadowborn-authorization.path"])?;
    // Enable first. Pending boot recovery still rolls back if commit is interrupted.
    for unit in [
        "shadowborn-firewall.service".to_owned(),
        format!("wg-quick@{}.service", d.interface),
        "shadowborn-dns.service".into(),
    ] {
        system(&["enable", &unit])?;
    }
    d.phase = "committed".into();
    d.boot_id.clear();
    save(&d)?;
    let _ = system(&[
        "stop",
        &format!("shadowborn-rollback-{}.timer", d.transaction),
    ]);
    Ok(())
}
pub fn status(state_path: &Path) -> Result<serde_json::Value> {
    crate::require_root()?;
    ensure!(
        state_path == Path::new(ROOT),
        "deployment status uses canonical state"
    );
    let d = journal()?;
    Ok(match d {
        None => serde_json::json!({"deployment":"absent"}),
        Some(d) => {
            serde_json::json!({"deployment":d.phase,"transaction":d.transaction,"reconciliation_pending":d.previous.is_some() || exists(AUTH_PENDING),"activity_history":false})
        }
    })
}
fn fail_closed(state: &State) {
    let wg = &state.config.server.interface;
    if command("wg", &["show", wg, "public-key"])
        .ok()
        .as_deref()
        .map(str::trim)
        == Some(state.server_public_key.as_str())
    {
        let _ = command("ip", &["link", "set", "dev", wg, "down"]);
    }
}
fn reconcile_locked(store: &Store, state: &State) -> Result<()> {
    let mut d = journal()?.context("gateway is not deployed")?;
    ensure!(
        matches!(d.phase.as_str(), "pending" | "committed"),
        "deployment is not reconcilable"
    );
    ensure!(
        d.interface == state.config.server.interface,
        "deployed interface changed"
    );
    let desired = files(state, &d.transaction, &d.wan_networks)?;
    if d.previous.is_none() {
        ensure_files(&d)?;
        d.previous = Some(d.files.clone());
        d.files = desired;
        save(&d)?;
    } else {
        ensure!(
            d.files == desired,
            "pending reconciliation conflicts with canonical authorization"
        );
    }
    let old = d
        .previous
        .as_ref()
        .context("missing reconciliation baseline")?;
    ensure!(
        old.keys().eq(d.files.keys()),
        "live changes cannot add/remove deployment components"
    );
    for (path, next) in &d.files {
        let current = read(path)?;
        ensure!(
            current.as_ref() == old.get(path) || current.as_ref() == Some(next),
            "owned configuration changed during reconciliation"
        );
        if current.as_ref() != Some(next) {
            replace(path, current.as_ref(), Some(next))?;
        }
    }
    validate_files(state)?;
    // Canonical state was durably saved before this function. WG startup always
    // passes through this same reconciliation, so a stale export cannot revive a peer.
    let wg = &state.config.server.interface;
    if Path::new("/sys/class/net").join(wg).exists() {
        ensure!(
            command("wg", &["show", wg, "public-key"])?.trim() == state.server_public_key,
            "live interface ownership conflict"
        );
        let quick = shadowborn_core::server_wireguard(state)?;
        let sync = quick
            .lines()
            .filter(|l| !l.starts_with("Address =") && !l.starts_with("SaveConfig ="))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        run("wg", &["syncconf", wg, "/dev/stdin"], sync.as_bytes())?;
    }
    load_firewall(&mut d)?;
    d.previous = None;
    save(&d)?;
    if let Some(marker) = read(AUTH_PENDING)? {
        ensure!(
            marker.mode == 0o600 && marker.text.is_empty(),
            "invalid authorization marker"
        );
        replace(AUTH_PENDING, Some(&marker), None)?;
    }
    // Keep the held authorization lock until all derived configuration agrees.
    let _ = store;
    Ok(())
}
const TABLES: [(&str, &str); 2] = [("inet", "shadowborn"), ("ip", "shadowborn_nat")];

// Hash only the static rules of the two tables. Never persist a live ruleset.
fn table_signature(d: &Deployment) -> Result<Option<String>> {
    let tables: serde_json::Value =
        serde_json::from_str(&command("nft", &["-j", "list", "tables"])?)?;
    let listed = tables["nftables"]
        .as_array()
        .context("invalid table inventory")?;
    let mut snapshot = String::new();
    let mut count = 0;
    for (family, table) in TABLES {
        if listed
            .iter()
            .any(|row| row["table"]["family"] == family && row["table"]["name"] == table)
        {
            let text = command("nft", &["-s", "list", "table", family, table])?;
            let owner = format!("comment \"shadowborn-{}\"", d.transaction);
            ensure!(
                text.lines().any(|line| line.trim() == owner),
                "live firewall ownership conflict"
            );
            snapshot.push_str(&text);
            count += 1;
        }
    }
    if count == 0 {
        return Ok(None);
    }
    ensure!(
        count == TABLES.len(),
        "partial runtime firewall; inspect from console"
    );
    let digest = String::from_utf8(run("sha256sum", &[], snapshot.as_bytes())?)?;
    Ok(Some(
        digest
            .split_whitespace()
            .next()
            .context("missing fingerprint")?
            .to_owned(),
    ))
}
fn checked_tables(d: &Deployment) -> Result<Option<String>> {
    let current = table_signature(d)?;
    if let (Some(expected), Some(actual)) = (&d.firewall_signature, &current) {
        ensure!(
            expected == actual,
            "live firewall differs from the installed policy"
        );
    }
    Ok(current)
}
fn load_firewall(d: &mut Deployment) -> Result<()> {
    let existing = checked_tables(d)?;
    let policy = &d
        .files
        .get("/etc/shadowborn/server.nft")
        .context("missing firewall policy")?
        .text;
    let batch = if existing.is_none() {
        policy.replace("add table ", "create table ")
    } else {
        policy.clone()
    };
    run("nft", &["-c", "-f", "-"], batch.as_bytes())?;
    // A crash between the kernel commit and fsync must allow a retry. Each table
    // still carries its private transaction's ownership marker.
    d.firewall_signature = None;
    save(d)?;
    run("nft", &["-f", "-"], batch.as_bytes())?;
    d.firewall_signature = table_signature(d)?;
    ensure!(
        d.firewall_signature.is_some(),
        "owned firewall missing after load"
    );
    save(d)
}
pub fn firewall_load(state_path: &Path) -> Result<()> {
    host(state_path)?;
    let _store = Store::open(state_path, false)?;
    let mut d = journal()?.context("missing deployment")?;
    ensure!(
        matches!(d.phase.as_str(), "pending" | "committed"),
        "gateway is rolling back"
    );
    ensure_files(&d)?;
    load_firewall(&mut d)?;
    if fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "1" {
        command("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"])?;
    }
    Ok(())
}
pub fn reconcile(state_path: &Path) -> Result<()> {
    host(state_path)?;
    let store = Store::wait(state_path)?;
    let state = store.load()?;
    let result = reconcile_locked(&store, &state);
    if result.is_err() {
        fail_closed(&state);
    }
    result
}
/// Validate live ownership before generating any enrollment artifacts.
pub fn peer_preflight(state_path: &Path, state: &State, restricting: bool) -> Result<bool> {
    if state_path != Path::new(ROOT) || journal()?.is_none() {
        crate::require_offline(&state.config)?;
        return Ok(false);
    }
    host(state_path)?;
    let d = journal()?.context("missing deployment")?;
    if restricting && d.phase == "committed" {
        // Never leave a credential authorized just because unrelated files drifted.
        // A failed reconciliation closes the owned link after state is durable.
        return Ok(true);
    }
    ensure!(
        d.phase == "committed" && d.previous.is_none(),
        "commit/reconcile deployment before changing peers"
    );
    ensure_files(&d)?;
    if Path::new("/sys/class/net").join(&d.interface).exists() {
        ensure!(
            command("wg", &["show", &d.interface, "public-key"])?.trim() == state.server_public_key,
            "live interface ownership conflict"
        );
    }
    checked_tables(&d)?.context("deployed firewall absent; reconcile before changing peers")?;
    Ok(true)
}
/// Arm a level-triggered recovery job under the same lock as the canonical rename.
pub fn prepare_peer_change(_lock: &Store) -> Result<()> {
    match read(AUTH_PENDING)? {
        None => crate::write_new_secret(Path::new(AUTH_PENDING), b""),
        Some(m) => {
            ensure!(
                m.mode == 0o600 && m.text.is_empty(),
                "invalid authorization marker"
            );
            Ok(())
        }
    }
}
/// Called AFTER canonical state is saved. Any failure closes the owned tunnel.
pub fn peers_changed(store: &Store, state: &State) -> Result<()> {
    let result = reconcile_locked(store, state);
    if result.is_err() {
        fail_closed(state);
    }
    result.context("authorization is durable but reconciliation failed; owned tunnel was closed; run deployment reconcile")
}
/// Confirmed teardown keeps canonical secrets and revocations available for recovery.
pub fn remove(state_path: &Path, console: bool) -> Result<()> {
    host(state_path)?;
    ensure!(console, "verify an independent working console first");
    {
        let _store = Store::open(state_path, false)?;
        let Some(mut d) = journal()? else {
            return Ok(());
        };
        if d.phase == "committed" {
            ensure!(
                d.previous.is_none() && !exists(AUTH_PENDING),
                "finish pending peer reconciliation first"
            );
            ensure_files(&d)?;
            checked_tables(&d)?;
            d.phase = "reverting".into();
            save(&d)?;
        }
    }
    recover(state_path, false, None)
}

pub fn runtime_status(state_path: &Path) -> Result<serde_json::Value> {
    let mut result = serde_json::json!({"schema_version":1,"deployment":"UNKNOWN","tunnel":"UNKNOWN",
        "firewall":"UNKNOWN","dns_service":"UNKNOWN","egress":"NOT_TESTED","dns_privacy":"UNKNOWN",
        "activity_logging_runtime":"UNKNOWN","strict_client":"CHECK_ON_CLIENT"});
    if state_path != Path::new(ROOT) || crate::require_root().is_err() {
        return Ok(result);
    }
    let Some(d) = journal()? else {
        result["deployment"] = "absent".into();
        return Ok(result);
    };
    let state = Store::decode(&crate::read_secret(&state_path.join("state.json"))?)?;
    result["deployment"] = d.phase.clone().into();
    result["configuration"] = if ensure_files(&d).is_ok() {
        "MATCH"
    } else {
        "DRIFT_OR_UNAVAILABLE"
    }
    .into();
    let live_key = command("wg", &["show", &d.interface, "public-key"]);
    let wg_up = fs::read_to_string(format!("/sys/class/net/{}/flags", d.interface))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & 1 != 0);
    result["tunnel"] = if wg_up && live_key.is_ok_and(|k| k.trim() == state.server_public_key) {
        "UP"
    } else {
        "DOWN_OR_UNAVAILABLE"
    }
    .into();
    result["firewall"] = match checked_tables(&d) {
        Ok(Some(_)) if d.firewall_signature.is_some() => "MATCH",
        Ok(None) => "ABSENT",
        _ => "DRIFT_OR_UNAVAILABLE",
    }
    .into();
    result["dns_service"] = command(
        "systemctl",
        &[
            "show",
            "-p",
            "ActiveState",
            "--value",
            "shadowborn-dns.service",
        ],
    )
    .map_or_else(|_| "UNKNOWN".into(), |s| s.trim().into());
    Ok(result)
}

pub fn recover(state_path: &Path, boot_only: bool, transaction: Option<&str>) -> Result<()> {
    host(state_path)?;
    let store = Store::wait(state_path)?;
    let Some(mut d) = journal()? else {
        return Ok(());
    };
    if transaction.is_some_and(|id| id != d.transaction) || d.phase == "committed" {
        return Ok(());
    }
    if boot_only && d.boot_id == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() {
        return Ok(());
    }
    let state = store.load()?;
    for (path, after) in &d.files {
        let current = read(path)?;
        if current.is_some() && current.as_ref() != Some(after) {
            fail_closed(&state);
            d.phase = "conflict".into();
            save(&d)?;
            bail!("rollback conflict: administrator file changes preserved; owned tunnel closed");
        }
    }
    d.phase = "reverting".into();
    save(&d)?;
    // Nonblocking stop avoids a dependency cycle when recovery runs during boot.
    let _ = system(&["stop", "--no-block", "shadowborn-activate.service"]);
    for unit in [
        "shadowborn-dns.service".to_owned(),
        "shadowborn-dnscrypt.service".into(),
        format!("wg-quick@{}.service", d.interface),
        "shadowborn-firewall.service".into(),
        "shadowborn-authorization.path".into(),
    ] {
        if unit.starts_with("shadowborn-")
            && !d.files.contains_key(&format!("/etc/systemd/system/{unit}"))
        {
            continue;
        }
        let _ = system(&["stop", "--no-block", &unit]);
        let _ = system(&["disable", &unit]);
    }
    fail_closed(&state);
    if command("wg", &["show", &d.interface, "public-key"])
        .ok()
        .as_deref()
        .map(str::trim)
        == Some(state.server_public_key.as_str())
    {
        command("ip", &["link", "delete", "dev", &d.interface])?;
    }
    if checked_tables(&d)?.is_some() {
        run(
            "nft",
            &["-f", "-"],
            b"delete table inet shadowborn\ndelete table ip shadowborn_nat\n",
        )?;
    }
    let forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?
        .trim()
        .to_owned();
    ensure!(
        matches!(d.forwarding_before.as_str(), "0" | "1"),
        "invalid forwarding baseline"
    );
    if forward == "1" {
        command(
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv4.ip_forward={}", d.forwarding_before),
            ],
        )?;
    } else {
        ensure!(
            forward == d.forwarding_before,
            "forwarding rollback conflict"
        );
    }
    let _ = system(&["disable", "shadowborn-recovery.service"]);
    for (path, after) in d.files.iter().rev() {
        if let Some(current) = read(path)? {
            ensure!(&current == after, "rollback file conflict");
            replace(path, Some(after), None)?;
        }
    }
    system(&["daemon-reload"])?;
    // No historical deployment ledger: successful rollback removes the intent.
    replace(JOURNAL, read(JOURNAL)?.as_ref(), None)?;
    let _ = system(&[
        "stop",
        "--no-block",
        &format!("shadowborn-rollback-{}.timer", d.transaction),
    ]);
    Ok(())
}
