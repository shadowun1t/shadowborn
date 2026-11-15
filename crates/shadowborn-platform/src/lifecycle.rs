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
const CLI: &str = "/usr/local/bin/shadowborn";
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
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 4 * 1024 * 1024,
        "unsafe owned file"
    );
    let mut text = String::new();
    file.take(4 * 1024 * 1024 + 1).read_to_string(&mut text)?;
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
    replace(
        JOURNAL,
        read(JOURNAL)?.as_ref(),
        Some(&Artifact {
            text: serde_json::to_string(value)?,
            mode: 0o600,
        }),
    )
}
fn service(body: &str) -> String {
    format!("[Unit]\n{body}\n[Service]\nType=oneshot\nStandardOutput=null\nStandardError=null\nLimitCORE=0\nNoNewPrivileges=yes\nProtectHome=yes\nPrivateTmp=yes\n\n[Install]\nWantedBy=multi-user.target\n")
}
fn files(state: &State) -> Result<BTreeMap<String, Artifact>> {
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
        } else if name == "99-shadowborn.conf" {
            (format!("/etc/sysctl.d/{name}"), 0o644)
        } else {
            (format!("/etc/shadowborn/{name}"), 0o644)
        };
        result.insert(path, Artifact { text, mode });
    }
    let recovery=service("Description=Shadowborn interrupted deployment recovery\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target shadowborn-reconcile.service").replace("Type=oneshot",&format!("Type=oneshot\nExecStart={CLI} deployment recover --boot-only"));
    let reconcile=service(&format!("Description=Shadowborn current authorization reconciliation\nRequires=shadowborn-recovery.service\nAfter=shadowborn-recovery.service\nBefore=shadowborn-firewall.service wg-quick@{wg}.service")).replace("Type=oneshot",&format!("Type=oneshot\nExecStart={CLI} deployment reconcile"));
    let activate=service("Description=Shadowborn bounded activation worker").replace("Type=oneshot",&format!("Type=oneshot\nTimeoutStartSec=60\nKillMode=control-group\nExecStart={CLI} deployment activate"));
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
    ];
    paths.extend(
        ["server.nft", "unbound.conf", "dnscrypt-proxy.toml"]
            .map(|n| format!("/etc/shadowborn/{n}")),
    );
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
    command("unbound-checkconf", &["/etc/shadowborn/unbound.conf"])?;
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
    let nft = command("nft", &["list", "ruleset"])?;
    ensure!(
        nft.trim().is_empty(),
        "fresh activation requires no existing nft ruleset; firewall overlap refused"
    );
    for manager in ["ufw.service", "firewalld.service", "docker.service"] {
        ensure!(
            system(&["is-active", "--quiet", manager]).is_err(),
            "conflicting firewall/container manager is active"
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
    // Bound sockets are configuration/current state, never saved in intent or output.
    let sockets = command("ss", &["-H", "-lntu"])?;
    let dns = format!("{}:53", prefix.address);
    for line in sockets.lines() {
        let bind = line.split_whitespace().nth(4).unwrap_or("");
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
            files: files(&state)?,
            previous: None,
        };
        save(&d)?;
        // No network mutation occurs before durable recovery + independent timer.
        for (path, file) in &d.files {
            replace(path, None, Some(file))?;
        }
        system(&["daemon-reload"])?;
        system(&["enable", "shadowborn-recovery.service"])?;
        command(
            "systemd-run",
            &[
                "--quiet",
                "--unit=shadowborn-rollback",
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
    command("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"])?;
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
    Ok(())
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
    let _ = system(&["stop", "shadowborn-rollback.timer"]);
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
            serde_json::json!({"deployment":d.phase,"transaction":d.transaction,"reconciliation_pending":d.previous.is_some(),"activity_history":false})
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
    let desired = files(state)?;
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
        let quick = shadowborn_core::server_wireguard(state)?;
        let sync = quick
            .lines()
            .filter(|l| !l.starts_with("Address =") && !l.starts_with("SaveConfig ="))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        run("wg", &["syncconf", wg, "/dev/stdin"], sync.as_bytes())?;
    }
    run(
        "nft",
        &["-f", "/dev/stdin"],
        shadowborn_core::server_firewall(state)?.as_bytes(),
    )?;
    d.previous = None;
    save(&d)?;
    // Keep the held authorization lock until all derived configuration agrees.
    let _ = store;
    Ok(())
}
pub fn reconcile(state_path: &Path) -> Result<()> {
    host(state_path)?;
    let store = Store::open(state_path, false)?;
    let state = store.load()?;
    let result = reconcile_locked(&store, &state);
    if result.is_err() {
        fail_closed(&state);
    }
    result
}
/// Validate live ownership before generating any enrollment artifacts.
pub fn peer_preflight(state_path: &Path, state: &State) -> Result<bool> {
    if state_path != Path::new(ROOT) || journal()?.is_none() {
        crate::require_offline(&state.config)?;
        return Ok(false);
    }
    host(state_path)?;
    let d = journal()?.context("missing deployment")?;
    ensure!(
        d.phase == "committed" && d.previous.is_none(),
        "commit/reconcile deployment before changing peers"
    );
    ensure_files(&d)?;
    Ok(true)
}
/// Called AFTER canonical state is saved. Any failure closes the owned tunnel.
pub fn peers_changed(store: &Store, state: &State) -> Result<()> {
    let result = reconcile_locked(store, state);
    if result.is_err() {
        fail_closed(state);
    }
    result.context("authorization is durable but reconciliation failed; owned tunnel was closed; run deployment reconcile")
}
pub fn recover(state_path: &Path, boot_only: bool, transaction: Option<&str>) -> Result<()> {
    host(state_path)?;
    let store = Store::open(state_path, false)?;
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
    ] {
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
    // The first deployment requires an empty ruleset. These table names are
    // exclusively reserved; never flush or restore any other administrator table.
    for (family, name) in [("inet", "shadowborn"), ("ip", "shadowborn_nat")] {
        if command("nft", &["list", "table", family, name]).is_ok() {
            command("nft", &["delete", "table", family, name])?;
        }
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
    let _ = system(&["stop", "--no-block", "shadowborn-rollback.timer"]);
    Ok(())
}
