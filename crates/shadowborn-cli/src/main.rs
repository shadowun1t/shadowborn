use anyhow::{bail, Context, Result};
mod dns;
mod lockdown;
use lockdown::LockdownCommand;
mod policy;
mod setup;
use clap::{Parser, Subcommand};
use shadowborn_core::{Config, PeerStatus, State};
use shadowborn_platform as platform;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "shadowborn",
    version,
    about = "Provision and administer a self-hosted WireGuard gateway"
)]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/shadowborn/config.toml")]
    config: PathBuf,
    #[arg(long, global = true, default_value = "/var/lib/shadowborn")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Version,
    Doctor,
    Validate,
    /// File-only wizard for a fresh gateway using baseline defaults.
    Setup(setup::Setup),
    /// Manage configured DNS/IP filtering before server deployment.
    Policy {
        #[command(subcommand)]
        command: policy::PolicyCommand,
    },
    Init {
        #[arg(long)]
        dry_run: bool,
    },
    Plan {
        #[arg(long)]
        json: bool,
        /// Perform read-only preflight on this initialized, fresh server.
        #[arg(long)]
        host: bool,
    },
    /// Export a new root-only directory. Does not install or activate networking.
    Render {
        #[arg(long)]
        output: PathBuf,
    },
    /// Activate a fresh server with independent rollback; commit after a test peer.
    Apply {
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        console_verified: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Deployment {
        #[command(subcommand)]
        command: DeploymentCommand,
    },
    Status,
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
    Firewall {
        #[command(subcommand)]
        command: FirewallCommand,
    },
    Backup {
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        output: PathBuf,
    },
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Uninstall {
        #[arg(long)]
        plan: bool,
    },
}
#[derive(Subcommand)]
enum DeploymentCommand {
    Status,
    Commit {
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        egress_verified: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Tear down an owned gateway and retain canonical state and revocations.
    Remove {
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        console_verified: bool,
    },
    /// Resume current authorization into owned config/kernel; no activity history.
    Reconcile,
    /// Recover pending deployment (also invoked by timer and boot service).
    Recover {
        #[arg(long)]
        boot_only: bool,
        #[arg(long)]
        transaction: Option<String>,
    },
    #[command(hide = true)]
    Activate,
    #[command(hide = true)]
    FirewallLoad,
}
#[derive(Subcommand)]
enum ServerCommand {
    Status,
}
#[derive(Subcommand)]
enum DnsCommand {
    Status,
    /// Configure an upstream in offline authorization state, then render anew.
    Configure {
        #[arg(
            long,
            conflicts_with = "quad9_dot",
            required_unless_present = "quad9_dot"
        )]
        stamp_file: Option<PathBuf>,
        #[arg(long)]
        quad9_dot: bool,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Subcommand)]
enum FirewallCommand {
    Plan,
}
#[derive(Subcommand)]
enum PeerCommand {
    List,
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_key: String,
    },
    /// Explicit convenience flow: creates a client private key in server memory.
    Issue {
        #[arg(long)]
        name: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        bundle: PathBuf,
        /// Maintain an idle NAT mapping for this device (25 seconds).
        #[arg(long)]
        nat_keepalive: bool,
        /// Optional PNG QR encrypted to the same age recipient; never printed.
        #[arg(long)]
        qr_bundle: Option<PathBuf>,
        #[arg(long)]
        accept_server_key_generation: bool,
    },
    Disable {
        #[arg(long)]
        name: String,
        #[arg(long)]
        confirm: bool,
    },
    Revoke {
        #[arg(long)]
        name: String,
        #[arg(long)]
        confirm: bool,
    },
    RotatePsk {
        #[arg(long)]
        name: String,
        #[arg(long)]
        confirm: bool,
    },
    ExportPublic {
        #[arg(long)]
        name: String,
    },
    Show {
        #[arg(long)]
        name: String,
        #[arg(long, required = true)]
        redacted: bool,
    },
}
#[derive(Subcommand)]
enum ClientCommand {
    Profile {
        /// Maintain an idle NAT mapping for this device (25 seconds).
        #[arg(long)]
        nat_keepalive: bool,
        /// Add the routing mark used by the strict Linux client firewall.
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    Lockdown {
        #[command(subcommand)]
        command: LockdownCommand,
    },
}
fn config(cli: &Cli) -> Result<Config> {
    Config::parse(&fs::read_to_string(&cli.config).context("cannot read server configuration")?)
}
fn read_state(cli: &Cli) -> Result<State> {
    platform::require_root()?;
    platform::Store::decode(&platform::read_secret(&cli.state_dir.join("state.json"))?)
}
fn emit(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn confirm(value: bool) -> Result<()> {
    if !value {
        bail!("explicit --confirm is required")
    }
    Ok(())
}
fn status(cli: &Cli) -> Result<()> {
    emit(platform::lifecycle::runtime_status(&cli.state_dir)?)
}
fn provisioning_plan(cli: &Cli) -> Result<()> {
    match fs::symlink_metadata(cli.state_dir.join("state.json")) {
        Ok(_) => {
            let state = read_state(cli)?;
            emit(shadowborn_core::plan(&state.config, Some(&state))?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            emit(shadowborn_core::plan(&config(cli)?, None)?)
        }
        Err(_) => bail!(
            "cannot inspect protected state for planning; use root for an initialized gateway"
        ),
    }
}
fn peer_command(cli: &Cli, cmd: &PeerCommand) -> Result<()> {
    match cmd {
        PeerCommand::List => {
            let state = read_state(cli)?;
            emit(state.peers.iter().map(|p|serde_json::json!({"name":p.name,"address":p.address,"status":p.status})).collect::<Vec<_>>())
        }
        PeerCommand::Show { name, .. } => {
            let state = read_state(cli)?;
            let p = state.peer(name)?;
            emit(
                serde_json::json!({"name":p.name,"address":p.address,"status":p.status,"public_key":"[REDACTED]","psk":"[REDACTED]"}),
            )
        }
        PeerCommand::ExportPublic { name } => {
            let state = read_state(cli)?;
            let p = state.peer(name)?;
            emit(
                serde_json::json!({"name":p.name,"public_key":p.public_key,"address":p.address,"status":p.status,"server_public_key":state.server_public_key}),
            )
        }
        _ => {
            platform::require_root()?;
            let store = platform::Store::open(&cli.state_dir, false)?;
            let before = store.load()?;
            let restricting = matches!(
                cmd,
                PeerCommand::Revoke { .. } | PeerCommand::Disable { .. }
            );
            let live = platform::lifecycle::peer_preflight(&cli.state_dir, &before, restricting)?;
            let mut after = before.clone();
            let mut artifacts: Vec<&Path> = Vec::new();
            match cmd {
                PeerCommand::Add { name, public_key } => after.add(
                    name.clone(),
                    public_key.clone(),
                    platform::generate_key(true)?,
                )?,
                PeerCommand::Issue {
                    name,
                    recipient,
                    bundle,
                    qr_bundle,
                    nat_keepalive,
                    accept_server_key_generation,
                } => {
                    if !accept_server_key_generation {
                        bail!("requires --accept-server-key-generation: this generates the client private key on the server")
                    }
                    let encrypted = platform::issue(
                        &mut after,
                        name,
                        recipient,
                        qr_bundle.is_some(),
                        *nat_keepalive,
                    )?;
                    platform::write_new_secret(bundle, &encrypted.profile)?;
                    artifacts.push(bundle);
                    if let (Some(path), Some(qr)) = (qr_bundle, encrypted.qr) {
                        if let Err(error) = platform::write_new_secret(path, &qr) {
                            fs::remove_file(bundle).context("QR export failed; incomplete encrypted profile could not be removed")?;
                            return Err(error);
                        }
                        artifacts.push(path);
                    }
                }
                PeerCommand::Disable { name, confirm: ok } => {
                    confirm(*ok)?;
                    after.disable(name, false)?;
                }
                PeerCommand::Revoke { name, confirm: ok } => {
                    confirm(*ok)?;
                    after.disable(name, true)?;
                }
                PeerCommand::RotatePsk { name, confirm: ok } => {
                    confirm(*ok)?;
                    let p = after
                        .peers
                        .iter_mut()
                        .find(|p| p.name == *name)
                        .context("peer not found")?;
                    if p.status == PeerStatus::Revoked {
                        bail!("revoked identity cannot be reused")
                    }
                    p.psk = Some(platform::generate_key(true)?);
                }
                _ => unreachable!(),
            }
            let persist = || -> Result<()> {
                if live {
                    platform::lifecycle::prepare_peer_change(&store)?;
                }
                store.save(Some(&before), &after)
            };
            if let Err(error) = persist() {
                for path in artifacts {
                    let _ = fs::remove_file(path);
                }
                return Err(error);
            }
            if live {
                platform::lifecycle::peers_changed(&store, &after)?;
            }
            println!("Authorization updated durably; owned live gateway reconciled when deployed. Previous exports are stale.");
            Ok(())
        }
    }
}
fn execute(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Policy { command } => policy::execute(cli, command),
        Commands::Version => {
            println!("shadowborn {} (gateway preview)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Commands::Setup(args) => {
            if cli.config != Path::new("/etc/shadowborn/config.toml")
                || cli.state_dir != Path::new("/var/lib/shadowborn")
            {
                bail!("setup creates a new gateway under --output; do not combine it with global --config/--state-dir")
            }
            args.execute()
        }
        Commands::Doctor => {
            let tools = [
                "wg",
                "wg-quick",
                "nft",
                "unbound",
                "unbound-checkconf",
                "age",
                "qrencode",
                "systemctl",
            ]
            .map(|name| {
                (
                    name,
                    ["/usr/bin", "/usr/sbin"]
                        .iter()
                        .any(|p| Path::new(p).join(name).is_file()),
                )
            });
            emit(
                serde_json::json!({"schema_version":1,"tools":tools.into_iter().collect::<std::collections::BTreeMap<_,_>>(),"network_mutations":false,"live_apply":"FRESH_DEBIAN_UBUNTU_CONSOLE_TRANSACTION","kernel_wireguard":"NOT_TESTED","ssh_safety":"NOT_TESTED","no_logs_runtime":"UNKNOWN","legacy_client":"independent; not inspected or changed"}),
            )
        }
        Commands::Validate => {
            config(cli)?;
            println!("Server configuration valid (deployment readiness NOT TESTED).");
            Ok(())
        }
        Commands::Plan { host, .. } => {
            if *host {
                platform::lifecycle::check_host(&cli.state_dir, &read_state(cli)?)?;
            }
            provisioning_plan(cli)
        }
        Commands::Init { dry_run: true } => provisioning_plan(cli),
        Commands::Init { dry_run: false } => {
            platform::require_root()?;
            let config = config(cli)?;
            platform::require_offline(&config)?;
            let store = platform::Store::open(&cli.state_dir, true)?;
            let private = platform::generate_key(false)?;
            let public = platform::public_key(&private)?;
            let state = State {
                schema_version: 1,
                config,
                server_private_key: private,
                server_public_key: public,
                peers: vec![],
            };
            store.save(None, &state)?;
            println!("Private gateway provisioning state initialized. No networking changed.");
            Ok(())
        }
        Commands::Render { output } => {
            let state = read_state(cli)?;
            platform::require_offline(&state.config)?;
            platform::export_bundle(output, &state)?;
            println!("Private VM review bundle written. Not installed or activated.");
            Ok(())
        }
        Commands::Apply { dry_run: true, .. } => provisioning_plan(cli),
        Commands::Apply {
            confirm: ok,
            console_verified,
            ..
        } => {
            confirm(*ok)?;
            let transaction = platform::lifecycle::apply(&cli.state_dir, *console_verified)?;
            emit(
                serde_json::json!({"deployment":"pending","transaction":transaction,"rollback_seconds":120,"next":"Test Internet and DNS with an enrolled peer, then deployment commit --transaction ID --peer NAME --egress-verified --confirm"}),
            )
        }
        Commands::Deployment { command } => match command {
            DeploymentCommand::Status => emit(platform::lifecycle::status(&cli.state_dir)?),
            DeploymentCommand::Commit {
                transaction,
                peer,
                egress_verified,
                confirm: ok,
            } => {
                confirm(*ok)?;
                platform::lifecycle::commit(&cli.state_dir, transaction, peer, *egress_verified)?;
                println!(
                    "Deployment committed. Boot reconciliation enabled; rollback timer cancelled."
                );
                Ok(())
            }
            DeploymentCommand::Remove {
                confirm: ok,
                console_verified,
            } => {
                confirm(*ok)?;
                platform::lifecycle::remove(&cli.state_dir, *console_verified)?;
                println!("Owned deployment removed. Configuration, keys and revocations retained.");
                Ok(())
            }
            DeploymentCommand::Reconcile => platform::lifecycle::reconcile(&cli.state_dir),
            DeploymentCommand::Recover {
                boot_only,
                transaction,
            } => platform::lifecycle::recover(&cli.state_dir, *boot_only, transaction.as_deref()),
            DeploymentCommand::FirewallLoad => platform::lifecycle::firewall_load(&cli.state_dir),
            DeploymentCommand::Activate => platform::lifecycle::activate(&cli.state_dir),
        },
        Commands::Status
        | Commands::Server {
            command: ServerCommand::Status,
        } => status(cli),
        Commands::Dns { command } => dns::execute(cli, command),
        Commands::Peer { command } => peer_command(cli, command),
        Commands::Client {
            command:
                ClientCommand::Profile {
                    name,
                    output,
                    strict,
                    nat_keepalive,
                },
        } => {
            let state = read_state(cli)?;
            platform::write_new_secret(
                output,
                shadowborn_core::with_nat_keepalive(
                    shadowborn_core::linux_client_template(&state, name, *strict)?,
                    *nat_keepalive,
                )
                .as_bytes(),
            )?;
            println!("Secret template written. Insert the device private key locally before activating the client.");
            Ok(())
        }
        Commands::Client {
            command: ClientCommand::Lockdown { command },
        } => lockdown::execute(cli, command),
        Commands::Firewall {
            command: FirewallCommand::Plan,
        } => {
            let state = read_state(cli)?;
            print!("{}", shadowborn_core::server_firewall(&state)?);
            Ok(())
        }
        Commands::Backup { recipient, output } => {
            let state = read_state(cli)?;
            let encrypted = platform::encrypt(recipient, &serde_json::to_vec(&state)?)?;
            platform::write_new_secret(output, &encrypted)?;
            println!("Encrypted configuration/key backup written; contains no activity history.");
            Ok(())
        }
        Commands::Restore {
            input,
            identity,
            confirm: ok,
            dry_run,
        } => {
            platform::require_root()?;
            if !dry_run {
                confirm(*ok)?;
            }
            let current = read_state(cli)?;
            platform::require_offline(&current.config)?;
            let backup = platform::Store::decode(&platform::decrypt(
                identity,
                &platform::read_secret(input)?,
            )?)?;
            let next = current.restore_authorization(backup)?;
            if *dry_run {
                println!("Offline restore validated; disabled/revoked identities remain restricted. No changes written.");
                return Ok(());
            }
            let store = platform::Store::open(&cli.state_dir, false)?;
            platform::require_offline(&current.config)?;
            store.save(Some(&current), &next)?;
            println!("Offline configuration restored with current revocations preserved. No network changes.");
            Ok(())
        }
        Commands::Uninstall { plan: true } => emit(
            serde_json::json!({"network_mutations":false,"installer":"scripts/uninstall-server.sh","retained":["configuration","keys","authorization state"],"live_deployment":"deployment remove --console-verified --confirm before file removal"}),
        ),
        Commands::Uninstall { plan: false } => {
            platform::unsupported("automatic removal of a live gateway; use uninstall --plan")
        }
    }
}
fn main() {
    // Limit accidental secret exposure through core dumps; do not touch host-wide policy.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    let cli = Cli::parse();
    if let Err(error) = execute(&cli) {
        eprintln!("shadowborn: {error}");
        std::process::exit(1)
    }
}
