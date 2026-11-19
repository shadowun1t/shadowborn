use crate::{config, emit, Cli};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use std::{path::PathBuf, process::Command};

const HELPER: &str = "/usr/local/bin/shadowborn-client-lockdown";

#[derive(Args)]
pub(crate) struct Network {
    #[arg(long, default_value = "wg-shadowborn")]
    interface: String,
    /// Physical interfaces allowed to broadcast DHCPv4 requests.
    #[arg(long)]
    dhcp_interface: Vec<String>,
}
impl Network {
    fn arguments(&self, cmd: &mut Command) {
        cmd.args(["--interface", self.interface.as_str()]);
        for nic in &self.dhcp_interface {
            cmd.args(["--dhcp-interface", nic]);
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum LockdownCommand {
    /// Export static-address firewall policy for offline review.
    Render {
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect the protected client profile and local provider conflicts.
    Plan(Network),
    Status,
    /// Start a 120-second trial. Rollback restores direct access.
    Enable {
        #[command(flatten)]
        network: Network,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        console_verified: bool,
    },
    /// Bind network and WireGuard startup to the reviewed firewall.
    Commit {
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        egress_verified: bool,
        #[arg(long)]
        confirm: bool,
    },
    /// Permit HTTP/HTTPS to one on-link IPv4 address for up to five minutes.
    TemporaryLan {
        #[arg(long)]
        address: std::net::Ipv4Addr,
        #[arg(long)]
        uplink: String,
        #[arg(long, default_value_t = 120)]
        seconds: u16,
        #[arg(long)]
        confirm: bool,
    },
    /// Remove owned rules and dependencies, permitting direct access.
    Disable {
        #[arg(long)]
        confirm: bool,
    },
}

pub(crate) fn execute(cli: &Cli, action: &LockdownCommand) -> Result<()> {
    use LockdownCommand::*;
    if let Render { output } = action {
        shadowborn_platform::require_root()?;
        let files = shadowborn_core::client_lockdown(&config(cli)?)?;
        shadowborn_platform::create_private(output)?;
        for (name, text) in files {
            shadowborn_platform::write_new_secret(&output.join(name), text.as_bytes())?;
        }
        println!("Client firewall review bundle written. See docs/client-kill-switch.md.");
        return Ok(());
    }
    if matches!(action, Status) && !std::path::Path::new(HELPER).exists() {
        return emit(serde_json::json!({"state":"HELPER_UNAVAILABLE","enforced":null}));
    }
    let mut cmd = Command::new(HELPER);
    match action {
        Render { .. } => unreachable!(),
        Plan(net) => net.arguments(cmd.arg("plan")),
        Status => {
            cmd.arg("status");
        }
        Enable {
            network,
            confirm,
            console_verified,
        } => {
            super::confirm(*confirm)?;
            ensure!(
                *console_verified,
                "verify a working console and specify --console-verified"
            );
            network.arguments(cmd.args(["enable", "--confirm", "--console-verified"]));
        }
        Commit {
            transaction,
            egress_verified,
            confirm,
        } => {
            super::confirm(*confirm)?;
            ensure!(
                *egress_verified,
                "verify DNS and egress from the client first"
            );
            cmd.args([
                "commit",
                "--transaction",
                transaction,
                "--egress-verified",
                "--confirm",
            ]);
        }
        TemporaryLan {
            address,
            uplink,
            seconds,
            confirm,
        } => {
            super::confirm(*confirm)?;
            cmd.args([
                "temporary-lan",
                "--address",
                &address.to_string(),
                "--uplink",
                uplink,
                "--seconds",
                &seconds.to_string(),
                "--confirm",
            ]);
        }
        Disable { confirm } => {
            super::confirm(*confirm)?;
            cmd.args(["disable", "--confirm"]);
        }
    }
    ensure!(
        cmd.status()
            .context("install the separate client package with scripts/install-client-lockdown.sh")?
            .success(),
        "client lockdown operation failed"
    );
    Ok(())
}
