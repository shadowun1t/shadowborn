use anyhow::{bail, Result};
use clap::Args;
use shadowborn_core::{Config, State};
use shadowborn_platform as platform;
use std::{fs, net::Ipv4Addr, path::PathBuf};

/// Prepare a fresh gateway and first device in a private directory; no activation.
#[derive(Args)]
pub struct Setup {
    #[arg(long)]
    endpoint: Ipv4Addr,
    #[arg(long)]
    wan_interface: String,
    #[arg(long)]
    admin_ipv4: String,
    #[arg(long, default_value = "wg-shadowborn")]
    interface: String,
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,
    #[arg(long, default_value = "10.89.0.1/24")]
    tunnel_ipv4: String,
    #[arg(long)]
    name: String,
    /// Operator's PUBLIC native age recipient; keep the identity off the VPS.
    #[arg(long)]
    recipient: String,
    /// New private directory containing state, server files and encrypted imports.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    accept_server_key_generation: bool,
    #[arg(long)]
    dry_run: bool,
}

impl Setup {
    pub fn execute(&self) -> Result<()> {
        // Reuse the shipped safety floor; no independently drifting wizard defaults.
        // Global --config/--state-dir belong to existing-gateway commands, not setup.
        let mut config = Config::parse(include_str!("../../../config/server.example.toml"))?;
        config.server.endpoint = self.endpoint.into();
        config.server.wan_interface.clone_from(&self.wan_interface);
        config.server.admin_ipv4.clone_from(&self.admin_ipv4);
        config.server.interface.clone_from(&self.interface);
        config.server.listen_port = self.listen_port;
        config.server.ssh_port = self.ssh_port;
        config.server.tunnel_ipv4.clone_from(&self.tunnel_ipv4);
        config.validate()?;
        platform::validate_recipient(&self.recipient)?;
        if !shadowborn_core::valid_name(&self.name) {
            bail!("invalid device name")
        }
        if self.dry_run {
            return super::emit(shadowborn_core::plan(&config, None)?);
        }
        if !self.accept_server_key_generation {
            bail!("requires --accept-server-key-generation: setup generates a client private key on the server; use init/peer add for device-generated keys")
        }
        platform::require_root()?;
        platform::require_offline(&config)?;
        // Creation refuses existing directories/symlinks and unsafe ancestors.
        platform::create_private(&self.output)?;
        let result = (|| -> Result<()> {
            let private = platform::generate_key(false)?;
            let mut state = State {
                schema_version: 1,
                config,
                server_public_key: platform::public_key(&private)?,
                server_private_key: private,
                peers: vec![],
            };
            let enrollment = platform::issue(&mut state, &self.name, &self.recipient, true)?;
            platform::write_new_secret(
                &self.output.join("config.toml"),
                toml::to_string_pretty(&state.config)?.as_bytes(),
            )?;
            let store = platform::Store::open(&self.output.join("state"), true)?;
            store.save(None, &state)?;
            platform::export_bundle(&self.output.join("server"), &state)?;
            platform::write_new_secret(&self.output.join("client.conf.age"), &enrollment.profile)?;
            platform::write_new_secret(
                &self.output.join("client.png.age"),
                enrollment
                    .qr
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing QR artifact"))?,
            )?;
            platform::write_new_secret(
                &self.output.join("NEXT-STEPS.txt"),
                b"PROVISIONING ONLY: networking has NOT been activated.\n\
                Review config.toml and server/ using docs/installation-server.md.\n\
                Keep this directory root-only and outside Git/backups without encryption.\n\
                Before manual VM activation, install config.toml and the state directory\n\
                at /etc/shadowborn/config.toml and /var/lib/shadowborn respectively,\n\
                only if those destinations do not already exist. Do not run init again.\n\
                Alternatively pass --config OUTPUT/config.toml --state-dir OUTPUT/state\n\
                to existing-gateway commands. Never maintain two mutable state copies.\n\
                Transfer only client.conf.age/client.png.age to the operator's trusted\n\
                computer. Decrypt locally with age; scan using the WireGuard app.\n\
                Both imports authorize the SAME device. Issue a new peer per device.\n\
                QR is a secret: no public decoder, screenshots, terminal output or web UI.\n\
                STANDARD client only: no persistent kill switch; IPv6 egress blocked.\n\
                Live apply/revoke, strict client and runtime no-log VM gates are unfinished.\n",
            )?;
            Ok(())
        })();
        if result.is_err() {
            // Only remove the newly created, unpublished provisioning directory.
            if fs::remove_dir_all(&self.output).is_err() {
                bail!("setup failed and cleanup was incomplete; protect/remove the new output directory before retrying")
            }
        }
        result?;
        println!("Private server bundle and age-encrypted client profile/QR prepared. No networking changed. Read NEXT-STEPS.txt in the output directory. STANDARD client; strict protection is not installed.");
        Ok(())
    }
}
