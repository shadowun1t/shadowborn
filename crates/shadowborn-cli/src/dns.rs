use super::{Cli, DnsCommand};
use anyhow::Result;
use shadowborn_platform as platform;
pub fn execute(cli: &Cli, command: &DnsCommand) -> Result<()> {
    let DnsCommand::Configure {
        stamp_file,
        confirm,
        dry_run,
        ..
    } = command
    else {
        let configured = match std::fs::symlink_metadata(cli.state_dir.join("state.json")) {
            Ok(_) => super::read_state(cli)?.config,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => super::config(cli)?,
            Err(_) => anyhow::bail!("cannot inspect protected DNS configuration"),
        };
        return super::emit(
            serde_json::json!({"configured_upstream":configured.dns.upstream,"availability":"UNKNOWN","transport_verified":"NOT_TESTED","query_logging_runtime":"UNKNOWN","probes_issued":false}),
        );
    };
    platform::require_root()?;
    if !dry_run {
        super::confirm(*confirm)?;
    }
    let store = if *dry_run {
        None
    } else {
        Some(platform::Store::open(&cli.state_dir, false)?)
    };
    let before = match &store {
        Some(s) => s.load()?,
        None => super::read_state(cli)?,
    };
    platform::require_offline(&before.config)?;
    let mut after = before.clone();
    after.config.addons.dnscrypt = match stamp_file {
        Some(file) => Some(shadowborn_core::Dnscrypt {
            stamp: platform::read_policy(file)?.trim().to_owned(),
        }),
        None => None,
    };
    after.config.dns.upstream = if after.config.addons.dnscrypt.is_some() {
        "dnscrypt-proxy"
    } else {
        "quad9-dot"
    }
    .into();
    after.validate()?;
    if let Some(store) = store {
        store.save(Some(&before), &after)?;
        println!("Offline DNS configuration updated. Render a new bundle; previous exports are stale. No network changes.");
        Ok(())
    } else {
        super::emit(shadowborn_core::plan(&after.config, Some(&after))?)
    }
}
