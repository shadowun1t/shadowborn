use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use shadowborn_core::Filtering;
use shadowborn_platform as platform;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Show configured filtering, never DNS queries or traffic observations.
    Show,
    /// Check a complete policy against --config, without creating state.
    Check {
        #[arg(long)]
        input: PathBuf,
    },
    /// Replace the complete offline filtering policy; existing exports become stale.
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Replace one blocklist from a local domain/hosts or IPv4 list.
    ImportBlocklist {
        #[arg(long, value_enum)]
        kind: ListKind,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ListKind {
    Domains,
    Ipv4,
}

pub fn execute(cli: &super::Cli, command: &PolicyCommand) -> Result<()> {
    if let PolicyCommand::Check { input } = command {
        let mut config = super::config(cli)?;
        config.filtering = Filtering::parse(&platform::read_policy(input)?)?;
        config.validate()?;
        return super::emit(shadowborn_core::plan(&config, None)?);
    }
    if let PolicyCommand::Show = command {
        return super::emit(super::read_state(cli)?.config.filtering);
    }
    let (input, confirmed, dry_run) = match command {
        PolicyCommand::Import {
            input,
            confirm,
            dry_run,
        }
        | PolicyCommand::ImportBlocklist {
            input,
            confirm,
            dry_run,
            ..
        } => (input, *confirm, *dry_run),
        _ => unreachable!(),
    };
    platform::require_root()?;
    if !dry_run {
        super::confirm(confirmed)?;
    }
    // Dry-run reads the same atomic state but must not even create a lock file.
    let store = if dry_run {
        None
    } else {
        Some(platform::Store::open(&cli.state_dir, false)?)
    };
    let before = match &store {
        Some(store) => store.load()?,
        None => super::read_state(cli)?,
    };
    platform::require_offline(&before.config)?;
    let text = platform::read_policy(input)?;
    let mut after = before.clone();
    match command {
        PolicyCommand::Import { .. } => after.config.filtering = Filtering::parse(&text)?,
        PolicyCommand::ImportBlocklist {
            kind: ListKind::Domains,
            ..
        } => {
            after.config.filtering.blocked_domains = shadowborn_core::import_domains(&text)?;
        }
        PolicyCommand::ImportBlocklist {
            kind: ListKind::Ipv4,
            ..
        } => {
            after.config.filtering.blocked_ipv4 = shadowborn_core::import_ipv4(&text)?;
        }
        _ => unreachable!(),
    }
    after.validate()?;
    if let Some(store) = store {
        store.save(Some(&before), &after)?;
        println!("Offline filtering policy updated. Render a new server bundle; previous exports are stale. No network changes or activity recording.");
        Ok(())
    } else {
        super::emit(shadowborn_core::plan(&after.config, Some(&after))?)
    }
}
