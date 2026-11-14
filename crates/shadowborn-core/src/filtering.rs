//! Administrator-authored policy only; never learned from observed activity.
use crate::V4Prefix;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};

pub const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_POLICY_ENTRIES: usize = 20_000;
pub const PRIVATE_ZONE: &str = "shadowborn.home.arpa";

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Filtering {
    pub blocked_domains: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub blocked_ipv4: Vec<String>,
    pub local_records: Vec<LocalRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalRecord {
    pub name: String,
    pub address: Ipv4Addr,
}

pub fn domain(value: &str) -> Result<String> {
    let normalized = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    let labels: Vec<_> = normalized.split('.').collect();
    if normalized.len() > 253
        || labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || labels
            .last()
            .is_none_or(|label| !label.bytes().any(|b| b.is_ascii_alphabetic()))
    {
        bail!("invalid DNS name; use ASCII/punycode domain labels, without wildcards or URLs")
    }
    Ok(normalized)
}

fn checked_domains(values: &[String]) -> Result<BTreeSet<&str>> {
    let mut seen = BTreeSet::new();
    for value in values {
        if domain(value)? != *value || !seen.insert(value.as_str()) {
            bail!("domain lists require unique lowercase names without a trailing dot")
        }
        // Keep the private namespace authoritative and unable to leak upstream.
        if value == PRIVATE_ZONE
            || value.ends_with(&format!(".{PRIVATE_ZONE}"))
            || PRIVATE_ZONE.ends_with(&format!(".{value}"))
        {
            bail!("filter lists cannot override the private DNS namespace")
        }
    }
    Ok(seen)
}

fn has_ancestor(mut name: &str, names: &BTreeSet<&str>) -> bool {
    loop {
        if names.contains(name) {
            return true;
        }
        let Some((_, suffix)) = name.split_once('.') else {
            return false;
        };
        name = suffix;
    }
}

impl Filtering {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_POLICY_BYTES {
            bail!("policy input exceeds size limit")
        }
        toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid filtering TOML schema"))
    }

    pub fn validate(&self, tunnel: V4Prefix) -> Result<()> {
        if self.blocked_domains.len()
            + self.allowed_domains.len()
            + self.blocked_ipv4.len()
            + self.local_records.len()
            > MAX_POLICY_ENTRIES
        {
            bail!("filtering policy exceeds entry limit")
        }
        let blocked = checked_domains(&self.blocked_domains)?;
        let allowed = checked_domains(&self.allowed_domains)?;
        for value in allowed {
            if !has_ancestor(value, &blocked) {
                bail!("DNS exception must match a blocked name or its subdomain")
            }
        }
        let mut networks = BTreeSet::new();
        for cidr in &self.blocked_ipv4 {
            let prefix = V4Prefix::parse(cidr)?;
            if prefix.cidr() != *cidr || !networks.insert(cidr) {
                bail!("blocked IPv4 prefixes must be canonical and unique")
            }
        }
        let mut names = BTreeSet::new();
        for record in &self.local_records {
            if domain(&record.name)? != record.name
                || !record.name.ends_with(&format!(".{PRIVATE_ZONE}"))
                || !names.insert(&record.name)
                || !tunnel.contains(record.address)
                || [tunnel.network(), tunnel.broadcast()].contains(&u32::from(record.address))
            {
                bail!("local records require unique private-zone names and usable tunnel IPv4 addresses")
            }
        }
        Ok(())
    }

    pub fn unbound_rules(&self) -> String {
        // A more specific zone wins. At the same name an explicit allow wins.
        let allowed: BTreeSet<_> = self.allowed_domains.iter().collect();
        let mut rules = format!("    local-zone: \"{PRIVATE_ZONE}.\" static\n");
        for name in self.blocked_domains.iter().collect::<BTreeSet<_>>() {
            if !allowed.contains(name) {
                rules.push_str(&format!("    local-zone: \"{name}.\" always_nxdomain\n"));
            }
        }
        for name in allowed {
            rules.push_str(&format!("    local-zone: \"{name}.\" always_transparent\n"));
        }
        for record in &self.local_records {
            rules.push_str(&format!(
                "    local-data: \"{}. 60 IN A {}\"\n",
                record.name, record.address
            ));
        }
        rules
    }
}

/// Plain domain lists or hosts entries with loopback/unspecified sink addresses.
/// Reject the entire input on unsupported syntax; never silently skip bad rules.
pub fn import_domains(text: &str) -> Result<Vec<String>> {
    import_lines(text, |fields, values| {
        let names = match fields {
            [name] => std::slice::from_ref(name),
            ["0.0.0.0" | "127.0.0.1" | "::" | "::1", names @ ..] if !names.is_empty() => names,
            _ => bail!("expected a domain or a hosts entry with a sink address"),
        };
        for name in names {
            // Conventional local hosts aliases are not Internet blocking policy.
            if [
                "localhost",
                "localhost.localdomain",
                "ip6-localhost",
                "ip6-loopback",
            ]
            .contains(name)
            {
                continue;
            }
            values.insert(domain(name)?);
        }
        Ok(())
    })
}

pub fn import_ipv4(text: &str) -> Result<Vec<String>> {
    import_lines(text, |fields, values| {
        let [value] = fields else {
            bail!("expected one IPv4 address or prefix per line")
        };
        let prefix = if value.contains('/') {
            let prefix = V4Prefix::parse(value)?;
            if u32::from(prefix.address) != prefix.network() {
                bail!("IPv4 prefix has host bits; refusing to broaden it silently")
            }
            prefix
        } else {
            V4Prefix {
                address: value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid IPv4 address"))?,
                bits: 32,
            }
        };
        values.insert(prefix.cidr());
        Ok(())
    })
}

fn import_lines(
    text: &str,
    parse: impl Fn(&[&str], &mut BTreeSet<String>) -> Result<()>,
) -> Result<Vec<String>> {
    if text.len() > MAX_POLICY_BYTES {
        bail!("list input exceeds size limit")
    }
    let mut values = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let fields: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if !fields.is_empty() {
            parse(&fields, &mut values).map_err(|_| {
                anyhow::anyhow!(
                    "unsupported list syntax at line {}; input not imported",
                    index + 1
                )
            })?;
        }
        if values.len() > MAX_POLICY_ENTRIES {
            bail!("list exceeds entry limit")
        }
    }
    Ok(values.into_iter().collect())
}
