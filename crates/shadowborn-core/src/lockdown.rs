//! Offline preview of the separately packaged client firewall.
use crate::Config;
use anyhow::Result;
use std::collections::BTreeMap;

pub const CLIENT_FWMARK: u32 = 51820;

pub fn client_lockdown(config: &Config) -> Result<BTreeMap<String, String>> {
    config.validate()?;
    let wg = &config.server.interface;
    let rules = include_str!("../../../packaging/client/lockdown.nft.in")
        .replace("@OWNER@", "Shadowborn client review")
        .replace("@INTERFACE@", wg)
        .replace("@ENDPOINT@", &config.server.endpoint.to_string())
        .replace("@PORT@", &config.server.listen_port.to_string())
        .replace("@DHCP@", "");
    // VM review uses a known disposable table. Live installation checks ownership.
    let rules =
        format!("add table inet shadowborn_client\ndelete table inet shadowborn_client\n{rules}");
    let unit = include_str!("../../../packaging/client/shadowborn-client-lockdown.service");
    let dependency = "[Unit]\nRequires=shadowborn-client-lockdown.service\nAfter=shadowborn-client-lockdown.service\n";
    Ok(BTreeMap::from([
        ("lockdown.nft".into(), rules),
        ("shadowborn-client-lockdown.service".into(), unit.into()),
        ("wg-quick-client-lockdown.conf".into(), format!("{dependency}\n[Service]\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n")),
        ("CLIENT-REVIEW.txt".into(), format!("Review for {wg} using a static IPv4 uplink. The live installer derives its endpoint from the protected client profile. See docs/client-kill-switch.md for file-only installation, trial, provider gates and console recovery.\n")),
    ]))
}
