use shadowborn_core::*;

fn config() -> Config {
    Config::parse(include_str!("../../../config/server.example.toml")).unwrap()
}

#[test]
fn old_config_and_state_default_to_empty_policy() {
    assert_eq!(config().filtering, Filtering::default());
    let state = State {
        schema_version: 1,
        config: config(),
        server_private_key: Secret::new(format!("{}A=", "B".repeat(42))).unwrap(),
        server_public_key: format!("{}A=", "C".repeat(42)),
        peers: vec![],
    };
    let mut old_json = serde_json::to_value(&state).unwrap();
    old_json["config"]
        .as_object_mut()
        .unwrap()
        .remove("filtering");
    let decoded: State = serde_json::from_value(old_json).unwrap();
    decoded.validate().unwrap();
    assert_eq!(decoded, state);
    let mut c = config();
    c.filtering = Filtering::parse(include_str!("../../../config/filtering.example.toml")).unwrap();
    c.validate().unwrap();
    assert_eq!(Config::parse(&toml::to_string(&c).unwrap()).unwrap(), c);
}

#[test]
fn import_handles_hosts_comments_duplicates_and_case_without_broadening() {
    assert_eq!(import_domains("# selected list\n0.0.0.0 ADS.Example. telemetry.example # comment\nads.example\n::1 localhost ip6-localhost\n").unwrap(), vec!["ads.example", "telemetry.example"]);
    assert_eq!(
        import_ipv4("198.18.1.0/24\n198.18.2.1 # single host\n198.18.2.1/32\n").unwrap(),
        vec!["198.18.1.0/24", "198.18.2.1/32"]
    );
    assert!(import_ipv4("198.18.1.2/24").is_err());
    assert!(import_ipv4("::/0").is_err());
    assert!(import_ipv4("198.18.1.0/24; log").is_err());
}

#[test]
fn malformed_or_injected_input_fails_as_a_whole_without_echo() {
    for invalid in [
        "||ads.example^",
        "https://ads.example/list",
        "*.example",
        "example.\"\nlog-queries: yes",
        "1.2.3.4 evil.example",
        "☃.example",
        "com",
        ".",
        "bad..example",
        "bad_.example",
    ] {
        let result = import_domains(&format!("valid.example\n{invalid}"));
        assert!(result.is_err(), "invalid fixture was accepted");
        assert!(!result.unwrap_err().to_string().contains("evil.example"));
    }
    assert!(Filtering::parse("query_history = []").is_err());
    assert!(import_domains(&"x".repeat(MAX_POLICY_BYTES + 1)).is_err());
    let too_many = (0..=MAX_POLICY_ENTRIES)
        .map(|i| format!("d{i}.example\n"))
        .collect::<String>();
    assert!(import_domains(&too_many).is_err());
}

#[test]
fn exceptions_use_label_boundaries_and_cannot_override_private_namespace() {
    let mut c = config();
    c.filtering.blocked_domains = vec!["ads.example".into()];
    c.filtering.allowed_domains = vec!["safe.ads.example".into()];
    c.validate().unwrap();
    c.filtering.allowed_domains = vec!["notads.example".into()];
    assert!(c.validate().is_err());
    for invalid in ["home.arpa", PRIVATE_ZONE, "host.shadowborn.home.arpa"] {
        c.filtering = Filtering {
            blocked_domains: vec![invalid.into()],
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
}

#[test]
fn local_names_cannot_redirect_public_names_or_metadata() {
    for (name, address) in [
        ("example.com", "10.89.0.1"),
        ("host.shadowborn.home.arpa", "169.254.169.254"),
        ("host.shadowborn.home.arpa", "10.89.0.0"),
        ("host.shadowborn.home.arpa", "10.89.0.255"),
    ] {
        let mut c = config();
        c.filtering.local_records = vec![LocalRecord {
            name: name.into(),
            address: address.parse().unwrap(),
        }];
        assert!(c.validate().is_err());
    }
}

#[test]
fn generated_policy_does_not_enable_logs_or_weaken_mandatory_firewall() {
    let mut c = config();
    c.filtering = Filtering::parse(include_str!("../../../config/filtering.example.toml")).unwrap();
    let dns = unbound(&c).unwrap();
    assert!(dns.contains("\"ads.example.\" always_nxdomain"));
    assert!(dns.contains("\"updates.telemetry.example.\" always_transparent"));
    assert!(dns.contains("local-zone: \"shadowborn.home.arpa.\" static"));
    assert!(dns.contains("local-data: \"gateway.shadowborn.home.arpa. 60 IN A 10.89.0.1\""));
    for forbidden in [
        "inform",
        "log-queries: yes",
        "log-replies: yes",
        "include:",
        "control-enable: yes",
    ] {
        assert!(!dns.contains(forbidden));
    }
    let state = State {
        schema_version: 1,
        config: c,
        server_private_key: Secret::new(format!("{}A=", "B".repeat(42))).unwrap(),
        server_public_key: format!("{}A=", "C".repeat(42)),
        peers: vec![],
    };
    let nft = server_firewall(&state).unwrap();
    // nft flush-table retains set elements; replace the owned table atomically.
    assert!(nft.contains("add table inet shadowborn\ndelete table inet shadowborn"));
    assert!(!nft.contains("flush table"));
    assert!(nft.contains("198.18.1.0/24"));
    assert!(
        nft.find("ip saddr @blocked_v4 drop").unwrap()
            < nft
                .find("ip daddr @peers ct state established,related accept")
                .unwrap()
    );
    for required in ["169.254.0.0/16", "meta nfproto ipv6 drop", "jump vpn_input"] {
        assert!(nft.contains(required));
    }
    for forbidden in [" log ", "nflog", "counter", "flush ruleset"] {
        assert!(!nft.contains(forbidden));
    }
}
