use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use shadowborn_core::*;
fn raw(address: &str, name: &str, path: &str) -> Vec<u8> {
    let mut bytes = vec![2, 0, 0, 0, 0, 0, 0, 0, 0];
    for value in [address, "", name, path] {
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes
}
fn proxy(bytes: &[u8]) -> Dnscrypt {
    Dnscrypt {
        stamp: format!("sdns://{}", URL_SAFE_NO_PAD.encode(bytes)),
    }
}
#[test]
fn stamps_reject_bootstrap_truncation_injection_and_plaintext() {
    let good = raw("198.18.0.53", "resolver.example", "/dns-query");
    assert!(proxy(&good).validate().is_ok());
    for end in 0..good.len() {
        assert!(proxy(&good[..end]).validate().is_err());
    }
    for (ip, name, path) in [
        ("", "resolver.example", "/dns-query"),
        ("resolver.example", "resolver.example", "/dns-query"),
        ("127.0.0.1", "resolver.example", "/dns-query"),
        ("198.18.0.53", "user@resolver.example", "/dns-query"),
        ("198.18.0.53", "resolver.example:0", "/dns-query"),
        ("198.18.0.53", "resolver.example", "/dns\n-query"),
    ] {
        assert!(proxy(&raw(ip, name, path)).validate().is_err());
    }
    for protocol in [0, 1, 3, 4, 5] {
        let mut invalid = good.clone();
        invalid[0] = protocol;
        assert!(proxy(&invalid).validate().is_err());
    }
    let mut extra = good.clone();
    extra.push(0);
    assert!(proxy(&extra).validate().is_err());
    // Correct VLP: two 32-byte certificate hashes, continuation flag on first.
    let position = 10 + "198.18.0.53".len();
    let mut pins = vec![0xa0];
    pins.extend([1; 32]);
    pins.push(32);
    pins.extend([2; 32]);
    let mut multi = good.clone();
    multi.splice(position..position + 1, pins);
    assert!(proxy(&multi).validate().is_ok());
}
#[test]
fn adapter_has_no_cleartext_fallback_or_activity_sink() {
    let mut config = Config::parse(include_str!("../../../config/server.example.toml")).unwrap();
    config.addons.dnscrypt = Some(proxy(&raw("198.18.0.53", "resolver.example", "/dns-query")));
    assert!(config.validate().is_err()); // Never silently override a declared DoT policy.
    config.dns.upstream = "dnscrypt-proxy".into();
    config.validate().unwrap();
    let text = unbound(&config).unwrap();
    assert!(text.contains("forward-tls-upstream: no"));
    assert!(text.contains("do-not-query-localhost: no"));
    assert!(text.contains("forward-first: no"));
    assert!(!text.contains("9.9.9.9"));
    let proxy = config.addons.dnscrypt.as_ref().unwrap().render().unwrap();
    let parsed: toml::Value = toml::from_str(&proxy).unwrap();
    assert_eq!(parsed["bootstrap_resolvers"].as_array().unwrap().len(), 0);
    for section in [
        "sources",
        "query_log",
        "nx_log",
        "blocked_names",
        "tls_key_log_file",
        "user_name",
    ] {
        assert!(parsed.get(section).is_none());
    }
    assert_eq!(parsed["log_file"].as_str(), Some("/dev/null"));
    assert_eq!(
        parsed["listen_addresses"].as_array().unwrap()[0].as_str(),
        Some("127.0.0.1:5354")
    );
}
#[test]
fn unsupported_pihole_switch_is_rejected() {
    assert!(Config::parse(&format!(
        "{}\n[addons]\npihole=true",
        include_str!("../../../config/server.example.toml")
    ))
    .is_err());
}
