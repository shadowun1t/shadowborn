//! Validate DNS stamp serialization, never implement transport or cryptography.
use crate::Dnscrypt;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::net::Ipv4Addr;

fn take<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8]> {
    ensure!(input.len() >= size, "incomplete DoH stamp");
    let (value, rest) = input.split_at(size);
    *input = rest;
    Ok(value)
}
fn lp<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let size = usize::from(take(input, 1)?[0]);
    take(input, size)
}
impl Dnscrypt {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.stamp.len() <= 2048, "DoH stamp exceeds limit");
        let encoded = self
            .stamp
            .strip_prefix("sdns://")
            .context("DoH stamp requires sdns://")?;
        let data = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("invalid DoH stamp encoding"))?;
        let mut input = data.as_slice();
        ensure!(
            take(&mut input, 1)? == [2],
            "this adapter supports only pinned DoH stamps (protocol 2)"
        );
        take(&mut input, 8)?; // Declared provider properties are not guarantees.
        let address: Ipv4Addr = std::str::from_utf8(lp(&mut input)?)
            .ok()
            .and_then(|s| s.parse().ok())
            .context("stamp must pin a literal IPv4 address, without a port")?;
        ensure!(
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_private()
                && !address.is_link_local(),
            "public resolver address required"
        );
        // VLP: each hash has its own length byte; high bit means another follows.
        loop {
            let length = take(&mut input, 1)?[0];
            let size = usize::from(length & 0x7f);
            ensure!(
                size == 32 || length == 0,
                "invalid DoH certificate hash length"
            );
            take(&mut input, size)?;
            if length & 0x80 == 0 {
                break;
            }
        }
        let authority =
            std::str::from_utf8(lp(&mut input)?).context("invalid DoH TLS authority")?;
        let hostname = if let Some((name, port)) = authority.split_once(':') {
            ensure!(
                port.parse::<u16>().ok().filter(|port| *port != 0).is_some(),
                "invalid DoH port"
            );
            name
        } else {
            authority
        };
        ensure!(
            hostname.len() <= 253
                && hostname.contains('.')
                && hostname.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')),
            "invalid DoH TLS hostname"
        );
        let path = lp(&mut input)?;
        ensure!(
            path.starts_with(b"/")
                && path
                    .iter()
                    .all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'?' | b'\\')),
            "invalid DoH request path"
        );
        ensure!(
            input.is_empty(),
            "trailing data/bootstrap resolvers are forbidden in DoH stamp"
        );
        Ok(())
    }
    pub fn render(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            r#"# Pinned DoH via dnscrypt-proxy. No resolver-list downloads or activity sinks.
server_names = ['shadowborn']
listen_addresses = ['127.0.0.1:5354']
max_clients = 256
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = false
doh_servers = true
odoh_servers = false
http3 = false
http3_probe = false
doh_check_cert_hashes_on_connect = true
ignore_system_dns = true
bootstrap_resolvers = []
netprobe_timeout = 0
lb_estimator = false
log_level = 6
log_file = '/dev/null'
use_syslog = false
cache = true
cache_size = 4096
cache_min_ttl = 0
cache_max_ttl = 86400
cache_neg_min_ttl = 0
cache_neg_max_ttl = 600
timeout = 5000
[static.shadowborn]
stamp = '{}'
"#,
            self.stamp
        ))
    }
}
