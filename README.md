<div align="center">
  <img src="assets/shadow-mist-rounded-icon.png" width="104" alt="">
  <h1>Shadowborn</h1>
</div>

Shadowborn is a self-hosted WireGuard VPN. Install it on a Linux VPS you control,
give each device its own key, and connect with a standard WireGuard client.
While connected, websites see the gateway's public IPv4 address. The default
profile sends DNS through the tunnel to the gateway, which forwards queries to
Quad9 using DNS over TLS. The gateway forwards IPv4 and blocks tunneled IPv6.

[Po polsku](docs/README.pl.md) · [Connect a phone by QR](docs/quickstart-qr.md) · [Linux kill switch](docs/client-kill-switch.md)

## 1. Install the VPN server

Use a fresh Debian 13 or Ubuntu 24.04 VPS with a public IPv4 address. Log in
with an SSH key and a user account that can run `sudo`. Keep the provider
console open for activation and commit, since connecting the laptop can
interrupt its SSH session. In the provider firewall, allow UDP `51820` for
WireGuard and your SSH port from your admin address.

**On the VPS**, install Rust and Cargo using your distribution packages or a
standalone installer. Check that `rustc --version` reports 1.85 or later, then
build as your regular user. [Rust installers](https://forge.rust-lang.org/infra/other-installation-methods.html#standalone-installers).

```bash
sudo apt-get update
sudo apt-get install git build-essential python3 iproute2 wireguard-tools nftables unbound ca-certificates
git clone https://github.com/shadowun1t/shadowborn.git
cd shadowborn
cargo build --locked --release -p shadowborn-cli
sudo ./scripts/install-server.sh
sudo install -D -m 0600 config/server.example.toml /etc/shadowborn/config.toml
sudoedit /etc/shadowborn/config.toml
```

In the `[server]` section, replace the three example values.

| Setting | What to enter |
| --- | --- |
| `endpoint` | The public IPv4 address of your VPS. |
| `wan_interface` | The name after `dev` in the output of `ip -4 route show default` on the VPS. |
| `admin_ipv4` | The source address from which you SSH into the VPS. Use `/32` for one IPv4 address. |

If SSH uses a custom port, set `ssh_port` too. Save the file and initialize the gateway once.

```bash
sudo shadowborn validate
sudo shadowborn init
```

## 2. Add your laptop

**On the Linux laptop**, install `wireguard-tools` and create a key for this
device. The last command displays its **public** key. The profile also needs a
working `resolvconf` command for DNS. If it is missing or Shadow Mist already
manages DNS on the laptop, check the [client setup guide](docs/client-enrollment.md) first.

```bash
sudo apt-get install wireguard-tools
command -v resolvconf
umask 077
mkdir "$HOME/shadowborn-laptop" && wg genkey > "$HOME/shadowborn-laptop/private.key"
wg pubkey < "$HOME/shadowborn-laptop/private.key"
```

**On the VPS**, replace `LAPTOP_PUBLIC_KEY` with that key. These commands
authorize the laptop and make its template available to your SSH account.
For a laptop that must block direct traffic whenever the tunnel stops, add
`--strict` to the profile export and follow the client firewall guide **before
starting WireGuard**. [Linux kill switch](docs/client-kill-switch.md).

```bash
sudo shadowborn peer add --name laptop --public-key 'LAPTOP_PUBLIC_KEY'
sudo shadowborn client profile --name laptop --output /root/laptop.template
sudo install -m 0600 -o "$(id -un)" /root/laptop.template "$HOME/laptop.template"
```

**Back on the laptop**, replace `ADMIN@VPS` with your verified SSH login.
Download the template and insert the private key locally. The template contains
a preshared key, so keep it private along with the finished profile.

```bash
cd "$HOME/shadowborn-laptop"
umask 077
scp ADMIN@VPS:laptop.template .
awk 'NR == FNR { key = $0; next } { sub(/<DEVICE_PRIVATE_KEY>/, key); print }' \
  private.key laptop.template > wg-shadowborn.conf
sudo install -d -m 0700 /etc/wireguard
sudo install -m 0600 wg-shadowborn.conf /etc/wireguard/wg-shadowborn.conf
```

## 3. Connect and check your exit IP

**In the VPS console**, run `sudo shadowborn plan --host --json` and review the
proposed changes. Resolve any reported firewall, route or DNS conflict before
proceeding. When the laptop is ready, start the trial and keep the transaction
ID. You have **120 seconds** to connect, verify the VPN and commit. If the trial
expires, the server rolls back automatically.

```bash
sudo shadowborn apply --console-verified --confirm
```

**On the laptop**, start the tunnel and check that a hostname resolves.

```bash
sudo systemctl start wg-quick@wg-shadowborn.service
getent ahostsv4 example.org
```

Open an HTTPS IP-check page on the laptop and confirm it shows the VPS's public
egress IPv4. You can also read the caller's address at an HTTPS endpoint you
control. Once DNS and the exit IP are correct, **in the VPS console** replace
`SERVER_ID` with the ID from `apply`.

```bash
sudo shadowborn deployment commit --transaction SERVER_ID --peer laptop --egress-verified --confirm
sudo shadowborn status
```

If you chose strict mode, commit the laptop's separate firewall trial before
enabling automatic startup.

| On the laptop | Command |
| --- | --- |
| Connect | `sudo systemctl start wg-quick@wg-shadowborn.service` |
| Disconnect | `sudo systemctl stop wg-quick@wg-shadowborn.service` |
| Connect at boot | `sudo systemctl enable wg-quick@wg-shadowborn.service` |

Disconnecting a standard profile restores direct Internet access. With the strict
firewall committed, Internet access resumes through the VPN when you reconnect.
To revoke a lost laptop, run `sudo shadowborn peer revoke --name laptop --confirm` on the VPS.

## Privacy and support

Shadowborn stores keys, configuration and authorization state. Its services do
not retain DNS queries, browsing history or per-device traffic history. The ISP
can see the VPN endpoint and traffic timing. The VPS provider, upstream resolver
and websites can keep their own records. [Privacy policy](docs/no-logs-policy.md).

This gateway preview was tested with a strict client on Debian 13 and Ubuntu
24.04.5 x86_64 VMs, including DNS, exit IP, tunnel loss, reboot and peer revocation.
Public VPS reachability and physical laptop behavior require verification on
your own network. [Test results](docs/validation.md) · [Lab benchmarks](docs/performance.md).

[Server setup](docs/installation-server.md) · [Backup, recovery and removal](docs/admin-recovery.md) · [DNS filtering](docs/filtering.md) · [Legacy Shadow Mist](docs/legacy/README.md)

License terms and the status of the legacy code are documented in
[LICENSE](LICENSE) and the [licensing notes](docs/licensing.md).
