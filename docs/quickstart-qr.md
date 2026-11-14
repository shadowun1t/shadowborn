# Prepare a server and connect by QR

This preview prepares all files for a **fresh disposable VPS VM** in one command.
Activation is still manual: automatic apply/rollback, live peer administration
and persistent strict client protection are unfinished. No command below changes
your laptop's firewall, routes or DNS. Do not deploy the server on that laptop.

## 1. Keep the export decryption key on the operator's computer

On your trusted computer with age installed:

```bash
umask 077
mkdir -m 0700 -p "$HOME/shadowborn-operator"
age-keygen -o "$HOME/shadowborn-operator/identity.agekey"
age-keygen -y "$HOME/shadowborn-operator/identity.agekey"
```

The last command shows the **public** `age1...` recipient. Copy only that public
recipient to the server command below. Keep the private identity and its recovery
copy off the VPS. Do not overwrite an existing identity; reuse its public recipient.

## 2. Prepare the fresh server

From the checkout on the fresh server, after reviewing package installation:

```bash
sudo apt-get install wireguard-tools nftables unbound ca-certificates age qrencode
cargo build --locked --release -p shadowborn-cli
./scripts/install-server.sh --dry-run
sudo ./scripts/install-server.sh
shadowborn doctor
```

Replace the example addresses, WAN name and `AGE_PUBLIC_RECIPIENT` with your own.
The admin CIDR is the address/range permitted for SSH, **not** a VPN peer address.
Discover the WAN using `ip route show default`; do not assume `eth0` or `ens3`.
The initial preparation is read-only:

```bash
shadowborn setup \
  --endpoint 203.0.113.10 --wan-interface ens3 \
  --admin-ipv4 198.51.100.8/32 \
  --name phone --recipient AGE_PUBLIC_RECIPIENT \
  --output /root/shadowborn-prepared --dry-run
```

Then prepare files, explicitly accepting that this convenience flow generates
the phone's private key in server memory:

```bash
sudo shadowborn setup \
  --endpoint 203.0.113.10 --wan-interface ens3 \
  --admin-ipv4 198.51.100.8/32 \
  --name phone --recipient AGE_PUBLIC_RECIPIENT \
  --output /root/shadowborn-prepared --accept-server-key-generation
```

`--listen-port`, `--ssh-port`, `--interface` and `--tunnel-ipv4` have explicit
overrides. The default is UDP 51820, SSH TCP 22, `wg-shadowborn`, `10.89.0.1/24`,
with IPv4 Internet egress and IPv6 blocked. Both client default routes use WG.
Safety settings, DoT and the no-activity-logs policy cannot be disabled.
`--dry-run` checks configuration, not installed tools, age recipient checksum or
host deployment readiness. Existing output paths are always refused.

The private directory contains:

| File/directory | Purpose |
| --- | --- |
| `config.toml`, `state/` | Gateway policy, server key, authorized public keys and PSKs; no client private key or activity history. |
| `server/` | WireGuard, nftables, Unbound, sysctl and systemd files for review. |
| `client.conf.age`, `client.png.age` | Encrypted imports of the **same device identity**, as a standard profile and QR. |
| `NEXT-STEPS.txt` | Deployment and custody reminders without secrets. |

All directories/files are 0700/0600. Failure cleanup removes only the new output
directory; interrupted processes may leave a private incomplete directory to
inspect/remove before retrying. No claim of secure SSD or memory erasure is made.
Keep the directory outside Git and unencrypted backup/sync services.

## 3. Review and activate in the VM

Use the generated state for subsequent commands; **do not initialize again**:

```bash
sudo shadowborn --config /root/shadowborn-prepared/config.toml \
  --state-dir /root/shadowborn-prepared/state plan --json
sudo shadowborn --state-dir /root/shadowborn-prepared/state peer list
```

Follow [manual VM activation](installation-server.md#manual-activation-in-a-disposable-vm),
using `/root/shadowborn-prepared/server` wherever that recipe says
`/root/shadowborn-review`. First verify console access, SSH allowlist/port, subnet
collisions, existing firewalls, resolver bindings and provider UDP firewall.
Keep using the explicit config/state paths; do not keep two independently mutable
state copies. Existing gateways must not be reinitialized with `setup`.

Additional devices must be enrolled **before activation** with `peer add` or
`peer issue`, then `render` into a new review directory. Live enrollment/revoke
is still unsupported. Never reuse the phone's profile for another device.

## 4. Scan on the trusted computer

Transfer only the encrypted `client.png.age` and/or `client.conf.age` from the
server using authenticated SSH/SFTP or encrypted removable storage. No public QR
decoder or web page is involved. On a Linux desktop with a private session runtime
directory and a trusted local image viewer:

```bash
(
  set -eu
  umask 077
  test -n "${XDG_RUNTIME_DIR:-}"
  SHADOWBORN_QR_DIR=$(mktemp -d "$XDG_RUNTIME_DIR/shadowborn-qr.XXXXXX")
  trap 'rm -f "$SHADOWBORN_QR_DIR/client.png"; rmdir "$SHADOWBORN_QR_DIR"' EXIT
  age --decrypt --identity "$HOME/shadowborn-operator/identity.agekey" \
    --output "$SHADOWBORN_QR_DIR/client.png" ./client.png.age
  display "$SHADOWBORN_QR_DIR/client.png"
)
```

`display` is an example of a local foreground viewer (ImageMagick); close it after
scanning. Avoid viewers that upload images, retain previews or create thumbnails.
Session runtime storage may be swapped; use encrypted swap or a swap-free lab if
plaintext swap is a concern. This procedure limits extra files; it cannot enforce
the storage behavior of the OS, image viewer or phone. Never screenshot/share a QR.

In a WireGuard app that supports QR import, choose **add tunnel → scan QR code**.
The QR carries the actual configuration, not a URL, token or enrollment API.
Activate only after the server is ready. Actual Android/iOS app import remains
NOT TESTED; independent decoding is checked in the lab.

For Linux file import, decrypt into a protected directory:

```bash
umask 077
age --decrypt --identity "$HOME/shadowborn-operator/identity.agekey" \
  --output "$HOME/shadowborn-operator/wg-shadowborn.conf" ./client.conf.age
```

Then follow [standard client installation](client-enrollment.md), including
resolver checks. A standard profile has **no persistent kill switch**. Verify
egress and DNS from an opted-in test client; a handshake alone is insufficient.
No tested production, universal client support or absolute no-leak claim is made.
