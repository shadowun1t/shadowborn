# Client enrollment

For the convenience flow with a new server and first device, see the
[server + QR walkthrough](quickstart-qr.md). It prepares files without activating
networking. Device-generated keys below remain the preferred custody model.

Preferred flow: create keys on the device, send only its public key over an
already authenticated administrator channel. Never share device private keys.
On a standard Linux client with wireguard-tools:

```bash
umask 077
mkdir -m 0700 -p "$HOME/shadowborn-device"
cd "$HOME/shadowborn-device"
wg genkey > privatekey
wg pubkey < privatekey > publickey
```

Before VM activation, authorize that public key using `sudo shadowborn peer add
--name laptop --public-key DEVICE_PUBLIC_KEY`. The server assigns a unique /32
and generates a separate PSK. `peer export-public --name laptop` outputs public
configuration; `peer show --name laptop --redacted` hides keys. `peer list` has
no activity counters or timestamps.

Export `sudo shadowborn client profile --name laptop --output /root/laptop.template`.
Transfer the PSK-bearing template using authenticated encrypted transport or
an encrypted removable medium. Replace `<DEVICE_PRIVATE_KEY>` on the device with
its own private key using a local editor, without printing keys. The result is a
standard wg-quick config. Protect directory/file permissions as 0700/0600.

Optional convenience: `sudo shadowborn peer issue --name laptop --recipient
AGE_RECIPIENT --bundle /root/laptop.conf.age --accept-server-key-generation`.
This explicitly creates the client private key in server memory and immediately
encrypts the profile to a native age recipient. No plaintext convenience artifact
is written. Decrypt locally using the matching age identity into a 0600 file.
This does not provide the preferred device-only key custody.

To also create a scannable QR, install the distro's `qrencode` package and use:

```bash
sudo shadowborn peer issue --name phone --recipient AGE_PUBLIC_RECIPIENT \
  --bundle /root/phone.conf.age --qr-bundle /root/phone.png.age \
  --accept-server-key-generation
```

The profile and PNG are independently age-encrypted to the same recipient, with
identical credentials. Secret input reaches qrencode through stdin; its image
output stays in memory until encrypted. Neither plaintext export is written to
disk or printed. Failed exports do not save a new authorization; existing files
are never overwritten. An interruption can leave encrypted incomplete artifacts;
inspect current peer state and retire unused artifacts before retrying. Client
private keys are not retained in authorization state, so QR regeneration from
that state is deliberately unavailable. Keep the encrypted original as needed.

For a gateway prepared with `setup`, add `--state-dir /root/shadowborn-prepared/state`
to the command. All enrollment remains offline: add devices and render a fresh
server bundle **before** activation. Follow the walkthrough to transfer, decrypt
and display the QR locally, then scan in a standard WireGuard app. No web
dashboard or shareable enrollment token is involved. Phone app acceptance is
NOT TESTED; independent QR decode checks are not a substitute for that test.

On a separate, explicitly approved client VM:

```bash
sudo install -d -m 0700 /etc/wireguard
sudo install -m 0600 /path/to/completed/profile.conf /etc/wireguard/wg-shadowborn.conf
sudo systemctl enable --now wg-quick@wg-shadowborn.service
```

`DNS =` relies on wg-quick's resolvconf integration. Inspect the distro's DNS stack
and install the appropriate integration deliberately. Kali NetworkManager plus
systemd-resolved/Shadow Mist compatibility is NOT TESTED. Do not switch the
working laptop DNS implicitly. Use a pinned endpoint to avoid DNS bootstrap.

Both default address families route into the tunnel. This preview has IPv4-only
server egress; IPv6 is intentionally unavailable through it. **Standard mode has
no persistent kill switch**: stopping WG, resolver fallback or competing routing
can expose direct traffic. `client lockdown enable` is unsupported. Non-Linux WG
apps are best effort with no strict guarantee.

All peer mutations currently operate before deployment. A detected live/installed
gateway is rejected. For urgent revocation on the manual VM, use the console and
stop the tunnel until both kernel and persistent config have been updated; see
admin-recovery.md. Never assume a changed offline state invalidates old bundles.
