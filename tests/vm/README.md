# Disposable gateway and client acceptance

The harness uses two Linux systemd VMs and a third network namespace acting as
the external observer. Its HTTPS origin returns the source address it actually
receives. A synthetic CA authenticates the observer's DoT and HTTPS services.
The observer occupies the configured Quad9 IPs **only on the isolated test LAN**.
The package-download interface is brought down before the traffic tests. Guest
commands and the private test LAN use Unix sockets under a mode-0700 directory.
No SSH port is forwarded to the host. A guest-only key tests real SSH separately.

On an x86_64 Linux host with QEMU, qemu-img, genisoimage and Python 3, download an
official Debian 13 genericcloud or Ubuntu 24.04 Noble amd64 cloud image over HTTPS.
Verify it against the matching Debian SHA512SUMS or Ubuntu SHA256SUMS before boot.
A disk overlay and seed ISO are created for each guest. KVM is preferred. Allow
time for cloud-init and the virtio test transport on first boot.

```bash
cargo build --locked --release -p shadowborn-cli
LAB_DIR=$(mktemp -d)
IMAGE=/absolute/path/to/verified-cloud-image
python3 tests/vm/lab.py start "$LAB_DIR/server" "$IMAGE" "$(command -v genisoimage)" --lan "$LAB_DIR/lan.sock" --listen
python3 tests/vm/lab.py start "$LAB_DIR/client" "$IMAGE" "$(command -v genisoimage)" --lan "$LAB_DIR/lan.sock"
python3 tests/vm/acceptance.py "$LAB_DIR" packages
python3 tests/vm/acceptance.py "$LAB_DIR" prepare
python3 tests/vm/acceptance.py "$LAB_DIR" rollback
python3 tests/vm/acceptance.py "$LAB_DIR" exercise
python3 tests/vm/lab.py qmp "$LAB_DIR/client" system_powerdown
python3 tests/vm/lab.py qmp "$LAB_DIR/server" system_powerdown
```

Run the phases in order with fresh overlays. The tests exercise an IPv4 WAN,
WG and NAT, the standard resolver hookup, pinned DoT, HTTPS, SSH, timer and boot
recovery, client provider ordering, fail-closed tunnel loss, current authorization,
journal/file checks and package update/removal. Captures contain synthetic traffic and are inspected in
memory. Throughput is measured against the same observer before and after WG.
Test disks and per-guest boot output can contain lab identities and secrets.
After both VMs exit, retire the disposable directory. Never publish the overlays.

The [validation matrix](../../docs/validation.md) gives executed results. Public
VPS/provider egress, physical laptops, firmware, initramfs networking and real
radio/sleep transitions require independent acceptance.
