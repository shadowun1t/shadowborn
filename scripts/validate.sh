#!/bin/sh
set -eu
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release --workspace
for script in scripts/*.sh; do sh -n "$script"; done
cargo build --locked -p shadowborn-core --example render_lab
python3 tests/integration/shadowborn.py
python3 tests/integration/provisioning.py
python3 tests/integration/generated.py
python3 tests/integration/smoke.py --skip-daemon
# Network tests run only in guarded disposable user/network namespaces.
python3 tests/namespaces/shadowborn.py
if command -v dnscrypt-proxy >/dev/null 2>&1 || [ -n "${SHADOWBORN_DNSCRYPT:-}" ]; then
    python3 tests/namespaces/dnscrypt.py
else
    echo 'SKIPPED: dnscrypt-proxy runtime test; install tested package or set SHADOWBORN_DNSCRYPT'
fi
