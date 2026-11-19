#!/usr/bin/env python3
"""Acceptance tests through the disposable guests' private virtio control channels."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import io
import os
from pathlib import Path
import secrets
import statistics
import runpy
import tarfile
import time

import lab

ROOT = Path(__file__).resolve().parents[2]
CLI = '/usr/local/bin/shadowborn'
LOCK = '/usr/local/bin/shadowborn-client-lockdown'
WG = 'wg-quick@wg-shadowborn.service'
QUERY = 'acceptance.shadowborn.example'
UPLINK = 'enp0s4'
WRITE = """import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
with open(path, 'wb', opener=lambda name, flags: os.open(name, flags, int(sys.argv[2], 8))) as f:
    f.write(sys.stdin.buffer.read())
os.chmod(path, int(sys.argv[2], 8))
"""


class Guest:
    def __init__(self, base):
        self.base = base
        self.run('test', '-c', '/dev/virtio-ports/shadowborn.test')

    def run(self, *args, data=b'', ok=True, timeout=60):
        if os.environ.get('SHADOWBORN_VM_PROGRESS'):
            print(self.base.name, args[0], flush=True)
        code, out, err = lab.request(self.base, list(args), data, timeout)
        if (code == 0) != ok:
            # No args, stdout or stderr here: provisioning commands can carry credentials.
            detail = err.decode().strip() if args[0] in (CLI, LOCK) else ''
            raise RuntimeError(f'{self.base.name}: unexpected exit {code} from {args[0]}. {detail}')
        return out

    def put(self, path, data, mode='0644'):
        self.run('python3', '-c', WRITE, path, mode, data=data.encode() if isinstance(data, str) else data)

    def reboot(self):
        before = self.run('cat', '/proc/sys/kernel/random/boot_id')
        self.run('systemctl', '--no-block', 'reboot')
        lab.disconnect(self.base)
        wait_for(lambda: self.run('cat', '/proc/sys/kernel/random/boot_id', timeout=5) != before, timeout=150)

    def pkg(self):
        self.run('apt-get', '-qq', 'update', timeout=300)
        self.run('env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-qq', 'install', '--no-install-recommends',
                 'wireguard-tools', 'nftables', 'unbound', 'age', 'tcpdump', 'iperf3', 'openssl', 'curl',
                 'systemd-resolved', 'iputils-ping', 'openssh-client', 'dnsutils', timeout=300)


def wait_for(check, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, RuntimeError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Guest condition timed out')


def units(server, client):
    # Test setup is a fresh cloud image with only two NICs. Disconnect the package
    # NIC before testing. All subsequent packets remain on the private QEMU LAN.
    for guest in (server, client):
        guest.put('/etc/systemd/network/01-packages.network',
                  '[Match]\nName=enp0s2\n[Link]\nActivationPolicy=always-down\nRequiredForOnline=no\n[Network]\nLinkLocalAddressing=no\n')
        if guest is server:
            guest.put('/etc/systemd/network/01-br-wan.netdev', '[NetDev]\nName=br-wan\nKind=bridge\n')
            guest.put('/etc/systemd/network/01-lab.network', '[Match]\nName=enp0s4\n[Network]\nBridge=br-wan\n')
            nic, address = 'br-wan', '203.0.113.1'
        else:
            nic, address = UPLINK, '203.0.113.2'
        guest.put('/etc/systemd/network/02-wan.network',
                  f'[Match]\nName={nic}\n[Network]\nAddress={address}/24\nGateway=203.0.113.254\n'
                  + ('Address=2001:db8:1::2/64\n' if guest is client else ''))
        guest.put('/etc/cloud/cloud.cfg.d/99-shadowborn-lab-network.cfg', 'network: {config: disabled}\n')
        guest.put('/etc/systemd/system/systemd-networkd-wait-online.service.d/90-lab.conf',
                  f'[Service]\nExecStart=\nExecStart=/usr/lib/systemd/systemd-networkd-wait-online --interface={nic}:routable --timeout=20\n')
        # Fresh Ubuntu cloud images enable the UFW loader even with no UFW policy.
        # Verify the unused packaged configuration before detaching it in this lab.
        if guest.run('sh', '-c', 'command -v ufw || true').strip():
            assert b'inactive' in guest.run('ufw', 'status')
            guest.run('systemctl', 'disable', '--now', 'ufw.service')
        guest.run('systemctl', 'daemon-reload')
        guest.run('systemctl', 'restart', 'systemd-networkd')
        guest.run('ip', 'link', 'set', 'enp0s2', 'down')
        wait_for(lambda: b'203.0.113.254' in guest.run('ip', '-4', 'route', 'show', 'default'))
    server.put('/root/observer.py', (ROOT/'tests/vm/observer.py').read_bytes())
    server.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '2',
               '-subj', '/CN=shadowborn synthetic lab',
               '-addext', f'subjectAltName=DNS:dns.quad9.net,DNS:{QUERY},IP:198.18.0.80',
               '-keyout', '/root/fixture.key', '-out', '/root/fixture.crt')
    for guest in (server, client):
        guest.put('/usr/local/share/ca-certificates/shadowborn-test.crt', server.run('cat', '/root/fixture.crt'))
        guest.run('update-ca-certificates')
    server.put('/root/observer.sh', """#!/bin/sh
set -eu
ip netns add observer
ip link add obs-br type veth peer name eth0 netns observer
ip link set obs-br master br-wan
ip link set obs-br up
ip -n observer link set lo up
ip -n observer link set eth0 up
ip -n observer address add 203.0.113.254/24 dev eth0
ip -n observer -6 address add 2001:db8:1::fe/64 dev eth0 nodad
for addr in 198.18.0.80 9.9.9.9 149.112.112.112; do
    ip -n observer address add "$addr/32" dev lo
done
ip netns exec observer iperf3 -s -D -B 198.18.0.80 --logfile /dev/null
exec ip netns exec observer python3 /root/observer.py
""", '0700')
    server.put('/etc/systemd/system/lab-observer.service', """[Unit]
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/root/observer.sh
ExecStopPost=-/usr/sbin/ip netns delete observer
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
""")
    server.run('systemctl', 'daemon-reload')
    server.run('systemctl', 'enable', '--now', 'lab-observer.service')
    wait_for(lambda: source(client, pinned=True) == b'203.0.113.2')
    print('PASS direct HTTPS control from client on isolated WAN', flush=True)


def source(client, pinned=False, ok=True):
    args = ['--resolve', f'{QUERY}:443:198.18.0.80'] if pinned else []
    return client.run('curl', '-4fsS', '--noproxy', '*', '--connect-timeout', '2', '--max-time', '4',
                      *args, 'https://' + QUERY, ok=ok)


def install(server, client, update=False):
    package = runpy.run_path(str(ROOT/'scripts/server-package.py'))
    server_script = 'update-server.sh' if update else 'install-server.sh'
    for guest, inventory, installer, options in [(server, 'FILES', server_script, []),
                                                (client, 'CLIENT_FILES', 'install-client-lockdown.sh',
                                                 ['--update'] if update else [])]:
        sources = {src for src, _ in package[inventory].values()}
        sources.update({'scripts/server-package.py', 'scripts/' + installer})
        if guest is server:
            sources.add('scripts/uninstall-server.sh')
        with io.BytesIO() as data:
            with tarfile.open(fileobj=data, mode='w:gz') as archive:
                for src in sorted(sources):
                    archive.add(ROOT/src, arcname=src, recursive=False)
            guest.run('install', '-d', '-m', '0700', '/root/lab-package')
            guest.run('tar', '-xz', '-C', '/root/lab-package', data=data.getvalue())
        path = '/root/lab-package/scripts/' + installer
        guest.run(path, *options, '--dry-run')
        guest.run(path, *options)


def prepare(server, client):
    install(server, client)
    units(server, client)
    conf = (ROOT/'config/server.example.toml').read_text().replace('ens3', 'br-wan').replace(
        '203.0.113.10', '203.0.113.1').replace('198.51.100.8/32', '203.0.113.254/32')
    server.put('/etc/shadowborn/config.toml', conf, '0600')
    server.run(CLI, 'init')
    # Private key stays in the guest that owns the client.
    public = client.run('sh', '-ec', 'umask 077; wg genkey > /root/device.key; wg pubkey < /root/device.key')
    server.run(CLI, 'peer', 'add', '--name', 'test-device', '--public-key', public.decode().strip())
    server.run(CLI, 'client', 'profile', '--strict', '--name', 'test-device', '--output', '/root/device.template')
    client.run('python3', '-c', """import os, pathlib, sys
os.umask(0o077)
pathlib.Path('/etc/wireguard/wg-shadowborn.conf').write_text(
    sys.stdin.read().replace('<DEVICE_PRIVATE_KEY>', pathlib.Path('/root/device.key').read_text().strip()))
""", data=server.run('cat', '/root/device.template'))
    client.run(LOCK, 'plan')
    print('PASS protected preferred enrollment and strict client preflight', flush=True)


def trial(client):
    return json.loads(client.run(LOCK, 'enable', '--confirm', '--console-verified'))['transaction']


def apply(server):
    return json.loads(server.run(CLI, 'apply', '--confirm', '--console-verified'))['transaction']


def ssh_fixture(server):
    # A guest-only admin and host key pinned via the private virtio console.
    server.run('sh', '-ec', """
id sb-lab-admin >/dev/null 2>&1 || useradd -m -s /bin/sh sb-lab-admin
test -f /root/lab-ssh-id || ssh-keygen -q -t ed25519 -N '' -f /root/lab-ssh-id
install -d -m 0700 -o sb-lab-admin -g sb-lab-admin /home/sb-lab-admin/.ssh
install -m 0600 -o sb-lab-admin -g sb-lab-admin /root/lab-ssh-id.pub /home/sb-lab-admin/.ssh/authorized_keys
awk '{print "203.0.113.1", $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub > /root/lab-known-hosts
""")
    wait_for(lambda: ssh_check(server) is None)


def ssh_check(server):
    server.run('ip', 'netns', 'exec', 'observer', 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=4',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/root/lab-known-hosts',
               '-i', '/root/lab-ssh-id', 'sb-lab-admin@203.0.113.1', 'true')


def privacy(server, client):
    for guest, units in [(server, (WG, 'shadowborn-dns.service', 'shadowborn-firewall.service',
                                    'shadowborn-reconcile.service', 'shadowborn-recovery.service',
                                    'shadowborn-activate.service')), (client, (WG, 'shadowborn-client-lockdown.service',
                                                                              'shadowborn-client-resume.service',
                                                                              'shadowborn-client-trial-recovery.service'))]:
        for unit in units:
            # Read the service process stream. PID 1 lifecycle and sshd are OS records.
            entries = guest.run('journalctl', '--quiet', '--no-pager', '-o', 'cat', '_SYSTEMD_UNIT=' + unit)
            assert not entries.strip(), 'Owned service emitted journal output'
        for directory in ('/var/log', '/var/cache'):
            entries = guest.run('find', directory, '-type', 'f', '-iname', '*shadowborn*')
            assert not entries.strip(), 'Unexpected project log/cache'
    for guest, folder, allowed in [(server, '/etc/shadowborn', {'config.toml','server.nft'}),
                                   (server, '/var/lib/shadowborn', {'lock','state.json','deployment.json'}),
                                   (client, '/etc/shadowborn-client', {'lock','state.json'})]:
        for name in guest.run('ls', '-1', folder).decode().splitlines():
            assert name in allowed
            assert QUERY.encode() not in guest.run('cat', folder + '/' + name)


def measure(client, scope):
    tcp = json.loads(client.run('iperf3', '-c', '198.18.0.80', '-P', '2', '-t', '3', '-J'))['end']
    udp = json.loads(client.run('iperf3', '-c', '198.18.0.80', '-u', '-b', '10M', '-t', '2', '-J'))['end']['sum']
    ping = client.run('ping', '-n', '-M', 'do', '-s', '1300', '-c', '5', '-i', '0.1', '198.18.0.80').decode()
    latency = float(ping.split(' = ')[-1].split('/')[1])
    print('MEASURE', scope, json.dumps({'tcp_mbps': round(tcp['sum_received']['bits_per_second']/1e6, 1),
          'sender_cpu_pct': round(tcp['cpu_utilization_percent']['host_total'], 1),
          'udp_10m_loss_pct': udp['lost_percent'], 'udp_jitter_ms': round(udp['jitter_ms'], 3),
          'icmp_mean_ms': latency}), flush=True)


def observe(server, client, up):
    # Independent WAN ingress plus the client's outgoing physical and WG traffic.
    # The guest compares summaries in memory and returns only the exit status.
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(server.run, 'timeout', '-s', 'INT', '7', 'tcpdump', '-nn', '-l', '-Q', 'in',
                             '-i', UPLINK, 'ip or ip6', ok=False)
        time.sleep(0.7)
        client.run('python3', '-c', """import signal, socket, subprocess, sys, time
up = sys.argv[1] == 'up'
captures = {}
try:
    for nic in ([sys.argv[2], 'wg-shadowborn'] if up else [sys.argv[2]]):
        captures[nic] = subprocess.Popen(['tcpdump', '-nn', '-l', '-Q', 'out', '-i', nic, 'ip or ip6'],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(.4)
    assert all(proc.poll() is None for proc in captures.values())
    curl = subprocess.run(['curl', '-4fsS', '--noproxy', '*', '--max-time', '3', '--resolve',
                          f'{sys.argv[3]}:443:198.18.0.80', 'https://' + sys.argv[3]], capture_output=True)
    assert (curl.returncode == 0 and curl.stdout == b'203.0.113.1') if up else (curl.returncode != 0)
    if not up:
        for family, addr in [(socket.AF_INET, '203.0.113.254'), (socket.AF_INET6, '2001:db8:1::fe')]:
            for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                with socket.socket(family, kind) as s:
                    s.settimeout(.15)
                    try:
                        s.connect((addr, 53))
                        s.send(b'synthetic')
                    except OSError:
                        pass
    time.sleep(.4)
finally:
    for proc in captures.values():
        proc.send_signal(signal.SIGINT)
    packets = {nic: proc.communicate(timeout=3)[0].decode().splitlines() for nic, proc in captures.items()}
    assert all(proc.returncode == 0 for proc in captures.values())
physical = [line for line in packets[sys.argv[2]] if line.strip() and 'ICMP6, neighbor' not in line]
assert all(' > 203.0.113.1.51820: UDP' in line for line in physical)
if up:
    assert physical and any(' > 198.18.0.80.443:' in line for line in packets['wg-shadowborn'])
""", 'up' if up else 'down', UPLINK, QUERY)
        packets = result.result().decode().splitlines()
    # ARP is outside this IP filter. IPv6 neighbour discovery is a link control.
    outer = [line for line in packets if ' > 203.0.113.1.51820: UDP' in line]
    other = [line for line in packets if line.strip() and line not in outer and 'ICMP6, neighbor' not in line]
    assert not other, 'Observed unexpected physical IP packet'
    assert not up or outer, 'Missing positive encrypted transport control'
    print('PASS client and independent server WAN captures, tunnel ' + ('up (inner HTTPS observed)' if up else 'down'), flush=True)


def authorization_wakeup(server):
    public = server.run('sh', '-ec', 'wg genkey | wg pubkey').decode().strip()
    peer_name = 'interruption-' + secrets.token_hex(4)
    server.run(CLI, 'peer', 'add', '--name', peer_name, '--public-key', public)
    assert public.encode() in server.run('wg', 'show', 'wg-shadowborn', 'peers').split()
    # Model process loss immediately after canonical atomic rename. No command
    # follows it to touch the active kernel; the installed .path unit must do so.
    server.run('python3', '-c', """import fcntl, json, os, pathlib, sys, tempfile
root = pathlib.Path('/var/lib/shadowborn')
lock = (root/'lock').open('rb')
fcntl.flock(lock, fcntl.LOCK_EX)
marker = os.open(root/'authorization.pending', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.fsync(marker)
os.close(marker)
path = root/'state.json'
state = json.loads(path.read_bytes())
peer = next(p for p in state['peers'] if p['name'] == sys.argv[1])
peer.update(status='revoked', psk=None)
with tempfile.NamedTemporaryFile(dir=root, delete=False) as tmp:
    tmp.write(json.dumps(state).encode()); tmp.flush(); os.fsync(tmp.fileno())
os.replace(tmp.name, path)
fd = os.open(root, os.O_DIRECTORY); os.fsync(fd); os.close(fd)
""", peer_name)
    wait_for(lambda: public.encode() not in server.run('wg', 'show', 'wg-shadowborn', 'peers').split())
    wait_for(lambda: server.run('test', '!', '-e', '/var/lib/shadowborn/authorization.pending') == b'')
    print('PASS independent recovery after simulated process loss following canonical authorization rename', flush=True)


def credential_failures(server, client):
    path = '/etc/wireguard/wg-shadowborn.conf'
    original = client.run('cat', path)
    for field, command in [('PresharedKey', 'genpsk'), ('PrivateKey', 'genkey'), ('Endpoint', None)]:
        client.run('systemctl', 'stop', WG)
        value = client.run('wg', command).strip() if command else b'203.0.113.99:51820'
        changed = b'\n'.join(field.encode() + b' = ' + value if line.startswith(field.encode() + b' = ')
                             else line for line in original.split(b'\n'))
        try:
            client.put(path, changed, '0600')
            client.run('systemctl', 'start', WG)
            source(client, pinned=True, ok=False)
        finally:
            client.run('systemctl', 'stop', WG)
            client.put(path, original, '0600')
    client.run('systemctl', 'start', WG)
    wait_for(lambda: source(client) == b'203.0.113.1')
    print('PASS wrong PSK, unknown client key and changed endpoint block egress; original profile recovers', flush=True)


def guest_suspend(client):
    if b'mem' not in client.run('cat', '/sys/power/state').split():
        print('SKIPPED guest suspend: VM kernel exposes no mem state', flush=True)
        return
    client.run('systemd-run', '--quiet', '--collect', '--unit=lab-suspend', '--on-active=2s', '--timer-property=AccuracySec=100ms', '/usr/bin/systemctl', 'suspend')
    seen = False
    for _ in range(30):
        if lab.qmp(client.base, 'query-status')['return']['status'] == 'suspended':
            seen = True
            break
        time.sleep(.5)
    if seen:
        assert 'return' in lab.qmp(client.base, 'system_wakeup')
        wait_for(lambda: source(client) == b'203.0.113.1')
        assert json.loads(client.run(LOCK, 'status'))['enforced']
        print('PASS QEMU guest ACPI suspend/resume with enforced firewall and working WG', flush=True)
    else:
        print('SKIPPED guest suspend: no ACPI suspended state observed', flush=True)


def boot_failure(client):
    asset = '/usr/local/share/shadowborn-client/lockdown.nft.in'
    original = client.run('cat', asset)
    client.put(asset, b'invalid fixture\n')
    client.reboot()
    wait_for(lambda: client.run('systemctl', 'show', '-p', 'ActiveState', '--value',
                                'shadowborn-client-lockdown.service').strip() == b'failed')
    client.run('systemctl', 'is-active', '--quiet', 'systemd-networkd', ok=False)
    client.run('systemctl', 'is-active', '--quiet', WG, ok=False)
    assert not client.run('ip', '-4', 'route', 'show', 'default').strip()
    client.put(asset, original)
    client.run('systemctl', 'start', 'shadowborn-client-lockdown.service', 'systemd-networkd')
    client.run('systemctl', 'start', WG)
    wait_for(lambda: source(client) == b'203.0.113.1')
    print('PASS provider and WG blocked after failed boot firewall; console repair restores tunnel', flush=True)


def rollback(server, client):
    before = server.run('cat', '/proc/sys/net/ipv4/ip_forward')
    server.run('nft', 'add', 'table', 'inet', 'lab_unrelated')
    client.run('nft', 'add', 'table', 'inet', 'lab_unrelated')
    transaction = apply(server)
    trial(client)
    client.run('systemctl', 'start', WG)
    assert source(client) == b'203.0.113.1'
    # No commit on either side. Independent timers must recover both VMs.
    wait_for(lambda: b'absent' in server.run(CLI, 'deployment', 'status')
             and b'INACTIVE' in client.run(LOCK, 'status'), timeout=150)
    client.run('systemctl', 'stop', WG)
    assert source(client, pinned=True) == b'203.0.113.2'
    assert server.run('cat', '/proc/sys/net/ipv4/ip_forward') == before
    server.run('nft', 'list', 'table', 'inet', 'lab_unrelated')
    client.run('nft', 'list', 'table', 'inet', 'lab_unrelated')
    print('PASS unattended server and client timeout, preserved unrelated tables and forwarding baseline', flush=True)
    assert apply(server) != transaction
    trial(client)
    client.run('systemctl', 'start', WG)
    assert source(client) == b'203.0.113.1'
    client.reboot()
    wait_for(lambda: json.loads(client.run(LOCK, 'status'))['state'] == 'INACTIVE')
    wait_for(lambda: source(client, pinned=True) == b'203.0.113.2')
    server.reboot()
    wait_for(lambda: b'absent' in server.run(CLI, 'deployment', 'status'))
    assert not server.run('wg', 'show', 'interfaces').strip()
    assert server.run('cat', '/proc/sys/net/ipv4/ip_forward') == before
    print('PASS pending client and server rollbacks after reboot', flush=True)


def retire_packages(server, client):
    install(server, client, update=True)
    server.run('/root/lab-package/scripts/uninstall-server.sh')
    client.run('/root/lab-package/scripts/install-client-lockdown.sh', '--uninstall')
    server.run('test', '!', '-e', CLI)
    client.run('test', '!', '-e', LOCK)
    stored = json.loads(server.run('cat', '/var/lib/shadowborn/state.json'))
    assert all(peer['status'] == 'revoked' for peer in stored['peers'])
    client.run('test', '-f', '/etc/wireguard/wg-shadowborn.conf')
    assert source(client, pinned=True) == b'203.0.113.2'
    print('PASS file-only update and uninstall on both roles, retained credentials and revocation state', flush=True)


def exercise(server, client):
    ssh_fixture(server)
    measure(client, 'direct')
    transaction = apply(server)
    strict = trial(client)
    source(client, pinned=True, ok=False)
    client.run('ping', '-6', '-c1', '-W1', '2001:db8:1::fe', ok=False)
    client.run('systemctl', 'start', WG)
    assert source(client) == b'203.0.113.1'
    server.run(CLI, 'deployment', 'commit', '--transaction', transaction, '--peer', 'test-device', '--egress-verified', '--confirm')
    client.run(LOCK, 'commit', '--transaction', strict, '--egress-verified', '--confirm')
    client.run('systemctl', 'enable', WG)
    wait_for(lambda: json.loads(client.run(LOCK, 'status'))['boot_dependencies'])
    print('PASS both transactions committed after authenticated DNS and HTTPS at the server egress address', flush=True)
    ssh_check(server)
    server.run('ip', 'netns', 'exec', 'observer', 'dig', '+time=1', '+tries=1', '@203.0.113.1', QUERY, ok=False)
    privacy(server, client)
    observe(server, client, True)
    measure(client, 'tunnel')
    # Readiness is already established. Capture resolver timings inside the guest.
    timings = [float(x) for x in client.run('python3', '-c', """import subprocess, time
for i in range(20):
    start = time.monotonic()
    subprocess.run(['getent', 'ahostsv4', f'sample-{i}.shadowborn.example'], stdout=subprocess.DEVNULL, check=True)
    print((time.monotonic()-start)*1000)
""").split()]
    print(f'MEASURE resolver including process startup p50={statistics.median(timings):.2f} ms '
          f'p95={sorted(timings)[18]:.2f} ms', flush=True)
    server.run('systemctl', 'stop', 'shadowborn-dns.service')
    client.run('dig', '+tries=1', '+time=1', '@10.89.0.1', QUERY, ok=False)
    assert source(client, pinned=True) == b'203.0.113.1'
    server.run('systemctl', 'start', 'shadowborn-dns.service')
    client.run('systemctl', 'stop', WG)
    observe(server, client, False)
    source(client, pinned=True, ok=False)
    client.run('ping', '-6', '-c1', '-W1', '2001:db8:1::fe', ok=False)
    # An explicit on-link exception expires in the kernel while WG is down.
    portal = ['curl', '-4fsS', '--max-time', '2', '--resolve', f'{QUERY}:443:203.0.113.254', 'https://' + QUERY]
    client.run(*portal, ok=False)
    client.run(LOCK, 'temporary-lan', '--uplink', UPLINK, '--address', '203.0.113.254',
               '--seconds', '4', '--confirm')
    assert json.loads(client.run(LOCK, 'status'))['state'] == 'NOT_STRICT'
    assert client.run(*portal) == b'203.0.113.2'
    wait_for(lambda: json.loads(client.run(LOCK, 'status'))['enforced'] is True, timeout=10)
    client.run(*portal, ok=False)
    client.run('systemctl', 'start', WG)
    assert source(client) == b'203.0.113.1'
    privacy(server, client)
    client.reboot()
    wait_for(lambda: source(client) == b'203.0.113.1')
    assert json.loads(client.run(LOCK, 'status'))['boot_dependencies']
    print('PASS client boot, WG down/up, IPv6 denial and resolver outage', flush=True)
    boot_failure(client)
    credential_failures(server, client)
    guest_suspend(client)
    authorization_wakeup(server)
    privacy(server, client)
    server.reboot()
    wait_for(lambda: source(client) == b'203.0.113.1', timeout=100)
    server.run(CLI, 'peer', 'revoke', '--name', 'test-device', '--confirm')
    source(client, pinned=True, ok=False)
    assert not server.run('wg', 'show', 'wg-shadowborn', 'peers').strip()
    server.run('systemctl', 'restart', WG)
    server.run(CLI, 'peer', 'revoke', '--name', 'test-device', '--confirm')
    privacy(server, client)
    server.reboot()
    wait_for(lambda: server.run('systemctl', 'is-active', WG).strip() == b'active', timeout=100)
    assert not server.run('wg', 'show', 'wg-shadowborn', 'peers').strip()
    source(client, pinned=True, ok=False)
    print('PASS live revoke, repeated revoke, WG restart and gateway reboot', flush=True)
    privacy(server, client)
    print('PASS scoped owned file inventory and empty service output through failures, revoke and reboot', flush=True)
    server.run(CLI, 'deployment', 'remove', '--console-verified', '--confirm')
    client.run('systemctl', 'disable', '--now', WG)
    client.run(LOCK, 'disable', '--confirm')
    assert source(client, pinned=True) == b'203.0.113.2'
    assert b'revoked' in server.run(CLI, 'peer', 'list')
    print('PASS managed teardown retaining revocations and restoring direct egress', flush=True)
    retire_packages(server, client)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path, help='private directory containing server/ and client/ created by lab.py')
    parser.add_argument('action', choices=('packages', 'prepare', 'rollback', 'exercise'))
    args = parser.parse_args()
    guests = (args.directory / 'server', args.directory / 'client')
    for directory in guests:
        wait_for(lambda: bool(Guest(directory)), timeout=180)
    server, client = map(Guest, guests)
    if args.action == 'packages':
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(Guest.pkg, (server, client)))
    else:
        {'prepare': prepare, 'rollback': rollback, 'exercise': exercise}[args.action](server, client)
