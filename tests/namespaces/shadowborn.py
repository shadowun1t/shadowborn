#!/usr/bin/env python3
"""Synthetic kernel WireGuard/nft tests in disposable user+network namespaces.

No real Internet, host firewall, host routes or persistent activity captures.
Namespace subprocesses die on exit; veth links vanish with their namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def run(args, *, data=None, ok=True, timeout=30):
    result = subprocess.run([str(x) for x in args], input=data,
                            capture_output=True, timeout=timeout)
    if ok and result.returncode:
        # Never print wg key material/config or raw subprocess output.
        raise RuntimeError(f'Lab command failed: {Path(args[0]).name} (exit {result.returncode})')
    return result


def isolated():
    outer_namespace = os.environ.get('SHADOWBORN_OUTER_NETNS')
    if not outer_namespace or outer_namespace == os.readlink('/proc/self/ns/net'):
        raise RuntimeError('Refusing execution without a distinct outer network namespace marker')
    if os.geteuid() != 0:
        raise RuntimeError('Expected root mapped only inside the disposable user namespace')
    from dns_policy import exercise_dns_policy
    children = []
    with tempfile.TemporaryDirectory(prefix='shadowborn-netns-') as temp:
        base = Path(temp)
        try:
            for _ in range(3):
                child = subprocess.Popen(['unshare', '--net', 'sleep', '300'])
                children.append(child)
                for _attempt in range(100):
                    if child.poll() is not None:
                        raise RuntimeError('Cannot create child network namespace')
                    if os.readlink(f'/proc/{child.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                        break
                    time.sleep(.01)
                else:
                    raise RuntimeError('Namespace creation timeout')
            server, client, other = (child.pid for child in children)

            def ns(pid, *args, **kwargs):
                return run(['nsenter', '-t', str(pid), '-n', *args], **kwargs)

            run(['ip', 'link', 'add', 'br-lab', 'type', 'bridge'])
            run(['ip', 'addr', 'add', '203.0.113.254/24', 'dev', 'br-lab'])
            run(['ip', 'addr', 'add', '198.18.0.10/32', 'dev', 'br-lab'])
            run(['ip', 'addr', 'add', '198.18.1.20/32', 'dev', 'br-lab'])
            run(['ip', 'addr', 'add', '198.18.0.53/32', 'dev', 'br-lab'])
            run(['ip', 'addr', 'add', '169.254.169.254/32', 'dev', 'br-lab'])
            run(['ip', 'link', 'set', 'br-lab', 'up'])
            for index, (pid, name, address) in enumerate(((server, 'ens3', '203.0.113.1/24'), (client, 'wan0', '203.0.113.2/24'),
                                                         (other, 'wan0', '203.0.113.3/24'))):
                outer = f'veth-{index}'
                run(['ip', 'link', 'add', outer, 'type', 'veth', 'peer', 'name', name])
                run(['ip', 'link', 'set', name, 'netns', str(pid)])
                run(['ip', 'link', 'set', outer, 'master', 'br-lab'])
                run(['ip', 'link', 'set', outer, 'up'])
                ns(pid, 'ip', 'link', 'set', 'lo', 'up')
                ns(pid, 'ip', 'addr', 'add', address, 'dev', name)
                ns(pid, 'ip', 'link', 'set', name, 'up')
                ns(pid, 'ip', 'route', 'add', 'default', 'via', '203.0.113.254')
            private_server = run(['wg', 'genkey']).stdout.strip()
            private_client = run(['wg', 'genkey']).stdout.strip()
            private_other = run(['wg', 'genkey']).stdout.strip()
            public_other = run(['wg', 'pubkey'], data=private_other).stdout.strip()
            psk_other = run(['wg', 'genpsk']).stdout.strip()
            public_server = run(['wg', 'pubkey'], data=private_server).stdout.strip()
            public_client = run(['wg', 'pubkey'], data=private_client).stdout.strip()
            psk = run(['wg', 'genpsk']).stdout.strip()
            config = tomllib.loads((ROOT / 'config/server.example.toml').read_text())
            config['server']['endpoint'] = '203.0.113.1'
            config['filtering'] = {
                'blocked_domains': ['ads.example', 'telemetry.example'],
                'allowed_domains': ['safe.ads.example'],
                'blocked_ipv4': ['198.18.1.0/24', '198.18.1.20/32'],
                'local_records': [{'name': 'gateway.shadowborn.home.arpa', 'address': '10.89.0.1'}],
            }
            state = {'schema_version': 1, 'config': config,
                     'server_private_key': private_server.decode(),
                     'server_public_key': public_server.decode(),
                     'peers': [{'name': 'synthetic', 'public_key': public_client.decode(),
                                'address': '10.89.0.2', 'status': 'active', 'psk': psk.decode()}]}
            state['peers'].append({'name': 'second', 'public_key': public_other.decode(), 'address': '10.89.0.3',
                                   'status': 'active', 'psk': psk_other.decode()})
            fixture = base / 'fixture.json'
            fixture.write_text(json.dumps(state))
            fixture.chmod(0o600)
            bundle = base / 'bundle'
            run([ROOT / 'target/debug/examples/render_lab', fixture, bundle])
            ns(server, 'nft', 'add', 'table', 'inet', 'shadowborn_lab_unrelated')
            ns(server, 'nft', '--check', '-f', str(bundle / 'server.nft'))
            ns(server, 'nft', '-f', str(bundle / 'server.nft'))
            ns(server, 'nft', '-f', str(bundle / 'server.nft'))  # owned replacement
            ns(server, 'nft', 'list', 'table', 'inet', 'shadowborn_lab_unrelated')
            # wg-quick has no DNS/PostUp hooks in the generated server config.
            ns(server, 'wg-quick', 'up', str(bundle / 'wg-shadowborn.conf'))
            ns(server, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
            # Persistent policy is installed before any client WG interface exists.
            run(['ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'br-lab', 'nodad'])
            ns(client, 'ip', '-6', 'addr', 'add', '2001:db8::2/64', 'dev', 'wan0', 'nodad')
            ns(client, 'ping', '-6', '-c', '1', '-W', '2', '2001:db8::1')
            ns(client, 'nft', 'add', 'table', 'inet', 'client_unrelated')
            ns(client, 'nft', '--check', '-f', str(bundle / 'lockdown.nft'))
            ns(client, 'nft', '-f', str(bundle / 'lockdown.nft'))
            ns(client, 'nft', '-f', str(bundle / 'lockdown.nft'))
            ns(client, 'nft', 'list', 'table', 'inet', 'client_unrelated')
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            assert ns(client, 'ping', '-6', '-c', '1', '-W', '1', '2001:db8::1', ok=False).returncode
            print('PASS: client policy blocks physical IPv4/IPv6 before WG exists; atomic reload preserves unrelated rules')
            for pid, key, secret, address in ((client, private_client, psk, '10.89.0.2/32'),
                                               (other, private_other, psk_other, '10.89.0.3/32')):
                peer_config = (b'[Interface]\nFwMark = 51820\nPrivateKey = ' + key +
                               b'\n[Peer]\nPublicKey = ' + public_server + b'\nPresharedKey = ' + secret +
                               b'\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\n')
                ns(pid, 'ip', 'link', 'add', 'wg-shadowborn', 'type', 'wireguard')
                ns(pid, 'wg', 'setconf', 'wg-shadowborn', '/dev/stdin', data=peer_config)
                ns(pid, 'ip', 'addr', 'add', address, 'dev', 'wg-shadowborn')
                ns(pid, 'ip', 'link', 'set', 'wg-shadowborn', 'up')
                ns(pid, 'ip', 'route', 'add', '203.0.113.1/32', 'dev', 'wan0')
                ns(pid, 'ip', 'route', 'replace', 'default', 'dev', 'wg-shadowborn')
                ns(pid, 'ping', '-c', '2', '-W', '2', '198.18.0.10')
            assert ns(client, 'ping', '-c1', '-W1', '10.89.0.3', ok=False).returncode
            assert ns(other, 'ping', '-c1', '-W1', '10.89.0.2', ok=False).returncode
            print('PASS: two authenticated peers reach the origin and cannot reach each other')
            print('PASS: real kernel WireGuard handshake, generated firewall, scoped NAT and return traffic')
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.1.20', ok=False).returncode
            print('PASS: configured IPv4 egress blocklist denies a synthetic destination; overlapping ranges accepted')
            config['filtering']['blocked_ipv4'].append('198.18.0.10/32')
            fixture.write_text(json.dumps(state))
            changed = base / 'changed-policy'
            run([ROOT / 'target/debug/examples/render_lab', fixture, changed])
            ns(server, 'nft', '-f', str(changed / 'server.nft'))
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            ns(server, 'nft', 'list', 'table', 'inet', 'shadowborn_lab_unrelated')
            ns(server, 'nft', '-f', str(bundle / 'server.nft'))
            assert b'198.18.0.10' not in ns(server, 'nft', 'list', 'set', 'inet', 'shadowborn', 'blocked_v4').stdout
            ns(client, 'ping', '-c', '1', '-W', '2', '198.18.0.10')
            print('PASS: filter replacement blocks a previously reachable destination, preserves unrelated table and reverses in the lab')
            exercise_dns_policy(base, bundle, server, client, ns, run)
            for address in ('10.89.0.1', '169.254.169.254'):
                assert ns(client, 'ping', '-c', '1', '-W', '1', address, ok=False).returncode
            ns(client, 'ip', 'addr', 'add', '10.89.0.3/32', 'dev', 'wg-shadowborn')
            assert ns(client, 'ping', '-I', '10.89.0.3', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            ns(client, 'ip', 'addr', 'del', '10.89.0.3/32', 'dev', 'wg-shadowborn')
            print('PASS: server host ICMP, metadata path and forged peer source denied')
            # Loss of the tunnel route must not expose the WAN default route.
            ns(client, 'ip', 'route', 'replace', 'default', 'via', '203.0.113.254', 'dev', 'wan0')
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            for kind in ('SOCK_DGRAM', 'SOCK_STREAM'):
                blocked = ns(client, sys.executable, '-c',
                    f'import socket; s=socket.socket(socket.AF_INET,socket.{kind}); s.settimeout(.4); s.connect(("198.18.0.53",53)); s.send(b"synthetic")', ok=False)
                assert blocked.returncode, 'physical DNS was not rejected'
            ns(client, 'ip', 'route', 'replace', 'default', 'dev', 'wg-shadowborn')
            ns(client, 'ping', '-c', '1', '-W', '2', '198.18.0.10')
            print('PASS: client refuses physical DNS TCP/UDP and fallback routes; marked WG endpoint still works')
            # Move the marked outer transport to a second synthetic physical link.
            run(['ip', 'link', 'add', 'alternate', 'type', 'veth', 'peer', 'name', 'wan1'])
            run(['ip', 'link', 'set', 'wan1', 'netns', str(client)])
            run(['ip', 'link', 'set', 'alternate', 'master', 'br-lab'])
            run(['ip', 'link', 'set', 'alternate', 'up'])
            ns(client, 'ip', 'link', 'set', 'wan0', 'down')
            ns(client, 'ip', 'link', 'set', 'wan1', 'up')
            ns(client, 'ip', 'addr', 'add', '203.0.113.4/24', 'dev', 'wan1')
            ns(client, 'ip', 'route', 'replace', '203.0.113.1/32', 'dev', 'wan1', 'src', '203.0.113.4')
            # Allow neighbour discovery and a WG retransmission on the new link.
            # A positive reply must coincide with the server learning the new endpoint.
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                reply = ns(client, 'ping', '-c1', '-W1', '198.18.0.10', ok=False)
                rows = ns(server, 'wg', 'show', 'wg-shadowborn', 'endpoints').stdout.splitlines()
                endpoints = dict(line.split() for line in rows)
                if reply.returncode == 0 and endpoints.get(public_client, b'').startswith(b'203.0.113.4:'):
                    break
                time.sleep(.2)
            else:
                raise RuntimeError('WG did not restore egress from the alternate uplink within 15 seconds')
            ns(client, 'ip', 'route', 'replace', 'default', 'via', '203.0.113.254', 'dev', 'wan1')
            assert ns(client, 'ping', '-c1', '-W1', '198.18.0.10', ok=False).returncode
            ns(client, 'ip', 'route', 'replace', 'default', 'dev', 'wg-shadowborn')
            print('PASS: outer WG roams to a second link; direct fallback on the new uplink is blocked')
            ns(server, 'wg', 'set', 'wg-shadowborn', 'peer' , public_client.decode(), 'remove')
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            print('PASS: explicit kernel peer removal stops lab traffic (not CLI live revoke)')
            ns(client, 'ip', 'link', 'del', 'wg-shadowborn')
            ns(client, 'ip', 'route', 'replace', 'default', 'via', '203.0.113.254', 'dev', 'wan1')
            assert ns(client, 'ping', '-c', '1', '-W', '1', '198.18.0.10', ok=False).returncode
            ns(client, 'ip', '-6', 'addr', 'add', '2001:db8::4/64', 'dev', 'wan1', 'nodad')
            assert ns(client, 'ping', '-6', '-c', '1', '-W', '1', '2001:db8::1', ok=False).returncode
            print('PASS: persistent client firewall remains after interface removal and server peer revocation')
            print('Namespace scope: synthetic traffic. Boot, sleep, SSH rollback and service journals use tests/vm/acceptance.py.')
        finally:
            for child in children:
                child.terminate()
            for child in children:
                child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        isolated()
        return
    missing = [name for name in ('unshare', 'nsenter', 'ip', 'wg', 'wg-quick', 'nft', 'ping', 'sysctl') if not shutil.which(name)]
    if missing:
        print('SKIPPED: missing lab tools: ' + ', '.join(missing))
        return
    probe = run(['unshare', '-Urn', 'true'], ok=False)
    if probe.returncode:
        print('SKIPPED: user/network namespaces unavailable')
        return
    if not (ROOT / 'target/debug/examples/render_lab').exists():
        raise RuntimeError('Build lab renderer: cargo build --locked -p shadowborn-core --example render_lab')
    environment = os.environ.copy()
    environment['SHADOWBORN_OUTER_NETNS'] = os.readlink('/proc/self/ns/net')
    result = subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside'], env=environment)
    if result.returncode:
        raise RuntimeError('Isolated namespace test failed; no host network was changed')


if __name__ == '__main__':
    main()
