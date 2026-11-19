#!/usr/bin/env python3
"""Root-only CLI exercised in a disposable chroot/user/network namespace.

All keys and profiles are synthetic lab identities and deleted with the fixture.
No root privileges or changes to host networking/services are requested.
"""
import json
import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    os.umask(0o077)
    age = os.environ.get('SHADOWBORN_AGE') or shutil.which('age')
    keygen = os.environ.get('SHADOWBORN_AGE_KEYGEN') or shutil.which('age-keygen')
    wg = shutil.which('wg')
    qrencode = shutil.which('qrencode')
    decoder = os.environ.get('SHADOWBORN_ZBARIMG') or shutil.which('zbarimg')
    if not all((age, keygen, wg, shutil.which('unshare'), shutil.which('chroot'))):
        print('SKIPPED: provisioning namespace requires wg, age, age-keygen, unshare, chroot')
        return
    if subprocess.run(['unshare', '-Urn', 'true'], capture_output=True).returncode:
        print('SKIPPED: user/network namespaces unavailable')
        return
    with tempfile.TemporaryDirectory(prefix='shadowborn-provisioning-') as temporary:
        jail = Path(temporary)
        for path in ('usr/local/bin', 'usr/bin', 'etc/shadowborn', 'var/lib', 'root', 'dev'):
            (jail / path).mkdir(parents=True, exist_ok=True)
        (jail / 'root').chmod(0o700)
        for device in ('null', 'urandom'):
            (jail / 'dev' / device).touch()
        binaries = ((ROOT / 'target/release/shadowborn', 'usr/local/bin/shadowborn'),
                    (Path(wg), 'usr/bin/wg'), (Path(age), 'usr/bin/age'))
        if qrencode:
            binaries += ((Path(qrencode), 'usr/bin/qrencode'),)
        for source, destination in binaries:
            shutil.copy2(source, jail / destination)
            linked = subprocess.run(['ldd', str(source)], capture_output=True, text=True, check=True).stdout
            for library in re.findall(r'(/[^\s()]+)', linked):
                target = jail / library.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(library, target)
        shutil.copy2(ROOT / 'config/server.example.toml', jail / 'etc/shadowborn/config.toml')
        identity = jail / 'root/operator.agekey'
        with identity.open('wb') as stream:
            subprocess.run([keygen], stdout=stream, stderr=subprocess.DEVNULL, check=True)
        identity.chmod(0o600)
        recipient = subprocess.run([keygen, '-y', str(identity)], capture_output=True, text=True, check=True).stdout.strip()

        outputs = []

        def cli(*args, ok=True):
            result = subprocess.run(['unshare', '-Urnm', '--propagation', 'private', 'sh', '-c',
                                     'mount --bind /dev/null "$1/dev/null" && mount --bind /dev/urandom "$1/dev/urandom" && exec chroot "$@"',
                                     'lab-runner', str(jail), '/usr/local/bin/shadowborn', *args], capture_output=True, text=True, timeout=45)
            assert (result.returncode == 0) == ok, ('CLI operation failed', args[0], result.returncode, result.stderr[:180])
            outputs.append(result.stdout + result.stderr)
            return result

        def decrypt(path):
            encrypted = path.read_bytes()
            assert encrypted.startswith(b'age-encryption.org/')
            return subprocess.run([age, '-d', '-i', str(identity)], input=encrypted,
                                  capture_output=True, check=True).stdout

        def verify_imports(base, profile_name, qr_name, stored):
            profile = decrypt(base / profile_name)
            png = decrypt(base / qr_name)
            assert png.startswith(b'\x89PNG\r\n\x1a\n')
            assert b'<DEVICE_PRIVATE_KEY>' not in profile
            assert b'AllowedIPs = 0.0.0.0/0, ::/0' in profile
            private = re.search(rb'^PrivateKey = (.+)$', profile, re.M).group(1)
            public = subprocess.run([wg, 'pubkey'], input=private + b'\n', capture_output=True, check=True).stdout.decode().strip()
            peer = next(p for p in stored['peers'] if p['public_key'] == public)
            assert f'PresharedKey = {peer["psk"]}'.encode() in profile
            assert private.decode() not in json.dumps(stored)
            assert all(private.decode() not in output and peer['psk'] not in output for output in outputs)
            if decoder:
                # No D-Bus broadcast of the decoded secret, and no terminal output.
                decoded = subprocess.run([decoder, '--nodbus', '--quiet', '--raw', '-'],
                                         input=png, capture_output=True, check=True).stdout
                assert decoded == profile + b'\n', 'QR payload differs from the importable profile'
            else:
                print('SKIPPED: independent QR decoding requires zbarimg')

        cli('init', '--dry-run')
        assert not (jail / 'var/lib/shadowborn').exists()
        cli('init')
        cli('init', ok=False)
        policy_file = jail / 'root/filtering.toml'
        policy_file.write_text('blocked_domains = ["ads.example"]\nallowed_domains = ["safe.ads.example"]\nblocked_ipv4 = ["198.18.1.0/24"]\n[[local_records]]\nname = "gateway.shadowborn.home.arpa"\naddress = "10.89.0.1"\n')
        state_path = jail / 'var/lib/shadowborn/state.json'
        before_policy = state_path.read_bytes()
        cli('policy', 'check', '--input', '/root/filtering.toml')
        cli('policy', 'import', '--input', '/root/filtering.toml', ok=False)
        cli('policy', 'import', '--input', '/root/filtering.toml', '--dry-run')
        assert state_path.read_bytes() == before_policy
        cli('policy', 'import', '--input', '/root/filtering.toml', '--confirm')
        assert json.loads(cli('policy', 'show').stdout)['blocked_domains'] == ['ads.example']
        assert json.loads(cli('plan').stdout)['policy_entries']['blocked_domains'] == 1
        # The initialized state's policy is authoritative, not the old config file.
        cli('render', '--output', '/root/filtered')
        assert 'always_nxdomain' in (jail / 'root/filtered/unbound.conf').read_text()
        assert '198.18.1.0/24' in (jail / 'root/filtered/server.nft').read_text()
        blocklist = jail / 'root/selected.list'
        blocklist.write_text('0.0.0.0 ads.example telemetry.example\n')
        cli('policy', 'import-blocklist', '--kind', 'domains', '--input', '/root/selected.list', '--confirm')
        assert len(json.loads(cli('policy', 'show').stdout)['blocked_domains']) == 2
        current_policy = state_path.read_bytes()
        blocklist.write_text('valid.example\n||PRIVATE_INVALID_FIXTURE^\n')
        result = cli('policy', 'import-blocklist', '--kind', 'domains', '--input', '/root/selected.list', '--confirm', ok=False)
        assert 'PRIVATE_INVALID_FIXTURE' not in result.stderr
        assert state_path.read_bytes() == current_policy
        blocklist.write_text('198.18.2.1\n')
        cli('policy', 'import-blocklist', '--kind', 'ipv4', '--input', '/root/selected.list', '--confirm')
        assert json.loads(cli('policy', 'show').stdout)['blocked_ipv4'] == ['198.18.2.1/32']
        policy_file.write_text('')
        cli('policy', 'import', '--input', '/root/filtering.toml', '--confirm')
        assert json.loads(cli('plan').stdout)['policy_entries']['blocked_domains'] == 0
        print('PASS: offline filtering import, dry-run, canonical-state planning, invalid-list atomicity and no activity output')
        def lp(value):
            value = value.encode()
            return bytes([len(value)]) + value
        stamp = 'sdns://' + base64.urlsafe_b64encode(b'\x02' + b'\0'*8 + lp('198.18.0.53') + b'\0' + lp('resolver.example') + lp('/dns-query')).decode().rstrip('=')
        (jail / 'root/upstream.stamp').write_text(stamp)
        before_dns = state_path.read_bytes()
        cli('dns', 'configure', '--stamp-file', '/root/upstream.stamp', '--dry-run')
        assert state_path.read_bytes() == before_dns
        cli('dns', 'configure', '--stamp-file', '/root/upstream.stamp', '--confirm')
        assert json.loads(cli('dns', 'status').stdout)['configured_upstream'] == 'dnscrypt-proxy'
        cli('render', '--output', '/root/doh-review')
        assert 'forward-tls-upstream: no' in (jail / 'root/doh-review/unbound.conf').read_text()
        assert (jail / 'root/doh-review/shadowborn-dnscrypt.service').is_file()
        before_dns = state_path.read_bytes()
        (jail / 'root/upstream.stamp').write_text('sdns://BAD')
        cli('dns', 'configure', '--stamp-file', '/root/upstream.stamp', '--confirm', ok=False)
        assert state_path.read_bytes() == before_dns
        cli('dns', 'configure', '--quad9-dot', '--confirm')
        cli('client', 'lockdown', 'render', '--output', '/root/client-lockdown')
        assert (jail / 'root/client-lockdown/lockdown.nft').is_file()
        cli('client', 'lockdown', 'render', '--output', '/root/client-lockdown', ok=False)
        print('PASS: DNS configuration dry-run/atomic rejection/restore and file-only client policy export')
        private = subprocess.run([wg, 'genkey'], capture_output=True, check=True).stdout
        public = subprocess.run([wg, 'pubkey'], input=private, capture_output=True, check=True).stdout.decode().strip()
        cli('peer', 'add', '--name', 'synthetic', '--public-key', public)
        cli('peer', 'add', '--name', 'duplicate', '--public-key', public, ok=False)
        cli('client', 'profile', '--name', 'synthetic', '--output', '/root/client.template')
        assert '<DEVICE_PRIVATE_KEY>' in (jail / 'root/client.template').read_text()
        assert 'PersistentKeepalive' not in (jail / 'root/client.template').read_text()
        cli('client', 'profile', '--strict', '--nat-keepalive', '--name', 'synthetic', '--output', '/root/nat.template')
        assert 'PersistentKeepalive = 25' in (jail / 'root/nat.template').read_text()
        cli('render', '--output', '/root/review')
        cli('backup', '--recipient', recipient, '--output', '/root/backup.age')
        assert (jail / 'root/backup.age').read_bytes().startswith(b'age-encryption.org/')
        cli('peer', 'revoke', '--name', 'synthetic', '--confirm')
        cli('restore', '--input', '/root/backup.age', '--identity', '/root/operator.agekey', '--dry-run')
        cli('restore', '--input', '/root/backup.age', '--identity', '/root/operator.agekey', '--confirm')
        peers = json.loads(cli('peer', 'list').stdout)
        assert peers[0]['status'] == 'revoked'
        cli('client', 'profile', '--name', 'synthetic', '--output', '/root/revoked.template', ok=False)
        cli('peer', 'issue', '--name', 'convenience', '--recipient', recipient,
            '--bundle', '/root/issued.age', '--nat-keepalive', '--accept-server-key-generation')
        encrypted = (jail / 'root/issued.age').read_bytes()
        decoded = subprocess.run([age, '-d', '-i', str(identity)], input=encrypted, capture_output=True, check=True).stdout
        assert b'<DEVICE_PRIVATE_KEY>' not in decoded and b'AllowedIPs = 0.0.0.0/0, ::/0' in decoded
        assert b'PersistentKeepalive = 25' in decoded
        if qrencode:
            state_path = jail / 'var/lib/shadowborn/state.json'
            before = state_path.read_bytes()
            issue = ['peer', 'issue', '--name', 'phone', '--recipient', recipient,
                     '--bundle', '/root/phone.conf.age', '--qr-bundle', '/root/phone.png.age']
            cli(*issue, ok=False)
            assert state_path.read_bytes() == before
            assert not (jail / 'root/phone.conf.age').exists()
            occupied = jail / 'root/phone.png.age'
            occupied.write_bytes(b'existing operator file')
            cli(*issue, '--accept-server-key-generation', ok=False)
            assert occupied.read_bytes() == b'existing operator file'
            assert not (jail / 'root/phone.conf.age').exists()
            assert state_path.read_bytes() == before
            occupied.unlink()
            (jail / 'usr/bin/qrencode').rename(jail / 'usr/bin/qrencode.saved')
            cli(*issue, '--accept-server-key-generation', ok=False)
            assert state_path.read_bytes() == before
            assert not (jail / 'root/phone.conf.age').exists()
            (jail / 'usr/bin/qrencode.saved').rename(jail / 'usr/bin/qrencode')
            cli(*issue, '--accept-server-key-generation')
            verify_imports(jail / 'root', 'phone.conf.age', 'phone.png.age', json.loads(state_path.read_text()))
            for artifact in ('phone.conf.age', 'phone.png.age'):
                assert (jail / 'root' / artifact).stat().st_mode & 0o777 == 0o600
            cli(*issue, '--accept-server-key-generation', ok=False)

            policy_file.write_text('blocked_domains = ["ads.example"]\n')
            setup = ['setup', '--policy', '/root/filtering.toml', '--endpoint', '203.0.113.20', '--wan-interface', 'ens4',
                     '--admin-ipv4', '198.51.100.9/32', '--listen-port', '51821',
                     '--ssh-port', '2222', '--tunnel-ipv4', '10.90.0.1/24',
                     '--name', 'first', '--recipient', recipient, '--output', '/root/prepared']
            plan = json.loads(cli(*setup, '--dry-run').stdout)
            assert plan['network_mutations'] is False and plan['listen_port'] == 51821
            assert plan['wan_interface'] == 'ens4' and plan['ssh_port'] == 2222
            assert not (jail / 'root/prepared').exists()
            cli(*setup, ok=False)
            assert not (jail / 'root/prepared').exists()
            (jail / 'usr/bin/qrencode').rename(jail / 'usr/bin/qrencode.saved')
            cli(*setup, '--accept-server-key-generation', ok=False)
            assert not (jail / 'root/prepared').exists()
            (jail / 'usr/bin/qrencode.saved').rename(jail / 'usr/bin/qrencode')
            cli(*setup, '--accept-server-key-generation')
            prepared = jail / 'root/prepared'
            stored_setup = json.loads((prepared / 'state/state.json').read_text())
            verify_imports(prepared, 'client.conf.age', 'client.png.age', stored_setup)
            assert stored_setup['config']['server']['endpoint'] == '203.0.113.20'
            assert stored_setup['peers'][0]['address'] == '10.90.0.2'
            assert stored_setup['config']['filtering']['blocked_domains'] == ['ads.example']
            assert sorted(p.name for p in prepared.iterdir()) == [
                'NEXT-STEPS.txt', 'client.conf.age', 'client.png.age', 'config.toml', 'server', 'state']
            for path in (prepared, *prepared.rglob('*')):
                assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
            assert sorted(p.name for p in (prepared / 'state').iterdir()) == ['lock', 'state.json']
            original = (prepared / 'state/state.json').read_bytes()
            cli(*setup, '--accept-server-key-generation', ok=False)
            assert (prepared / 'state/state.json').read_bytes() == original
            cli('--config', '/root/prepared/config.toml', '--state-dir', '/root/prepared/state', 'validate')
            cli('--state-dir', '/root/prepared/state', 'peer', 'revoke', '--name', 'first', '--confirm')
            assert json.loads((prepared / 'state/state.json').read_text())['peers'][0]['status'] == 'revoked'
            print('PASS: encrypted QR issuance/setup, secret custody, permissions, output conflicts and failure cleanup')
            if decoder:
                print('PASS: independent PNG QR decoding matches the complete standard WireGuard profile byte-for-byte')
        else:
            print('SKIPPED: QR enrollment/setup tests require qrencode')
        (jail / 'etc/wireguard').mkdir()
        (jail / 'etc/wireguard/wg-shadowborn.conf').write_text('# deployed marker')
        cli('peer', 'revoke', '--name', 'convenience', '--confirm', ok=False)
        cli('render', '--output', '/root/deployed', ok=False)
        cli('policy', 'import', '--input', '/root/filtering.toml', '--confirm', ok=False)
        if qrencode:
            cli(*setup[:-1], '/root/deployed-setup', '--accept-server-key-generation', ok=False)
            assert not (jail / 'root/deployed-setup').exists()
        stored = json.loads((jail / 'var/lib/shadowborn/state.json').read_text())
        redacted = cli('peer', 'show', '--name', 'convenience', '--redacted').stdout
        assert stored['server_private_key'] not in redacted
        assert all(p['psk'] is None or p['psk'] not in redacted for p in stored['peers'])
        assert sorted(p.name for p in (jail / 'var/lib/shadowborn').iterdir()) == ['lock', 'state.json']
        print('PASS: isolated root CLI init/enrollment/export/encrypted issue/backup/restore/revocation and deployed-host guard')
        print('PASS: no activity-history files; secret output redacted; host filesystem/network untouched')


if __name__ == '__main__':
    main()
