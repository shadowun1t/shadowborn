#!/usr/bin/env python3
"""Check generated daemon configurations; never start host services."""
import json
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def main():
    checker = os.environ.get('SHADOWBORN_UNBOUND_CHECKCONF') or shutil.which('unbound-checkconf')
    unbound = os.environ.get('SHADOWBORN_UNBOUND') or shutil.which('unbound')
    with tempfile.TemporaryDirectory(prefix='shadowborn-config-check-') as temporary:
        base = Path(temporary)
        fixture = {'schema_version': 1,
                   'config': tomllib.loads((ROOT / 'config/server.example.toml').read_text()),
                   'server_private_key': 'B' * 42 + 'A=', 'server_public_key': 'C' * 42 + 'A=', 'peers': []}
        fixture['config']['filtering'] = tomllib.loads((ROOT / 'config/filtering.example.toml').read_text())
        def lp(text):
            return bytes([len(text)]) + text.encode()
        stamp = 'sdns://' + base64.urlsafe_b64encode(b'\x02'+b'\0'*8+lp('198.18.0.53')+b'\0'+lp('resolver.example')+lp('/dns-query')).decode().rstrip('=')
        fixture['config']['dns']['upstream'] = 'dnscrypt-proxy'
        fixture['config']['addons'] = {'dnscrypt': {'stamp': stamp}}
        source = base / 'fixture.json'
        source.write_text(json.dumps(fixture))
        source.chmod(0o600)
        bundle = base / 'bundle'
        subprocess.run([ROOT / 'target/debug/examples/render_lab', source, bundle], check=True)
        if checker:
            conf = bundle / 'unbound.conf'
            # Only relocate the working directory; resolver policy stays exact.
            conf.write_text(conf.read_text().replace('directory: "/etc/shadowborn"', f'directory: "{bundle}"'))
            subprocess.run([checker, conf], check=True)
            print('PASS: generated policy parsed by actual unbound-checkconf')
        else:
            print('SKIPPED: unbound-checkconf unavailable')
        proxy = os.environ.get('SHADOWBORN_DNSCRYPT') or shutil.which('dnscrypt-proxy')
        if shutil.which('systemd-analyze') and unbound and proxy:
            dns = bundle / 'shadowborn-dns.service'
            dns.write_text(dns.read_text().replace('/usr/sbin/unbound', str(unbound)))
            proxy_unit = bundle / 'shadowborn-dnscrypt.service'
            proxy_unit.write_text(proxy_unit.read_text().replace('/usr/sbin/dnscrypt-proxy', str(proxy)))
            subprocess.run(['systemd-analyze', 'verify', '--man=no',
                            bundle / 'shadowborn-firewall.service', dns, proxy_unit, bundle / 'shadowborn-client-lockdown.service'], check=True)
            print('PASS: generated systemd units verified (executable path relocated for extracted tools)')
        else:
            print('SKIPPED: systemd or Unbound executable unavailable')


if __name__ == '__main__':
    main()
