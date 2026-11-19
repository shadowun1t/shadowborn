#!/usr/bin/env python3
"""Unprivileged CLI and file-package tests. No network mutations."""
import json
import runpy
import re
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'target/release/shadowborn'


def run(args, ok=True):
    result = subprocess.run([str(x) for x in args], cwd=ROOT, text=True,
                            capture_output=True, timeout=60)
    assert (result.returncode == 0) == ok, (result.returncode, result.stderr[:300])
    return result


def main():
    config = ROOT / 'config/server.example.toml'
    with tempfile.TemporaryDirectory(prefix='shadowborn-files-') as temp:
        base = Path(temp)
        state = base / 'absent-state'
        cmd = [CLI, '--config', config, '--state-dir', state]
        for operation in (['plan', '--json'], ['init', '--dry-run'], ['apply', '--dry-run']):
            plan = json.loads(run(cmd + operation).stdout)
            assert plan['network_mutations'] is False
            assert plan['stage'] == 'PLAN'
            assert not state.exists()
        run(cmd + ['validate'])
        policy = ROOT / 'config/filtering.example.toml'
        checked = json.loads(run(cmd + ['policy', 'check', '--input', policy]).stdout)
        assert checked['policy_entries']['blocked_domains'] == 2
        assert not state.exists()
        if os.geteuid() != 0:
            run(cmd + ['policy', 'import', '--input', policy, '--confirm'], ok=False)
            assert not state.exists()
        setup = [CLI, 'setup', '--endpoint', '203.0.113.20', '--wan-interface', 'ens4',
                 '--admin-ipv4', '198.51.100.9/32', '--name', 'phone',
                 '--recipient', 'age1placeholder', '--output', base / 'setup']
        assert json.loads(run(setup + ['--dry-run']).stdout)['network_mutations'] is False
        assert not (base / 'setup').exists()
        for flag, value in (('--listen-port', '0'), ('--name', '../../escape'),
                            ('--wan-interface', 'ens4;id'), ('--admin-ipv4', '0.0.0.0/0'),
                            ('--recipient', 'not-a-recipient')):
            invalid = list(setup)
            if flag in invalid:
                invalid[invalid.index(flag) + 1] = value
            else:
                invalid += [flag, value]
            run(invalid + ['--dry-run'], ok=False)
        if os.geteuid() != 0:
            run(setup + ['--accept-server-key-generation'], ok=False)
            assert not (base / 'setup').exists()
        run(cmd + ['apply', '--confirm'], ok=False)
        run(cmd + ['client', 'lockdown', 'enable', '--confirm'], ok=False)
        assert json.loads(run(cmd + ['client', 'lockdown', 'status']).stdout)['enforced'] is None
        assert json.loads(run(cmd + ['dns', 'status']).stdout)['transport_verified'] == 'NOT_TESTED'
        if os.geteuid() != 0:
            run(cmd + ['init'], ok=False)
            assert not state.exists()
        print('PASS: dry runs create no state; unsupported/unprivileged mutations fail')
        # This guard runs before euid checks, namespace creation or any network
        # command. Calling the internal mode directly must never touch the host.
        lab = runpy.run_path(str(ROOT / 'tests/namespaces/shadowborn.py'), run_name='namespace_guard_test')
        marker = os.environ.pop('SHADOWBORN_OUTER_NETNS', None)
        try:
            for value in (None, os.readlink('/proc/self/ns/net')):
                if value is not None:
                    os.environ['SHADOWBORN_OUTER_NETNS'] = value
                try:
                    lab['isolated']()
                except RuntimeError as error:
                    assert 'outer network namespace marker' in str(error)
                else:
                    raise AssertionError('internal test mode did not reject host namespace')
        finally:
            os.environ.pop('SHADOWBORN_OUTER_NETNS', None)
            if marker is not None:
                os.environ['SHADOWBORN_OUTER_NETNS'] = marker
        print('PASS: direct/internal namespace test invocation cannot mutate host networking')
        dns_lab = runpy.run_path(str(ROOT / 'tests/namespaces/dns_policy.py'), run_name='dns_guard_test')
        try:
            dns_lab['guard']()
        except RuntimeError:
            pass
        else:
            raise AssertionError('DNS helper accepted the developer host namespace')
        stage = base / 'stage'
        install = [ROOT / 'scripts/install-server.sh', '--destdir', stage]
        update = [ROOT / 'scripts/update-server.sh', '--destdir', stage]
        uninstall = [ROOT / 'scripts/uninstall-server.sh', '--destdir', stage]
        run(install + ['--dry-run'])
        assert not stage.exists()
        run(install)
        assert not (stage / 'etc').exists()
        assert not (stage / 'usr/local/bin/shadowmist').exists()
        installed_docs = stage / 'usr/local/share/doc/shadowborn'
        for document in installed_docs.rglob('*.md'):
            for match in re.findall(r'\]\(([^)#\s]+)(?:#[^)]*)?\)|(?:href|src)="([^"#]+)"', document.read_text()):
                destination = next(part for part in match if part)
                if '://' in destination or destination.startswith(('mailto:', '#', '/')):
                    continue
                assert (document.parent / destination).exists(), (document.name, destination)
        run(install, ok=False)
        run(update)
        binary = stage / 'usr/local/bin/shadowborn'
        original = binary.read_bytes()
        binary.write_bytes(original + b'changed')
        run(update, ok=False)
        run(uninstall, ok=False)
        binary.write_bytes(original)
        run(uninstall)
        assert not binary.exists()
        print('PASS: staged install/update/uninstall, conflicts and legacy separation')
        client_stage = base / 'client-stage'
        client_install = [ROOT / 'scripts/install-client-lockdown.sh']
        destination = ['--destdir', client_stage]
        run(client_install + destination + ['--dry-run'])
        assert not client_stage.exists()
        run(client_install + destination)
        helper = client_stage / 'usr/local/bin/shadowborn-client-lockdown'
        assert helper.is_file() and not (client_stage / 'etc').exists()
        assert not (client_stage / 'usr/local/bin/shadowborn').exists()
        run([helper, '--help'])
        run(client_install + ['--update'] + destination)
        edited = client_stage/'usr/local/share/shadowborn-client/lockdown.nft.in'
        saved = edited.read_bytes()
        edited.write_bytes(saved + b'# administrator edit\n')
        run(client_install + ['--uninstall'] + destination, ok=False)
        assert helper.exists()
        edited.write_bytes(saved)
        run(client_install + ['--uninstall'] + destination)
        assert not helper.exists()
        print('PASS: separate client package, file-only install/update/removal and conflict refusal')
        outside = base / 'outside'
        outside.mkdir()
        (stage / 'usr/local/bin/shadowborn').symlink_to(outside / 'victim')
        run(install, ok=False)
        assert not (outside / 'victim').exists()
        print('PASS: symlink destination refused')


if __name__ == '__main__':
    main()
