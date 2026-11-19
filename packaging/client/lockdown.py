#!/usr/bin/python3 -I
"""Install a timed client firewall trial and commit persistent systemd provider gates."""
import argparse
import base64
import configparser
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ETC = Path('/etc/shadowborn-client')
STATE = ETC / 'state.json'
ASSETS = Path('/usr/local/share/shadowborn-client')
BIN = '/usr/local/bin/shadowborn-client-lockdown'
UNITS = Path('/etc/systemd/system')
UNIT = 'shadowborn-client-lockdown.service'
TABLE = 'shadowborn_client'
RESUME = 'shadowborn-client-resume.service'
TRIAL_RECOVERY = 'shadowborn-client-trial-recovery.service'
RECOVERY_LINK = UNITS / 'sysinit.target.wants' / TRIAL_RECOVERY
SLEEP_SERVICES = ('systemd-suspend.service', 'systemd-hibernate.service', 'systemd-hybrid-sleep.service',
                  'systemd-suspend-then-hibernate.service')
PROVIDERS = ('NetworkManager.service', 'systemd-networkd.service', 'networking.service')
DEPENDENCY = f'[Unit]\nRequires={UNIT}\nAfter={UNIT}\n'
QUIET = '[Service]\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n'
LIMIT = 120
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, data=None, required=True):
    result = subprocess.run(args, input=data, capture_output=True, text=True,
                            env=ENV, timeout=20, check=False)
    if required:
        check(result.returncode == 0, f'{args[0]} {args[1]} failed')
    return result


def trusted(path, private=False):
    for directory in path.parents:
        mode = directory.lstat()
        check(stat.S_ISDIR(mode.st_mode) and mode.st_uid == 0 and not mode.st_mode & 0o022,
              'Untrusted parent directory')
    info = path.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
          and not info.st_mode & (0o077 if private else 0o022), 'Untrusted file')
    return path.read_text()


def flush(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, content, mode, new=False):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            tmp.write(content.encode())
            tmp.flush()
            os.fchmod(tmp.fileno(), mode)
            os.fsync(tmp.fileno())
            if new:
                os.link(tmp_path, path)
            else:
                os.replace(tmp_path, path)
        finally:
            tmp_path.unlink(missing_ok=True)
    flush(path.parent)


def safe_dir(path, mode):
    for entry in (path, *path.parents):
        info = entry.lstat()
        check(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & (mode if entry == path else 0o022),
              'Unsafe configuration directory')


@contextmanager
def locked(create=False):
    if create and not ETC.exists():
        safe_dir(ETC.parent, 0o022)
        ETC.mkdir(mode=0o700, exist_ok=True)
        flush(ETC.parent)
    safe_dir(ETC, 0o077)
    # The boot service runs with ProtectSystem=strict. Only the trial creates this lock.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(ETC / 'lock', flags | (os.O_CREAT if create else 0), 0o600)
    try:
        info = os.fstat(fd)
        check(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
              and not info.st_mode & 0o077, 'Unsafe client transaction lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def name(text):
    if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,14}', text) or text == 'lo':
        raise ValueError('Invalid interface name')
    return text


def profile(interface):
    path = Path('/etc/wireguard') / f'{name(interface)}.conf'
    safe_dir(path.parent, 0o077)
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=('#',))
    # Parse errors can include entire secret lines. Never propagate their text.
    try:
        content = trusted(path, private=True)
        parser.read_string(content)
        check(not parser.defaults() and parser.sections() == ['Interface', 'Peer'], 'Expected one WG peer')
        local, peer = parser['Interface'], parser['Peer']
        check(set(local) <= {'address', 'privatekey', 'dns', 'fwmark', 'mtu'} and
              set(peer) <= {'publickey', 'presharedkey', 'allowedips', 'endpoint', 'persistentkeepalive'},
              'Unexpected directive in strict profile')
        check(int(local['fwmark'], 0) == 51820, 'Use FwMark = 51820 in the strict profile')
        check({x.strip() for x in peer['allowedips'].split(',')} == {'0.0.0.0/0', '::/0'},
              'Full IPv4 and IPv6 routes required')
        for value in (local['privatekey'], peer['publickey'], peer['presharedkey']):
            decoded = base64.b64decode(value, validate=True)
            check(len(decoded) == 32 and any(decoded), 'Invalid WireGuard key')
        addr = ipaddress.IPv4Interface(local['address'])
        dns = ipaddress.IPv4Address(local['dns'])
        check(addr.network.prefixlen == 32 and dns != addr.ip and
              any(dns in ipaddress.ip_network(cidr) and addr.ip in ipaddress.ip_network(cidr)
                  for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')),
              'Use the assigned tunnel address and tunnel-side resolver')
        host, port = peer['endpoint'].rsplit(':', 1)
        endpoint = ipaddress.IPv4Address(host)
        check(not (endpoint.is_multicast or endpoint.is_link_local or endpoint.is_loopback
                   or endpoint.is_unspecified or endpoint == ipaddress.IPv4Address('255.255.255.255')),
              'Invalid pinned IPv4 endpoint')
        port = int(port)
        check(0 < port <= 65535, 'Invalid endpoint port')
    except (configparser.Error, ValueError, KeyError):
        raise RuntimeError('Invalid strict WireGuard profile; credentials suppressed') from None
    return str(endpoint), port, peer['publickey'], hashlib.sha256(content.encode()).hexdigest()


def owned_state():
    try:
        return json.loads(trusted(STATE, private=True))
    except FileNotFoundError:
        return None


def save(state, new=False):
    put(STATE, json.dumps(state), 0o600, new)


def rules(s):
    dhcp = ''.join(f'        oifname "{name(nic)}" ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept\n'
                   for nic in s['dhcp'])
    return (trusted(ASSETS / 'lockdown.nft.in')
            .replace('@OWNER@', 'shadowborn-' + s['transaction'])
            .replace('@INTERFACE@', name(s['interface'])).replace('@ENDPOINT@', s['endpoint'])
            .replace('@PORT@', str(s['port'])).replace('@DHCP@', dhcp))


def privacy_file(s):
    return UNITS / f'wg-quick@{name(s["interface"])}.service.d' / '40-shadowborn-privacy.conf'


def create_unit(path, content):
    if not path.parent.exists():
        safe_dir(path.parent.parent, 0o022)
        path.parent.mkdir(mode=0o755, exist_ok=True)
        flush(path.parent.parent)
    safe_dir(path.parent, 0o022)
    put(path, content, 0o644, new=True)


def files(s):
    gated = (*PROVIDERS, 'ifup@.service', 'network-pre.target', f'wg-quick@{name(s["interface"])}.service')
    result = {privacy_file(s): QUIET, UNITS / UNIT: trusted(ASSETS / UNIT)}
    result[UNITS / RESUME] = (
        '[Unit]\nDescription=Restore active Shadowborn client routing after wake\n'
        + 'After=' + ' '.join(SLEEP_SERVICES) + '\n\n[Service]\nType=oneshot\n'
        + f'ExecStart={BIN} resume\nStandardOutput=null\nStandardError=null\nLimitCORE=0\n'
        + 'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
        + 'CapabilityBoundingSet=CAP_NET_ADMIN\nRestrictAddressFamilies=AF_NETLINK AF_UNIX\n')
    for unit in SLEEP_SERVICES:
        result[UNITS / (unit + '.d') / '50-shadowborn-client.conf'] = (
            f'[Service]\nExecStartPost=-/usr/bin/systemctl --quiet --no-block start {RESUME}\n')
    for unit in gated:
        result[UNITS / (unit + '.d') / '50-shadowborn-client.conf'] = DEPENDENCY
    return result


def recovery_unit(s):
    return ('[Unit]\nDescription=Roll back an uncommitted Shadowborn client trial at boot\n'
            'DefaultDependencies=no\nAfter=local-fs.target\n'
            + 'Before=network-pre.target ' + ' '.join(PROVIDERS) + f' wg-quick@{name(s["interface"])}.service\n'
            + '\n[Service]\nType=oneshot\n'
            + f'ExecStart={BIN} recover --transaction {s["transaction"]}\n'
            + 'StandardOutput=null\nStandardError=null\nLimitCORE=0\nNoNewPrivileges=yes\n'
            + 'ProtectSystem=strict\nReadWritePaths=/etc/shadowborn-client /etc/systemd/system\n'
            + 'ProtectHome=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_NETLINK AF_UNIX\n'
            + 'CapabilityBoundingSet=CAP_NET_ADMIN\n')


def arm_boot_recovery(s):
    create_unit(UNITS / TRIAL_RECOVERY, recovery_unit(s))
    RECOVERY_LINK.parent.mkdir(mode=0o755, exist_ok=True)
    safe_dir(RECOVERY_LINK.parent, 0o022)
    RECOVERY_LINK.symlink_to(UNITS / TRIAL_RECOVERY)
    flush(RECOVERY_LINK.parent)
    flush(UNITS)


def check_boot_recovery(s):
    path = UNITS / TRIAL_RECOVERY
    if os.path.lexists(path):
        check(trusted(path) == recovery_unit(s), 'Changed boot recovery unit requires console review')
    if os.path.lexists(RECOVERY_LINK):
        safe_dir(RECOVERY_LINK.parent, 0o022)
        check(RECOVERY_LINK.is_symlink() and RECOVERY_LINK.readlink() == path, 'Boot recovery link conflict')


def detach_boot_recovery(s):
    check_boot_recovery(s)
    path = UNITS / TRIAL_RECOVERY
    if os.path.lexists(RECOVERY_LINK):
        RECOVERY_LINK.unlink()
        flush(RECOVERY_LINK.parent)
    if os.path.lexists(path):
        path.unlink()
        flush(UNITS)


def table():
    tables = json.loads(command('nft', '-j', 'list', 'tables').stdout)['nftables']
    if not any(row.get('table', {}).get('family') == 'inet' and
               row['table'].get('name') == TABLE for row in tables):
        return None
    rows = json.loads(command('nft', '-j', '-s', 'list', 'table', 'inet', TABLE).stdout)['nftables']
    return [row for row in rows if 'metainfo' not in row]


def verify_table(s, rows):
    check(rows is not None and any(row.get('table', {}).get('comment') == 'shadowborn-' + s['transaction']
                                   for row in rows), 'Client firewall table ownership conflict')
    for row in rows:
        # An operator-approved LAN exception exists only in the kernel. Never
        # fingerprint its address or its decreasing expiration time.
        if row.get('set', {}).get('name') == 'temporary_lan':
            row['set'].pop('elem', None)
            row['set'].pop('count', None)
        for attrs in row.values():
            attrs.pop('handle', None)
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    check(s.get('signature', digest) == digest, 'Client firewall rules differ from the trial')
    return digest


def new_batch(s):
    return f'create table inet {TABLE} {{ comment "shadowborn-{s["transaction"]}"; }}\n' + rules(s)


def install_rules(s):
    check(hashlib.sha256(rules(s).encode()).hexdigest() == s['rules_hash'],
          'Installed policy template differs from the reviewed trial')
    current = table()
    if current is not None:
        return verify_table(s, current)
    batch = new_batch(s)
    command('nft', '-c', '-f', '-', data=batch)
    command('nft', '-f', '-', data=batch)
    return verify_table(s, table())


def unit_property(unit, prop):
    return command('systemctl', 'show', '-p', prop, '--value', unit).stdout.strip()


def preflight(s):
    check(Path('/proc/1/comm').read_text().strip() == 'systemd', 'Client activation requires systemd')
    check(not Path('/etc/systemd/system/shadowborn-firewall.service').exists(), 'Gateway role detected')
    check(any(unit_property(unit, 'ActiveState') == 'active' for unit in PROVIDERS),
          'No supported active network provider')
    for unit in ('nftables', 'ufw', 'firewalld', 'docker', 'dhcpcd', 'connman', 'shadowmist'):
        check(unit_property(unit + '.service', 'ActiveState') not in ('active', 'activating')
              and unit_property(unit + '.service', 'UnitFileState') not in ('enabled', 'enabled-runtime'),
              'Resolve conflicting service before strict activation: ' + unit)
    check(not any(arg.startswith(('ip=', 'rd.neednet=1', 'root=/dev/nfs'))
                  for arg in Path('/proc/cmdline').read_text().split()), 'Early boot network detected')
    check(shutil.which('resolvconf', path=ENV['PATH']), 'WG DNS requires resolvconf integration')
    check(not command('wg', 'show', 'interfaces').stdout.strip(), 'Start with WG interfaces down')
    check(unit_property(f'wg-quick@{s["interface"]}.service', 'UnitFileState') == 'disabled',
          'Start with WG automatic startup disabled; enable it after commit')
    check(not Path('/sys/class/net', s['interface']).exists(), 'Tunnel interface name already in use')
    for procfile in ('/proc/net/ip_tables_names', '/proc/net/ip6_tables_names'):
        path = Path(procfile)
        check(not path.exists() or not path.read_text().strip(), 'Legacy iptables overlap requires review')
    check(table() is None, 'Client table already exists')
    for family in ('-4', '-6'):
        check(not command('ip', family, 'route', 'show', 'table', '51820', required=False).stdout.strip(),
              'WG routing table already in use')
        policy = command('ip', family, 'rule', 'show').stdout
        check('fwmark' not in policy and 'lookup 51820' not in policy, 'Conflicting policy routing')
    existing = json.loads(command('nft', '-j', 'list', 'ruleset').stdout)['nftables']
    check(not any('hook' in row.get('chain', {}) or 'flowtable' in row for row in existing),
          'Existing firewall hooks require independent compatibility review')
    for path in files(s):
        check(not os.path.lexists(path), 'Existing unit or provider drop-in')
    check(not os.path.lexists(RECOVERY_LINK) and not os.path.lexists(UNITS / TRIAL_RECOVERY)
          and all(unit_property(unit, 'LoadState') == 'not-found' for unit in (UNIT, RESUME, TRIAL_RECOVERY)),
          'Existing client unit or recovery link')
    command('nft', '-c', '-f', '-', data=new_batch(s))


def remove(s):
    check_boot_recovery(s)
    current = table()
    if current is not None:
        verify_table(s, current)
    owned = files(s)
    for path, value in owned.items():
        if os.path.lexists(path):
            check(trusted(path) == value, 'Modified unit preserved; inspect from console')
    if s['phase'] != 'committed' and unit_property(f'wg-quick@{s["interface"]}.service', 'ActiveState') == 'active':
        # Preflight required an absent interface. Undo the trial's WG start
        # with its original profile and quiet service settings still in place.
        check(profile(s['interface'])[3] == s['profile_hash'], 'Trial WG profile changed')
        command('systemctl', 'stop', f'wg-quick@{s["interface"]}.service')
    for path in reversed(owned):
        if os.path.lexists(path):
            path.unlink()
            flush(path.parent)
    if current is not None:
        command('nft', 'delete', 'table', 'inet', TABLE)
    detach_boot_recovery(s)
    command('systemctl', 'daemon-reload')
    # The detached firewall unit has no ExecStop that changes the kernel.
    command('systemctl', '--no-block', 'stop', UNIT, required=False)
    STATE.unlink()
    flush(ETC)
    command('systemctl', '--no-block', 'stop', timer(s) + '.timer', required=False)


def timer(s):
    return 'shadowborn-client-rollback-' + s['transaction']


def gated(s):
    return all(trusted(path) == value for path, value in files(s).items()) and all(
        UNIT in unit_property(provider, 'Requires').split() and UNIT in unit_property(provider, 'After').split()
        for provider in (*PROVIDERS, f'wg-quick@{s["interface"]}.service')
        if unit_property(provider, 'LoadState') == 'loaded')


def routing_rules():
    for family in ('-4', '-6'):
        rows = json.loads(command('ip', '-j', family, 'rule', 'show').stdout)
        if not (any(row.get('table') == 'main' and row.get('suppress_prefixlen') == 0 for row in rows)
                and any(str(row.get('table')) == '51820' and 'not' in row
                        and int(str(row.get('fwmark', '0')), 0) == 51820 for row in rows)):
            return False
    return True


def resume():
    # Some providers discard wg-quick's routing rules while reconfiguring the uplink.
    # Keep the firewall enforced while the standard unit repairs its own routes.
    with locked():
        s = owned_state()
        if not s or s['phase'] != 'committed':
            return
        install_rules(s)
        unit = f'wg-quick@{name(s["interface"])}.service'
    for _ in range(10):
        time.sleep(.5)
        if unit_property(unit, 'ActiveState') != 'active':
            return
        if not routing_rules():
            command('systemctl', 'try-restart', unit)
            check(routing_rules(), 'WG policy routing still unavailable after wake')
            return


def run(args):
    if args.action == 'status' and not ETC.exists():
        print(json.dumps({'state': 'NOT_INSTALLED', 'enforced': None}))
        return
    check(os.geteuid() == 0, 'Root is required for client profile, firewall and unit inspection')
    if args.action == 'resume':
        resume()
        return
    if args.action in ('plan', 'enable'):
        endpoint, port, _, profile_hash = profile(args.interface)
        check(args.interface not in args.dhcp_interface, 'DHCP exception must name a physical uplink')
        s = dict(transaction=secrets.token_hex(16), interface=args.interface, endpoint=endpoint,
                 port=port, dhcp=sorted(set(args.dhcp_interface)), phase='trial', profile_hash=profile_hash)
        if args.action == 'plan':
            preflight(s)
            print(json.dumps({'interface': s['interface'], 'endpoint': endpoint, 'udp_port': port,
                              'dhcp_broadcast_interfaces': s['dhcp'], 'rollback_seconds': LIMIT,
                              'provider_dependencies': [str(p) for p in files(s)], 'network_mutations': False}))
            return
        check(args.confirm and args.console_verified, 'Use --confirm --console-verified from a tested console')
        check(Path(__file__) == Path(BIN) and trusted(Path(BIN)), 'Run the installed client helper')
        with locked(create=True):
            check(owned_state() is None, 'Client transaction exists; inspect status')
            preflight(s)
            # Both the independent timer and boot recovery precede kernel changes.
            command('systemd-run', '--quiet', '--collect', '--unit=' + timer(s), f'--on-active={LIMIT}s',
                    '--timer-property=AccuracySec=1s', '--property=StandardOutput=null',
                    '--property=StandardError=null', '--property=Restart=on-failure', BIN, 'recover',
                    '--transaction', s['transaction'])
            s['rules_hash'] = hashlib.sha256(rules(s).encode()).hexdigest()
            save(s, new=True)
            arm_boot_recovery(s)
            create_unit(privacy_file(s), QUIET)
            command('systemctl', 'daemon-reload')
            s['signature'] = install_rules(s)
            save(s)
            print(json.dumps({'state': 'TRIAL', 'transaction': s['transaction'], 'rollback_seconds': LIMIT,
                              'next': 'Start WG and test DNS and egress before commit. Timeout restores direct access.'}))
        return

    if not ETC.exists() and args.action == 'recover':
        return
    with locked():
        s = owned_state()
        if args.action == 'recover':
            if s and s['transaction'] == args.transaction:
                if s['phase'] == 'committed':
                    detach_boot_recovery(s)
                else:
                    remove(s)
            return
        if args.action == 'status':
            if not s:
                print(json.dumps({'state': 'INACTIVE', 'enforced': False if table() is None else None}))
                return
            try:
                existing = table()
                exception = any(row.get('set', {}).get('name') == 'temporary_lan' and row['set'].get('elem')
                                for row in existing or [])
                verify_table(s, existing)
                boot = s['phase'] == 'committed' and gated(s)
                print(json.dumps({'state': 'NOT_STRICT' if exception else s['phase'].upper(), 'transaction': s['transaction'],
                                  'enforced': not exception, 'boot_dependencies': boot, 'egress': 'NOT_TESTED'}))
            except (OSError, RuntimeError):
                print(json.dumps({'state': 'DRIFT_OR_UNAVAILABLE', 'enforced': None, 'boot_dependencies': None}))
            return
        check(s is not None, 'No owned client configuration')
        if args.action == 'disable':
            check(args.confirm, '--confirm required to restore direct access')
            remove(s)
            print('Client firewall removed. Direct network access is possible.')
        elif args.action == 'temporary-lan':
            check(args.confirm and s['phase'] == 'committed', 'Committed policy and --confirm required')
            check(0 < args.seconds <= 300 and args.uplink != s['interface'], 'Invalid duration/uplink')
            ip = args.address
            check(not (ip.is_loopback or ip.is_multicast or ip.is_unspecified or int(ip) == 0xffffffff),
                  'Choose a single unicast address')
            verify_table(s, table())
            routes = json.loads(command('ip', '-j', '-4', 'route', 'get', str(ip)).stdout)
            check(len(routes) == 1 and routes[0].get('dev') == args.uplink and 'gateway' not in routes[0],
                  'Address must be directly attached to the approved uplink')
            batch = (f'flush set inet {TABLE} temporary_lan\n'
                     f'add element inet {TABLE} temporary_lan {{ "{args.uplink}" . {ip} timeout {args.seconds}s }}\n')
            command('nft', '-c', '-f', '-', data=batch)
            command('nft', '-f', '-', data=batch)
            print(f'NOT STRICT. Physical HTTP/HTTPS to the selected LAN address permitted for {args.seconds}s.')
        elif args.action == 'load':
            check(s['phase'] in ('installing', 'committed'), 'Trial has no boot authorization')
            install_rules(s)
        elif args.action == 'commit':
            check(args.confirm and args.egress_verified and args.transaction == s['transaction'],
                  'Match the trial transaction and confirm tested tunnel DNS and egress')
            check(s['phase'] in ('trial', 'installing'), 'No trial to commit')
            verify_table(s, table())
            _, _, expected_peer, profile_hash = profile(s['interface'])
            check(profile_hash == s['profile_hash'], 'Client profile changed')
            handshake = command('wg', 'show', s['interface'], 'latest-handshakes').stdout.split()
            check(len(handshake) == 2 and handshake[0] == expected_peer and
                  0 <= time.time() - int(handshake[1]) <= 180,
                  'Recent handshake with the configured server required')
            mark = command('wg', 'show', s['interface'], 'fwmark').stdout.strip()
            check(int(mark, 0) == 51820, 'Expected a running WG client with the approved mark')
            s['phase'] = 'installing'
            save(s)
            for path, value in files(s).items():
                if os.path.lexists(path):
                    check(trusted(path) == value, 'Unit installation conflict')
                else:
                    create_unit(path, value)
            command('systemctl', 'daemon-reload')
            check(gated(s), 'Provider boot dependency missing')
            s['phase'] = 'committed'
            save(s)
            detach_boot_recovery(s)
            command('systemctl', 'daemon-reload')
            command('systemctl', '--no-block', 'start', UNIT)
            command('systemctl', '--no-block', 'stop', timer(s) + '.timer', required=False)
            print('Client firewall committed. Network providers and WG require successful firewall startup.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('plan', 'status', 'enable', 'disable', 'commit', 'load', 'recover', 'temporary-lan', 'resume'):
        cmd = commands.add_parser(action)
        if action in ('plan', 'enable'):
            cmd.add_argument('--interface', type=name, default='wg-shadowborn')
            cmd.add_argument('--dhcp-interface', type=name, action='append', default=[])
        if action in ('enable', 'disable', 'commit', 'temporary-lan'):
            cmd.add_argument('--confirm', action='store_true')
        if action in ('commit', 'recover'):
            cmd.add_argument('--transaction', required=True)
        if action == 'enable':
            cmd.add_argument('--console-verified', action='store_true')
        if action == 'temporary-lan':
            cmd.add_argument('--address', type=ipaddress.IPv4Address, required=True)
            cmd.add_argument('--uplink', type=name, required=True)
            cmd.add_argument('--seconds', type=int, default=120)
        if action == 'commit':
            cmd.add_argument('--egress-verified', action='store_true')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        run(parser.parse_args())
    except RuntimeError as err:
        sys.exit(str(err))
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.exit('Client operation failed; inspect owned files and unit state from the console')


if __name__ == '__main__':
    main()
