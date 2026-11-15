#!/usr/bin/env python3
"""Actual dnscrypt-proxy + Unbound against synthetic HTTPS in an isolated netns."""
import base64
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
from dns_policy import query, guard


def stamp(name='resolver.example', certificate_hash=None):
    def lp(s):
        s = s.encode()
        return bytes([len(s)]) + s
    return 'sdns://' + base64.urlsafe_b64encode(b'\x02' + b'\0' * 8 + lp('198.18.0.53') + (b'\0' if certificate_hash is None else bytes([len(certificate_hash)]) + certificate_hash) + lp(name) + lp('/dns-query')).decode().rstrip('=')


def run(args, **kwargs):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {result.returncode})')
    return result


def isolated():
    guard()
    proxy = os.environ.get('SHADOWBORN_DNSCRYPT') or shutil.which('dnscrypt-proxy')
    unbound = os.environ.get('SHADOWBORN_UNBOUND') or shutil.which('unbound')
    if not proxy or not unbound:
        raise RuntimeError('Set SHADOWBORN_DNSCRYPT and SHADOWBORN_UNBOUND to test binaries')
    run(['ip', 'link', 'set', 'lo', 'up'])
    for address in ('198.18.0.53/32', '10.89.0.1/24'):
        run(['ip', 'addr', 'add', address, 'dev', 'lo'])
    with tempfile.TemporaryDirectory(prefix='shadowborn-doh-') as tmp:
        base = Path(tmp)
        cert, key = base / 'ca.pem', base / 'key.pem'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=resolver.example', '-addext', 'subjectAltName=DNS:resolver.example',
             '-out', cert, '-keyout', key])
        key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        count = [0]

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                from urllib.parse import urlparse, parse_qs
                data = parse_qs(urlparse(self.path).query).get('dns', [''])[0]
                self.answer(base64.urlsafe_b64decode(data + '=' * (-len(data) % 4)))

            def do_POST(self):
                self.answer(self.rfile.read(int(self.headers['Content-Length'])))

            def answer(self, data):
                end = 12
                while data[end]:
                    end += data[end] + 1
                end += 5
                kind = struct.unpack('!H', data[end-4:end-2])[0]
                answer = data[:2] + struct.pack('!5H', 0x8183 if kind == 2 else 0x8180, 1, int(kind == 1), 0, 0) + data[12:end]
                if kind == 1:
                    answer += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('198.18.0.10')
                count[0] += 1
                self.send_response(200)
                self.send_header('Content-Type', 'application/dns-message')
                self.send_header('Content-Length', str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

        httpd = http.server.ThreadingHTTPServer(('198.18.0.53', 443), Handler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        config = tomllib.loads((ROOT / 'config/server.example.toml').read_text())
        config['dns']['upstream'] = 'dnscrypt-proxy'
        config['addons'] = {'dnscrypt': {'stamp': stamp()}}
        config['filtering'] = {'blocked_domains': ['ads.example']}
        state = {'schema_version': 1, 'config': config, 'server_private_key': 'B'*42+'A=', 'server_public_key': 'C'*42+'A=', 'peers': []}
        fixture = base / 'fixture.json'
        fixture.write_text(json.dumps(state))
        fixture.chmod(0o600)
        bundle = base / 'bundle'
        run([ROOT / 'target/debug/examples/render_lab', fixture, bundle])
        resolver = bundle / 'unbound.conf'
        resolver.write_text(resolver.read_text().replace('directory: "/etc/shadowborn"', f'directory: "{base}"'))
        proxy_config = bundle / 'dnscrypt-proxy.toml'
        # Only the lab's synthetic CA is added; TLS verification remains enabled.
        env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
        env['SSL_CERT_FILE'] = str(cert)
        result = run([proxy, '-check', '-config', proxy_config], env=env)
        assert not result.stdout and not result.stderr, 'configuration check emitted output'
        expected = {str(p.relative_to(base)): p.read_bytes() for p in base.rglob('*') if p.is_file()}
        processes = []

        def start(binary, args):
            proc = subprocess.Popen([binary, *map(str, args)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(proc)
            return proc

        def stop(proc):
            proc.terminate()
            out, err = proc.communicate(timeout=10)
            processes.remove(proc)
            assert not out and not err, 'resolver emitted output'

        def wait_answer(name, expected_rcode, destination=False):
            for _ in range(20):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('resolver exited before readiness')
                try:
                    response = query('10.89.0.1', name, 1, False)
                    if response['rcode'] == expected_rcode and (not destination or response['destination']):
                        return
                except OSError:
                    pass
                time.sleep(.1)
            raise RuntimeError('DNS response not observed')

        try:
            dp = start(proxy, ['-config', proxy_config])
            ub = start(unbound, ['-d', '-c', resolver])
            wait_answer('ads.example', 3)
            wait_answer('ok.example', 0, True)
            assert query('10.89.0.1', 'tcp.example', 1, True)['destination']
            assert query('10.89.0.1', 'aaaa.example', 28, False)['rcode'] == 0
            before = count[0]
            assert query('10.89.0.1', 'sub.ads.example', 1, False)['rcode'] == 3
            assert count[0] == before
            stop(dp)
            failed = False
            try:
                failed = query('10.89.0.1', 'outage.example', 1, False)['rcode'] == 2
            except OSError:
                failed = True
            assert failed, 'unexpected DNS fallback during proxy outage'
            assert query('10.89.0.1', 'ads.example', 1, False)['rcode'] == 3
            dp = start(proxy, ['-config', proxy_config])
            wait_answer('restarted.example', 0, True)
            stop(dp)
            proxy_config.write_text(proxy_config.read_text().replace(stamp(), stamp('wrong.example')))
            dp = start(proxy, ['-config', proxy_config])
            before = count[0]
            try:
                assert query('10.89.0.1', 'wrong-cert.example', 1, False)['rcode'] == 2
            except OSError:
                pass
            assert count[0] == before, 'wrong TLS name reached application responder'
            stop(dp)
            proxy_config.write_text(proxy_config.read_text().replace(stamp('wrong.example'), stamp(certificate_hash=b'\0' * 32)))
            dp = start(proxy, ['-config', proxy_config])
            before = count[0]
            try:
                assert query('10.89.0.1', 'wrong-pin.example', 1, False)['rcode'] == 2
            except OSError:
                pass
            assert count[0] == before, 'wrong certificate pin reached application responder'
            stop(dp)
            stop(ub)
            proxy_config.write_bytes(expected[str(proxy_config.relative_to(base))])
            actual = {str(p.relative_to(base)): p.read_bytes() for p in base.rglob('*') if p.is_file()}
            assert actual == expected, 'resolver created/changed persistent files'
            print('PASS: actual dnscrypt-proxy + Unbound DoH, A/AAAA/TCP, filtering, outage/restart, TLS-name/hash failure; no files/output retained')
        finally:
            for proc in processes:
                proc.terminate()
                proc.communicate(timeout=10)
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    if '--isolated' in sys.argv:
        isolated()
    else:
        env = os.environ.copy()
        env['SHADOWBORN_OUTER_NETNS'] = os.readlink('/proc/self/ns/net')
        raise SystemExit(subprocess.call(['unshare', '-Urn', sys.executable, __file__, '--isolated'], env=env))
