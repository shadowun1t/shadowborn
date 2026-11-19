#!/usr/bin/env python3
"""Synthetic DNS/DoT policy checks, only inside the parent network lab.

No external resolver, traffic capture or historical query store is used. The
small TLS responder is a disposable test fixture, not product DNS code.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time


def guard():
    outer = os.environ.get('SHADOWBORN_OUTER_NETNS')
    if not outer or outer == os.readlink('/proc/self/ns/net') or os.geteuid() != 0:
        raise RuntimeError('DNS lab requires the isolated network namespace guard')


def exact(stream, size):
    result = b''
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise OSError('fixture connection closed')
        result += part
    return result


def query(address, name, kind, tcp):
    guard()
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'
    payload = struct.pack('!6H', 4321, 0x100, 1, 0, 0, 0) + question + struct.pack('!2H', kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        if tcp:
            sock.connect((address, 53))
            sock.sendall(struct.pack('!H', len(payload)) + payload)
            reply = exact(sock, struct.unpack('!H', exact(sock, 2))[0])
        else:
            sock.sendto(payload, (address, 53))
            reply, _ = sock.recvfrom(4096)
    identifier, flags, _, answers, _, _ = struct.unpack('!6H', reply[:12])
    assert identifier == 4321
    return {'rcode': flags & 15, 'answers': answers,
            'gateway': socket.inet_aton('10.89.0.1') in reply,
            'destination': socket.inet_aton('198.18.0.10') in reply}


def exercise_dns_policy(base, bundle, server, client, ns, run):
    guard()
    unbound = os.environ.get('SHADOWBORN_UNBOUND') or shutil.which('unbound')
    if not unbound or not shutil.which('openssl'):
        print('SKIPPED: runtime DNS policy requires Unbound and openssl')
        return
    cert, key = base / 'fixture-ca.pem', base / 'fixture-key.pem'
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=dns.quad9.net', '-addext', 'subjectAltName=DNS:dns.quad9.net',
         '-keyout', key, '-out', cert])
    key.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('198.18.0.53', 853))
    listener.listen(8)
    listener.settimeout(.2)
    stop = threading.Event()
    queries = [0]  # Current synthetic test count in RAM only; never names/IPs.

    def respond():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
                connection.settimeout(.5)
                with connection, context.wrap_socket(connection, server_side=True) as stream:
                    while not stop.is_set():
                        size = struct.unpack('!H', exact(stream, 2))[0]
                        request = exact(stream, size)
                        end = 12
                        while request[end]:
                            end += request[end] + 1
                        end += 5
                        queries[0] += 1
                        answer = request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0)
                        answer += request[12:end] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4)
                        answer += socket.inet_aton('198.18.0.10')
                        stream.sendall(struct.pack('!H', len(answer)) + answer)
            except (OSError, ssl.SSLError, IndexError, struct.error):
                continue

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    # Relocate ONLY lab directory, CA and upstream fixture addresses. Keep the
    # generated ACL, TLS authentication, filtering and no-log directives intact.
    text = (bundle / 'unbound.conf').read_text().replace('directory: "/etc/unbound"', f'directory: "{base}"')
    text = text.replace('/etc/ssl/certs/ca-certificates.crt', str(cert))
    text = text.replace('9.9.9.9@853', '198.18.0.53@853').replace('149.112.112.112@853', '198.18.0.53@853')
    config = base / 'resolver-lab.conf'
    config.write_text(text)
    expected_files = {p.relative_to(base) for p in base.rglob('*')}
    process = None

    def ask(name, kind=1, tcp=False, address='10.89.0.1', ok=True):
        result = ns(client, sys.executable, str(Path(__file__).resolve()), '--query',
                    address, name, str(kind), str(int(tcp)), ok=ok, timeout=10)
        return json.loads(result.stdout) if ok else result

    def start():
        proc = subprocess.Popen(['nsenter', '-t', str(server), '-n', unbound, '-d', '-c', str(config)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(50):
            if proc.poll() is not None:
                raise RuntimeError('lab resolver exited before readiness')
            response = ask('gateway.shadowborn.home.arpa', ok=False)
            if response.returncode == 0:
                return proc
            time.sleep(.05)
        proc.terminate()
        proc.communicate(timeout=5)
        raise RuntimeError('lab resolver readiness timeout')

    def finish(proc):
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=5)
        assert not stdout
        for forbidden in (b'ads.example', b'telemetry.example', b'shadowborn.home.arpa', b'10.89.0.2'):
            assert forbidden not in stderr, 'resolver emitted synthetic query or client activity'

    try:
        process = start()
        initial = queries[0]
        for name in ('ads.example', 'sub.ads.example', 'telemetry.example'):
            for kind in (1, 28):
                assert ask(name, kind)['rcode'] == 3
        assert ask('ads.example', tcp=True)['rcode'] == 3
        local = ask('gateway.shadowborn.home.arpa')
        assert local['rcode'] == 0 and local['answers'] == 1 and local['gateway']
        assert ask('unknown.shadowborn.home.arpa')['rcode'] == 3
        assert queries[0] == initial, 'blocked/private names reached the synthetic upstream'
        allowed = ask('safe.ads.example')
        assert allowed['rcode'] == 0 and allowed['destination']
        assert queries[0] > initial
        assert ask('ads.example', address='203.0.113.1', ok=False).returncode
        finish(process)
        process = None
        process = start()
        assert ask('sub.ads.example')['rcode'] == 3
        assert ask('gateway.shadowborn.home.arpa')['gateway']
        finish(process)
        process = None
        # Wrong authenticated name must fail. It cannot use plaintext fallback.
        config.write_text(text.replace('#dns.quad9.net', '#wrong.invalid'))
        process = start()
        failure = ask('safe.ads.example', ok=False)
        assert failure.returncode != 0 or json.loads(failure.stdout)['rcode'] == 2
        assert ask('ads.example')['rcode'] == 3
        finish(process)
        process = None
        assert {p.relative_to(base) for p in base.rglob('*')} == expected_files
        print('PASS: actual Unbound A/AAAA/TCP domain blocking, exceptions via synthetic authenticated DoT, private records, WAN DNS denial and restart')
        print('PASS: wrong upstream TLS name fails; no new resolver files or query/client values in captured process output (scoped lab only)')
    finally:
        if process is not None:
            finish(process)
        stop.set()
        listener.close()
        thread.join(timeout=2)


if __name__ == '__main__':
    guard()
    if len(sys.argv) == 6 and sys.argv[1] == '--query':
        try:
            print(json.dumps(query(sys.argv[2], sys.argv[3], int(sys.argv[4]), bool(int(sys.argv[5])))))
        except (OSError, ValueError):
            sys.exit(1)
    else:
        raise SystemExit('This helper is only used by the isolated namespace lab')
