#!/usr/bin/env python3
"""Disposable QEMU guests. Control and the optional test LAN use private Unix sockets."""
import argparse
import base64
import json
import os
import secrets
import select
from pathlib import Path
import socket
import subprocess
import sys


AGENT = """import base64, json, os, subprocess, time
while True:
    try:
        with open('/dev/virtio-ports/shadowborn.test', 'r+b', buffering=0) as port:
            buf = bytearray()
            while True:
                chunk = os.read(port.fileno(), 65536)
                if not chunk:
                    raise OSError()
                buf.extend(chunk)
                if b'\\n' not in buf:
                    continue
                line, _, buf = buf.partition(b'\\n')
                try:
                    req = json.loads(line)
                    result = subprocess.run(req['args'], input=base64.b64decode(req['stdin']),
                                            capture_output=True, timeout=req['timeout'])
                    reply = {'code': result.returncode, 'out': base64.b64encode(result.stdout).decode(),
                             'err': base64.b64encode(result.stderr).decode()}
                except Exception as err:
                    reply = {'code': 255, 'out': '', 'err': base64.b64encode(type(err).__name__.encode()).decode()}
                port.write(json.dumps(reply).encode() + b'\\n')
    except OSError:
        time.sleep(0.2)
"""
UNIT = """[Unit]
Description=Disposable Shadowborn test transport
DefaultDependencies=no
After=local-fs.target systemd-udevd.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/libexec/shadowborn-test-agent.py
Restart=always
StandardOutput=null
StandardError=null
[Install]
WantedBy=sysinit.target
"""


def start(base, image, iso_tool, lan=None, listen=False):
    base.mkdir(mode=0o700, parents=True, exist_ok=False)
    subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                    str(image.resolve()), str(base/'disk.qcow2'), '8G'], check=True, capture_output=True)
    (base/'meta-data').write_text('instance-id: shadowborn-disposable\nlocal-hostname: shadowborn-lab\n')
    # Bring the private control channel up even if package installation fails.
    config = {'write_files': [
        {'path': '/usr/local/libexec/shadowborn-test-agent.py', 'permissions': '0700', 'content': AGENT},
        {'path': '/etc/systemd/system/shadowborn-test-agent.service', 'content': UNIT}],
        'runcmd': [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'shadowborn-test-agent.service']]}
    (base/'user-data').write_text('#cloud-config\n' + json.dumps(config))
    subprocess.run([str(iso_tool), '-output', str(base/'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                    str(base/'user-data'), str(base/'meta-data')], check=True, capture_output=True)
    accel = ['-accel', 'kvm', '-cpu', 'host'] if os.access('/dev/kvm', os.R_OK | os.W_OK) else ['-accel', 'tcg', '-cpu', 'max']
    args = ['qemu-system-x86_64', *accel, '-machine', 'q35', '-m', '1280', '-smp', '2', '-display', 'none',
            '-drive', f'file={base}/disk.qcow2,if=virtio,format=qcow2',
            '-drive', f'file={base}/seed.iso,media=cdrom,readonly=on',
            '-netdev', 'user,id=packages', '-device', 'virtio-net-pci,netdev=packages',
            '-device', 'virtio-serial-pci',
            '-chardev', f'socket,id=control,path={base}/control.sock,server=on,wait=off',
            '-device', 'virtserialport,chardev=control,name=shadowborn.test',
            '-qmp', f'unix:{base}/qmp.sock,server=on,wait=off', '-serial', f'file:{base}/boot.txt']
    if lan is not None:
        mode = 'on' if listen else 'off'
        mac = '52:54:00:00:00:01' if listen else '52:54:00:00:00:02'
        args += ['-netdev', f'stream,id=lan,addr.type=unix,addr.path={lan},server={mode}',
                 '-device', f'virtio-net-pci,netdev=lan,mac={mac}']
    with (base/'qemu-error.txt').open('wb') as errors:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=errors, start_new_session=True)
    (base/'pid').write_text(str(proc.pid))
    print('Disposable VM starting:', base)


_channels = {}


def disconnect(base):
    pair = _channels.pop(base, None)
    if pair:
        pair[1].close()
        pair[0].close()


def channel(base):
    if base not in _channels:
        connection = socket.socket(socket.AF_UNIX)
        stream = None
        try:
            connection.settimeout(8)
            connection.connect(str(base/'control.sock'))
            stream = connection.makefile('rb')
            # QEMU can accept a socket before the guest opens its virtio port.
            # Only harmless synchronization messages may be retransmitted.
            token = secrets.token_hex(16)
            probe = json.dumps({'args': ['printf', token], 'stdin': '', 'timeout': 3}).encode() + b'\n'
            ready = False
            for _ in range(4):
                connection.sendall(probe)
                if select.select([connection], [], [], 1.5)[0]:
                    ready = base64.b64decode(json.loads(stream.readline())['out']).decode() == token
                    if ready:
                        break
            if not ready:
                raise RuntimeError('Guest agent is not ready')
            _channels[base] = (connection, stream, base64.b64encode(token.encode()).decode())
        except BaseException:
            if stream is not None:
                stream.close()
            connection.close()
            raise
    return _channels[base]


def request(base, args, data=b'', timeout=60):
    connection, stream, probe = channel(base)
    try:
        connection.settimeout(timeout + 15)
        connection.sendall(json.dumps({'args': args, 'stdin': base64.b64encode(data).decode(),
                                       'timeout': timeout}).encode() + b'\n')
        reply = json.loads(stream.readline())
        while reply['out'] == probe:
            reply = json.loads(stream.readline())
        return reply['code'], base64.b64decode(reply['out']), base64.b64decode(reply['err'])
    except BaseException:
        disconnect(base)
        raise


def qmp(base, command):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(base/'qmp.sock'))
        with connection.makefile('rwb', buffering=0) as stream:
            json.loads(stream.readline())
            for instruction in ['qmp_capabilities', command]:
                stream.write(json.dumps({'execute': instruction}).encode() + b'\n')
                while True:
                    reply = json.loads(stream.readline())
                    if 'return' in reply or 'error' in reply:
                        break
        return reply


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    launch = sub.add_parser('start')
    launch.add_argument('where', type=Path)
    launch.add_argument('image', type=Path)
    launch.add_argument('iso_tool', type=Path)
    launch.add_argument('--lan', type=Path)
    launch.add_argument('--listen', action='store_true')
    for name in ('run', 'qmp'):
        op = sub.add_parser(name)
        op.add_argument('where', type=Path)
        op.add_argument('args', nargs=argparse.REMAINDER)
    parsed = parser.parse_args()
    if parsed.action == 'start':
        start(parsed.where, parsed.image, parsed.iso_tool, parsed.lan, parsed.listen)
    elif parsed.action == 'qmp':
        print(json.dumps(qmp(parsed.where, parsed.args[0])))
    else:
        code, out, err = request(parsed.where, parsed.args, sys.stdin.buffer.read())
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
        sys.exit(code)
