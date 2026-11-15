#!/usr/bin/env python3
"""Disposable QEMU VM transport. Control is a private virtio socket, never SSH."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

AGENT = '''import base64,json,subprocess,time
while True:
 try:
  with open('/dev/virtio-ports/shadowborn.test','r+b',buffering=0) as f:
   while True:
    line=b''
    while not line.endswith(b'\\n'):
     part=f.read(1)
     if not part: raise OSError()
     line+=part
    try:
     req=json.loads(line)
     result=subprocess.run(req['args'],input=base64.b64decode(req.get('stdin','')),capture_output=True,timeout=req.get('timeout',60))
     reply={'code':result.returncode,'out':base64.b64encode(result.stdout).decode(),'err':base64.b64encode(result.stderr).decode()}
    except Exception as e: reply={'code':255,'out':'','err':base64.b64encode(type(e).__name__.encode()).decode()}
    f.write(json.dumps(reply).encode()+b'\\n')
 except OSError: time.sleep(1)
'''


def start(base, image, iso_tool):
    base.mkdir(mode=0o700, parents=True, exist_ok=False)
    # A real verified official cloud image; caller keeps its SHA512 evidence.
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(base/'disk.qcow2'),'8G'],check=True,capture_output=True)
    (base/'meta-data').write_text('instance-id: shadowborn-disposable\nlocal-hostname: shadowborn-lab\n')
    config = {'package_update': True, 'packages': ['wireguard-tools','nftables','unbound','ca-certificates','curl','openssl','python3','iproute2'],
              'write_files': [{'path':'/usr/local/libexec/shadowborn-test-agent.py','permissions':'0700','content':AGENT},
                              {'path':'/etc/systemd/system/shadowborn-test-agent.service','content':'[Unit]\nAfter=multi-user.target\n[Service]\nExecStart=/usr/bin/python3 /usr/local/libexec/shadowborn-test-agent.py\nRestart=always\nStandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n'}],
              'runcmd': [['systemctl','daemon-reload'],['systemctl','enable','--now','shadowborn-test-agent.service']]}
    (base/'user-data').write_text('#cloud-config\n'+json.dumps(config))
    subprocess.run([str(iso_tool),'-output',str(base/'seed.iso'),'-volid','cidata','-joliet','-rock',str(base/'user-data'),str(base/'meta-data')],check=True,capture_output=True)
    args=['qemu-system-x86_64','-enable-kvm','-machine','q35','-cpu','host','-m','1536','-smp','2','-display','none',
          '-drive',f'file={base}/disk.qcow2,if=virtio,format=qcow2','-drive',f'file={base}/seed.iso,media=cdrom,readonly=on',
          '-netdev','user,id=wan','-device','virtio-net-pci,netdev=wan','-device','virtio-serial-pci',
          '-chardev',f'socket,id=control,path={base}/control.sock,server=on,wait=off',
          '-device','virtserialport,chardev=control,name=shadowborn.test',
          '-qmp',f'unix:{base}/qmp.sock,server=on,wait=off','-serial',f'file:{base}/boot.txt']
    with (base/'qemu-error.txt').open('wb') as errors:
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=errors,start_new_session=True)
    (base/'pid').write_text(str(proc.pid))
    print('Disposable VM starting:',base)


def request(base,args,data=b'',timeout=60):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(timeout+15)
        connection.connect(str(base/'control.sock'))
        connection.sendall(json.dumps({'args':args,'stdin':base64.b64encode(data).decode(),'timeout':timeout}).encode()+b'\n')
        buf=b''
        while not buf.endswith(b'\n'):
            part=connection.recv(65536)
            if not part: raise RuntimeError('VM control channel closed')
            buf+=part
        r=json.loads(buf)
        return r['code'],base64.b64decode(r['out']),base64.b64decode(r['err'])


def qmp(base, command):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10);connection.connect(str(base/'qmp.sock'))
        stream=connection.makefile('rwb',buffering=0)
        json.loads(stream.readline())
        for cmd in ['qmp_capabilities',command]:
            stream.write(json.dumps({'execute':cmd}).encode()+b'\n')
            while True:
                reply=json.loads(stream.readline())
                if 'return' in reply or 'error' in reply: break
        return reply


if __name__=='__main__':
    action,where,*args=sys.argv[1:];base=Path(where)
    if action=='start': start(base,Path(args[0]),Path(args[1]))
    elif action=='run':
        code,out,err=request(base,args,sys.stdin.buffer.read());sys.stdout.buffer.write(out);sys.stderr.buffer.write(err);sys.exit(code)
    elif action=='qmp':print(json.dumps(qmp(base,args[0])))
