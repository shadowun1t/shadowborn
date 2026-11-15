#!/usr/bin/env python3
"""Fetch one pinned upstream TEST binary; no installation or service activation."""
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import urllib.request

URL = 'https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.20/dnscrypt-proxy-linux_x86_64-2.1.20.tar.gz'
SHA256 = '71ba1165f006a682463aa30b120ac33bb3b3d0942b41d7cac8ab105e2dc98464'


def main():
    destination = Path(sys.argv[1])
    if not destination.is_absolute() or destination.exists():
        raise RuntimeError('new absolute output file required')
    with urllib.request.urlopen(URL, timeout=45) as response:
        archive = response.read(64 * 1024 * 1024 + 1)
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise RuntimeError('upstream test archive hash mismatch')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        matches = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == 'dnscrypt-proxy']
        if len(matches) != 1 or matches[0].size > 64 * 1024 * 1024:
            raise RuntimeError('unexpected test archive layout')
        # Read one regular member; never extract paths, links or config from tar.
        data = tar.extractfile(matches[0]).read()
    with os.fdopen(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o755), 'wb') as stream:
        stream.write(data)
    print('Pinned dnscrypt-proxy 2.1.20 test binary verified; no service installed')


if __name__ == '__main__':
    main()
