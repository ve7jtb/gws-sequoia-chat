#!/usr/bin/env python3
"""Install the pinned official gws release and a separately installed sq binary.

Archives are never unpacked as filesystem paths. Only the named CLI executable
is copied after SHA-256 verification. This installs no credentials or keys.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
VERSION = 'v0.22.5'


def download(url, limit):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(limit+1)
    if len(data) > limit:
        raise ValueError('Download exceeds size limit')
    return data


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sq', required=True, help='Path to sq with RFC 9980 hybrid support (tested: 1.5.0)')
    a = p.parse_args()
    os.umask(0o077)
    arch = {'arm64':'aarch64', 'aarch64':'aarch64', 'x86_64':'x86_64', 'AMD64':'x86_64'}[platform.machine()]
    system = platform.system()
    target = {'Darwin':'apple-darwin', 'Linux':'unknown-linux-gnu', 'Windows':'pc-windows-msvc'}[system]
    if system == 'Windows' and arch != 'x86_64':
        raise ValueError('This gws release does not publish a native Windows ARM64 binary')
    ext = 'zip' if system == 'Windows' else 'tar.gz'
    name = f'google-workspace-cli-{arch}-{target}.{ext}'
    base = f'https://github.com/googleworkspace/cli/releases/download/{VERSION}/{name}'
    expected = download(base+'.sha256', 4096).decode().split()[0]
    archive = download(base, 64*1024*1024)
    if hashlib.sha256(archive).hexdigest() != expected:
        raise ValueError('gws checksum mismatch')
    executable = 'gws.exe' if system == 'Windows' else 'gws'
    if ext == 'zip':
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            members = [n for n in z.namelist() if Path(n).name == executable]
            if len(members) != 1: raise ValueError('Expected one gws binary')
            binary = z.read(members[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(archive)) as t:
            members = [m for m in t.getmembers() if m.isfile() and Path(m.name).name == executable]
            if len(members) != 1: raise ValueError('Expected one gws binary')
            binary = t.extractfile(members[0]).read()
    (ROOT/'bin').mkdir(exist_ok=True)
    destination = ROOT/'bin'/executable
    if destination.exists(): raise ValueError('bin/gws already exists; review before replacing')
    destination.write_bytes(binary); destination.chmod(0o755)
    sq = ROOT/'bin'/('sq.exe' if system == 'Windows' else 'sq')
    if sq.exists(): raise ValueError('bin/sq already exists; review before replacing')
    shutil.copy2(a.sq, sq)
    subprocess.run([str(sq), 'version'], check=True)
    (ROOT/'private/gws').mkdir(mode=0o700, parents=True, exist_ok=True)
    print('Installed gws '+VERSION+' and sq. Dynamic sq dependencies must remain installed.')
    if system == 'Windows':
        print('The current Chat wrapper is POSIX-only; use WSL. Native Windows wiring is not tested.')


if __name__ == '__main__':
    main()
