#!/usr/bin/env python3
"""Install this experiment's native host into a new, owner-only directory.

Requires a reviewed local config JSON. Never reads a PIN, executes provisioning,
or overwrites an existing installation. Native binaries must already be built.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent
# Historical transport/verification experiments remain in source for independent
# interoperability tests, but are not part of the installed hardware service.
NATIVE_MODULES = ('host.py','chat_bridge.py','certificate_migration.py',
                  'identities.py','signing.py','decryption.py','vault_piv.py',
                  'native_state.py','hardware_audit.py')


def validate(config):
    required = {'serial','ykman','app','cert','chat_email'}
    if (set(config) != required or not isinstance(config['serial'],str) or
        not re.fullmatch(r'[1-9][0-9]{0,9}',config['serial']) or int(config['serial'])>2147483647):
        raise ValueError('Supply the exact example fields and an explicit numeric serial')
    for name in ('ykman','app','cert'):
        p=Path(config[name])
        if not p.is_absolute() or not p.exists():raise ValueError('Missing absolute path: '+name)
    for component in ('native','adapters'):
        if not (Path(config['app'])/component).is_dir():raise ValueError('Missing installed backend')
    # This mailbox belongs only to the fixed legacy/vault enrollment. Account
    # settings and selected message identities are independently IWA-owned.
    email=config['chat_email']
    if not isinstance(email,str) or not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+',email):
        raise ValueError('Explicit enrollment email required')


def install_code(destination,crypto_binary):
    """Copy the small native service, never a mail transport or Java runtime.

    The allowlist makes newly added source modules an explicit packaging review.
    Existing legacy runtimes are left alone during an upgrade: neither local
    test evidence nor older standalone tools are erased by installing this code.
    """
    for name in NATIVE_MODULES:
        shutil.copy2(ROOT/'native'/name,destination/'native'/name)
    shutil.copy2(crypto_binary,destination/'runtime/sequoia-iwa-crypto')


def copy(source,target):
    # ditto preserves existing bundle structure and executable modes. It does
    # not launch the copied code or change any key or policy on a smart card.
    subprocess.run(['/usr/bin/ditto',str(source),str(target)],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--crypto-bin',required=True,type=Path,help='Built sequoia-iwa-crypto executable')
    p.add_argument('--destination',type=Path,default=Path.home()/'Library/Application Support/Sequoia IWA Lab')
    args=p.parse_args();os.umask(0o077)
    cfg=json.loads(args.config.read_text());validate(cfg)
    crypto_binary=args.crypto_bin.resolve(strict=True)
    if not crypto_binary.is_file() or not os.access(crypto_binary,os.X_OK):raise ValueError('Built executable required')
    identity=json.loads((ROOT/'build/identity.json').read_text())
    extension=identity['extensionId']
    if not re.fullmatch('[a-p]{32}',extension):raise ValueError('Build the matching extension first')
    if not (ROOT/'build/pin-prompt').is_file():raise ValueError('Compile the native PIN prompt first')
    dest=args.destination.expanduser().resolve()
    # Refuse accidental changes to another helper installation. To update,
    # explicitly choose a new directory, inspect it, then switch registration.
    dest.mkdir(parents=True,mode=0o700,exist_ok=False)
    for name in ('native','private','runtime','build'):(dest/name).mkdir(mode=0o700)
    r=dest/'runtime'
    install_code(dest,crypto_binary)
    shutil.copy2(ROOT/'build/pin-prompt',dest/'build/pin-prompt')
    for source,target in [(Path(cfg['app'])/'native',r/'app/native'),
                          (Path(cfg['app'])/'adapters',r/'app/adapters')]:copy(source,target)
    shutil.copy2(cfg['cert'],r/'public.asc')
    cfg.update(extension_id=extension,app=str(r/'app'),cert=str(r/'public.asc'))
    (dest/'private/config.json').write_text(json.dumps(cfg,indent=2))
    launcher=dest/'native/host-launcher'
    launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 -I -B '+shlex.quote(str(dest/'native/host.py'))+' "$@"\n');launcher.chmod(0o700)
    # Registration is scoped to the experiment's custom Canary profile, not
    # the user's normal Chrome profile. No wildcard origins are accepted.
    registration=ROOT/'private/chrome-profile/NativeMessagingHosts'
    registration.mkdir(parents=True,exist_ok=True,mode=0o700)
    manifest={'name':'org.pqmail.sequoia_iwa','description':'Bounded Sequoia YubiKey hardware service','path':str(launcher),'type':'stdio','allowed_origins':['chrome-extension://'+extension+'/']}
    (registration/'org.pqmail.sequoia_iwa.json').write_text(json.dumps(manifest,indent=2))
    print('Installed native helper:',dest)
    print('No hardware operation performed. Review configuration before testing.')

if __name__=='__main__':main()
