#!/usr/bin/env python3
"""Install this experiment's native host into a new, owner-only directory.

Requires a reviewed local config JSON. Never reads a PIN, executes provisioning,
or overwrites an existing installation. Native binaries must already be built.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent


def validate(config):
    required = {'serial','ykman','app','java','binary','runner','cert','classpath'}
    if set(config) != required or not re.fullmatch(r'[0-9]+',config['serial']):
        raise ValueError('Supply the exact example fields and an explicit numeric serial')
    for name in ('ykman','app','java','binary','runner','cert'):
        p=Path(config[name])
        if not p.is_absolute() or not p.exists():raise ValueError('Missing absolute path: '+name)
    for component in config['classpath'].split(os.pathsep):
        p=Path(component[:-2] if component.endswith('/*') else component)
        if not p.is_absolute() or not p.exists():raise ValueError('Missing absolute classpath entry')
    for component in ('native','adapters'):
        if not (Path(config['app'])/component).is_dir():raise ValueError('Missing installed backend')
    if Path(config['java']).parent.name != 'bin':raise ValueError('java must be inside a JDK bin directory')


def copy(source,target):
    # ditto preserves existing bundle structure and executable modes. It does
    # not launch the copied code or change any key or policy on a smart card.
    subprocess.run(['/usr/bin/ditto',str(source),str(target)],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--destination',type=Path,default=Path.home()/'Library/Application Support/Sequoia IWA Lab')
    args=p.parse_args();os.umask(0o077)
    cfg=json.loads(args.config.read_text());validate(cfg)
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
    shutil.copy2(ROOT/'native/host.py',dest/'native/host.py')
    shutil.copy2(ROOT/'build/pin-prompt',dest/'build/pin-prompt')
    for source,target in [(Path(cfg['app'])/'native',r/'app/native'),
                          (Path(cfg['app'])/'adapters',r/'app/adapters'),
                          (Path(cfg['java']).parents[1],r/'java')]:copy(source,target)
    for name,target in [('binary','piv-test'),('runner','run.py'),('cert','public.asc')]:
        shutil.copy2(cfg[name],r/target)
    classpath=[]
    for i,component in enumerate(cfg['classpath'].split(os.pathsep)):
        wildcard=component.endswith('/*');source=Path(component[:-2] if wildcard else component)
        target=r/('classpath-'+str(i)+(source.suffix if source.is_file() else ''))
        copy(source,target);classpath.append(str(target)+('/*' if wildcard else ''))
    cfg.update(extension_id=extension,app=str(r/'app'),java=str(r/'java/bin/java'),binary=str(r/'piv-test'),runner=str(r/'run.py'),cert=str(r/'public.asc'),classpath=os.pathsep.join(classpath))
    (dest/'private/config.json').write_text(json.dumps(cfg,indent=2))
    launcher=dest/'native/host-launcher'
    launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 -I -B '+shlex.quote(str(dest/'native/host.py'))+' "$@"\n');launcher.chmod(0o700)
    # Registration is scoped to the experiment's custom Canary profile, not
    # the user's normal Chrome profile. No wildcard origins are accepted.
    registration=ROOT/'private/chrome-profile/NativeMessagingHosts'
    registration.mkdir(parents=True,exist_ok=True,mode=0o700)
    manifest={'name':'org.pqmail.sequoia_iwa','description':'Fixed Sequoia non-provisioning test','path':str(launcher),'type':'stdio','allowed_origins':['chrome-extension://'+extension+'/']}
    (registration/'org.pqmail.sequoia_iwa.json').write_text(json.dumps(manifest,indent=2))
    print('Installed native helper:',dest)
    print('No hardware operation performed. Review configuration before testing.')

if __name__=='__main__':main()
