#!/usr/bin/env python3
"""Select an existing classical PIV vault key; never generate or modify token keys.

Reads its SPKI through the installed PKCS#11 adapter and stores only public
configuration. Run locally with --apply after reviewing the chosen serial/slot.
"""
import argparse,base64,importlib.util,json,os,re
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--installed',type=Path,default=Path.home()/'Library/Application Support/Sequoia IWA Lab')
    p.add_argument('--serial',required=True);p.add_argument('--slot',required=True,choices=['9d']+[format(x,'02x') for x in range(0x82,0x96)])
    p.add_argument('--algorithm',required=True,choices=['ECDH-P256','ECDH-P384']);p.add_argument('--apply',action='store_true');a=p.parse_args()
    if not re.fullmatch(r'[0-9]+',a.serial):raise ValueError('Explicit serial required')
    os.umask(0o077);config=a.installed/'private/config.json';c=json.loads(config.read_text());app=Path(c['app'])
    spec=importlib.util.spec_from_file_location('vault_pkcs11_config',app/'adapters/pkcs11-kem.py');adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
    public=adapter.export_public(str(app/'native/bin/openssl'),str(app/'native/lib/pkcs11.dylib'),str(app/'native/lib/libykcs11.dylib'),a.serial,a.slot,a.algorithm)
    import hashlib
    print('Existing public key:',a.serial,a.slot,a.algorithm,'SHA-256',hashlib.sha256(public).hexdigest())
    if not a.apply:print('Read-only check. Add --apply to save this public mapping.');return
    c['vault_piv']={'serial':a.serial,'slot':a.slot,'algorithm':a.algorithm,'public':base64.b64encode(public).decode()}
    tmp=config.with_suffix('.vault-tmp');tmp.write_text(json.dumps(c,indent=2));tmp.chmod(0o600);tmp.replace(config)
    print('Classical vault mapping saved. No token keys, certificates or policies changed.')
if __name__=='__main__':main()
