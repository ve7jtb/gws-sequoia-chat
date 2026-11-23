"""Optional classical PIV vault key for older YubiKeys. No FIDO dependency.

The serial, slot and expected SPKI are local administrator/user configuration,
not browser-selected paths. This route performs ECDH only, never provisioning.
"""
import base64,hashlib,importlib.util,re,subprocess
from pathlib import Path

def configured(b):
    c=b.cfg.get('vault_piv')
    if c is None:return None
    if set(c)!={'serial','slot','algorithm','public'} or not re.fullmatch(r'[0-9]+',c['serial']) or c['slot'] not in ['9d']+[format(i,'02x') for i in range(0x82,0x96)] or c['algorithm'] not in ('ECDH-P256','ECDH-P384'):raise ValueError('Invalid fixed PIV vault configuration')
    raw=base64.b64decode(c['public'],validate=True)
    if not 80<=len(raw)<=150:raise ValueError('Invalid PIV public key')
    return {**c,'fingerprint':hashlib.sha256(raw).hexdigest()}

def recover(b,request):
    c=configured(b)
    if not c or request['fingerprint']!=c['fingerprint']:raise ValueError('Wrong vault recipient')
    peer=base64.b64decode(request['peer'],validate=True)
    if not 80<=len(peer)<=150:raise ValueError('Invalid peer key')
    serials=subprocess.check_output([b.cfg['ykman'],'list','--serials'],stderr=subprocess.DEVNULL,timeout=25).decode().split()
    if c['serial'] not in serials:raise ValueError('Required vault YubiKey absent')
    app=Path(b.cfg['app'])
    spec=importlib.util.spec_from_file_location('iwa_vault_pkcs11',app/'adapters/pkcs11-kem.py');adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
    prompt='Unlock IWA credential vault — '+c['algorithm']+' (classical protection)'
    b.emit({'type':'progress','message':prompt+'; enter PIN in the native dialog and touch if requested.'})
    ui=subprocess.run([str(b.root/'build/pin-prompt'),prompt,c['serial']],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
    pin=bytearray(ui.stdout)
    try:
        if ui.returncode or not 6<=len(pin)<=8 or any(x<32 or x>126 for x in pin):raise ValueError('PIN cancelled')
        secret=adapter.recover(c['algorithm'],base64.b64decode(c['public']),peer,str(app/'native/bin/openssl'),str(app/'native/lib/pkcs11.dylib'),str(app/'native/lib/libykcs11.dylib'),c['serial'],c['slot'],pin)
        # ECDH raw output is returned through the scoped pipe only. The browser
        # applies HKDF domain separation and authenticated vault-key unwrapping.
        return {'secret':base64.b64encode(secret).decode(),'fingerprint':c['fingerprint']}
    finally:pin[:]=b'\0'*len(pin)
