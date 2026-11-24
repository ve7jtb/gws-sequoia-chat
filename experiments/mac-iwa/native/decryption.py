"""One-use verified-key authority for browser-owned OpenPGP decapsulation.

The browser parses recipient packets, combines the two component secrets and
unwraps the session key. Native code authorizes only one pair of private PIV
operations, never browser-selected slots, paths, algorithms or certificates.
"""
import base64
import json
import re
import secrets
import subprocess
import time

from signing import authority_hash,backend_hash

BINDINGS=('requestId','cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral')
SERVICES=('Chat','Gmail','Vault','Hardware test')

from native_state import write_new,check_certificate


def canonical_bytes(value,size):
    """Reject ambiguous encodings before a PIN or native private operation."""
    if not isinstance(value,str) or len(value)!=4*((size+2)//3):
        raise ValueError('Invalid component encoding')
    try:
        raw=base64.b64decode(value,validate=True)
    except (ValueError,TypeError):
        raise ValueError('Invalid component encoding') from None
    if len(raw)!=size or base64.b64encode(raw).decode()!=value:
        raise ValueError('Invalid component encoding')
    return raw


def validate_components(request):
    """The ciphertext hash is an opaque operation binding, not a native claim
    that its unseen OpenPGP envelope was parsed. WASM checks this against its
    retained ciphertext and compares every echoed input before using secrets.
    """
    for name,pattern in [('review','[a-f0-9]{48}'),('requestId','[A-F0-9]{64}'),
                         ('cipherHash','[a-f0-9]{64}'),('recipientKey','[A-F0-9]{64}')]:
        if not isinstance(request.get(name),str) or not re.fullmatch(pattern,request[name]):
            raise ValueError('Invalid decryption binding')
    if request.get('service') not in SERVICES:raise ValueError('Unknown service')
    canonical_bytes(request.get('mlkemCiphertext'),1088)
    ephemeral=canonical_bytes(request.get('x25519Ephemeral'),32)
    if not any(ephemeral):raise ValueError('Invalid X25519 public input')


def prepare(bridge,service,identity=None):
    """Authenticate public identity material and create a short-lived grant.

    The grant contains no ciphertext, token PIN, shared secret or session key.
    Slot authority remains in the installed backend and certificate mapping.
    """
    if service not in SERVICES:raise ValueError('Unknown service')
    if identity is not None:
        # Vault wrappers retain their original fixed identity enrollment. A
        # message's recipient selection cannot redirect a vault unlock.
        if service=='Vault':raise ValueError('Selected identity is not a vault enrollment')
        from identities import selected
        context,public=selected(bridge,identity)
        key=public.get('recipientKey','')
        if not re.fullmatch('[A-F0-9]{64}',key):raise ValueError('Invalid selected decryption key')
        review=secrets.token_hex(24)
        record={'created':time.time(),'backendHash':backend_hash(bridge),
                'selectedIdentity':context,'recipientKey':key,'service':service}
        write_new(bridge.data/('decryption-'+review+'.json'),json.dumps(record).encode())
        return {'review':review,'recipientCertificate':context['certificate'],'recipientKey':key,'identity':dict(identity)}
    from pathlib import Path
    own=Path(bridge.cfg['cert']).read_bytes()
    if not 1<=len(own)<=65536:raise ValueError('Certificate limit')
    check_certificate(bridge,bridge.cfg['cert'],bridge.cfg['chat_email'])
    response=subprocess.run([str(bridge.root/'runtime/sequoia-iwa-crypto')],
        input=json.dumps({'op':'decryption-material','own':base64.b64encode(own).decode()}).encode(),
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if response.returncode or len(response.stdout)>2048:raise ValueError('Invalid decryption identity')
    key=json.loads(response.stdout).get('recipientKey','')
    if not re.fullmatch('[A-F0-9]{64}',key):raise ValueError('Invalid decryption key')
    review=secrets.token_hex(24)
    record={'created':time.time(),'authorityHash':authority_hash(bridge),
            'recipientKey':key,'service':service}
    write_new(bridge.data/('decryption-'+review+'.json'),json.dumps(record).encode())
    return {'review':review,'recipientCertificate':base64.b64encode(own).decode(),'recipientKey':key}


def components(bridge,request):
    """Consume the grant before showing a PIN, including cancellation/failure.

    An incomplete two-component operation never yields a partial result or a
    reusable authorization. The caller must explicitly start another operation.
    """
    validate_components(request)
    path=bridge.data/('decryption-'+request['review']+'.json')
    if path.is_symlink() or path.stat().st_size>100000:raise ValueError('Invalid decryption grant')
    record=json.loads(path.read_text())
    age=time.time()-record['created']
    if not 0<=age<=600:raise ValueError('Expired decryption grant')
    context=record.get('selectedIdentity')
    if context is not None:
        if set(record)!={'created','backendHash','selectedIdentity','recipientKey','service'} or record['service']=='Vault' or backend_hash(bridge)!=record['backendHash']:
            raise ValueError('Selected decryption backend changed')
        from identities import revalidate_context
        context=revalidate_context(bridge,context)
    elif authority_hash(bridge)!=record['authorityHash']:raise ValueError('Decryption identity changed')
    if request['recipientKey']!=record['recipientKey'] or request['service']!=record['service']:
        raise ValueError('Decryption grant mismatch')
    # ChatBridge.action holds an interprocess lock across this unlink and PIN/
    # token transaction. No second browser window can redeem the same grant.
    path.unlink()
    from pathlib import Path
    if context is not None:
        result=bridge.crypto('decapsulate-components',None,b'',service=request['service'],components=request,identity=context)
    else:
        result=bridge.crypto('decapsulate-components',Path(bridge.cfg['cert']),b'',service=request['service'],components=request)
    unchanged=backend_hash(bridge)==record['backendHash'] if context is not None else authority_hash(bridge)==record['authorityHash']
    if not unchanged:
        raise ValueError('Identity changed during decapsulation')
    return result
