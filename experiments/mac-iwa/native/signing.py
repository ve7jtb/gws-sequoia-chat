"""One-use authorization for browser-constructed signatures by a verified token.

The IWA owns certificates, recipient trust, MIME and send confirmation. This
module grants only the fixed enrollment or a freshly authenticated on-key
identity. Grants contain public certificate material and hashes, never messages,
PINs, private keys or digests.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from native_state import write_new,check_certificate


def certificate_hash(path):
    """Bind the complete configured public certificate, including subkeys."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def authority_hash(bridge):
    """Prevent swapping the configured key/backend between preparation and use.

    Hardware configuration is supplied by the installed host, never by a browser
    request. Include its public certificate, serial, adapter directory and sender
    address so a new native process cannot reuse a grant under another identity.
    """
    cfg=bridge.cfg
    authority={key:cfg.get(key) for key in ('cert','serial','app','chat_email')}
    authority['certificateHash']=certificate_hash(cfg['cert'])
    return hashlib.sha256(json.dumps(authority,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def backend_hash(bridge):
    """Bind selected grants to the installed backend, not the default serial.

    A selected identity is authenticated from its own on-key bundle. Changing
    the default vault identity must not silently redirect it. Conversely, code
    or path substitution between prepare and redemption invalidates the grant.
    These are executable/public file hashes; no PIN or token key is read.
    """
    app=Path(bridge.cfg['app'])
    paths=[bridge.root/'runtime/sequoia-iwa-crypto',Path(bridge.cfg['ykman'])]
    paths.extend(app/name for name in ('native/bin/openssl','native/bin/pqmail-pkcs11-sign',
        'native/bin/pqmail-pkcs11-kem','native/lib/pkcs11.dylib','native/lib/libykcs11.dylib',
        'adapters/pkcs11-mu.py','adapters/pkcs11-kem.py','adapters/ykman-mu.py'))
    material={str(path):certificate_hash(path) for path in paths}
    return hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def prepare(bridge,identity=None):
    """Return public sender material and one grant before any PIN/private call.

    Selected identities require fresh public-only card reads; the legacy route
    retains its fixed configured enrollment for existing vault installations.
    """
    if identity is not None:
        from identities import selected
        context,public=selected(bridge,identity)
        rid=secrets.token_hex(24)
        key=public.get('signingFingerprint','')
        if not re.fullmatch('[A-F0-9]{64}',key):raise ValueError('Invalid selected signing key')
        metadata={'created':time.time(),'backendHash':backend_hash(bridge),
                  'selectedIdentity':context,'signingFingerprint':key}
        write_new(bridge.data/('signing-'+rid+'.json'),json.dumps(metadata).encode())
        return {'review':rid,'senderCertificate':context['certificate'],
                'senderEmail':context['email'],'signingFingerprint':key,'identity':dict(identity)}
    own=Path(bridge.cfg['cert']).read_bytes()
    if not 1<=len(own)<=65536:raise ValueError('Certificate limit')
    # Validate the installed sender's current mailbox and select exactly one
    # permitted hybrid subkey. No browser-supplied public key can select a slot.
    check_certificate(bridge,bridge.cfg['cert'],bridge.cfg['chat_email'])
    check={'op':'signing-material','own':base64.b64encode(own).decode()}
    result=subprocess.run([str(bridge.root/'runtime/sequoia-iwa-crypto')],
        input=json.dumps(check).encode(),stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=30)
    if result.returncode or len(result.stdout)>2048:raise ValueError('Invalid signing identity')
    key=json.loads(result.stdout).get('signingFingerprint','')
    if not re.fullmatch('[A-F0-9]{64}',key):raise ValueError('Invalid signing key')
    rid=secrets.token_hex(24)
    metadata={'created':time.time(),'authorityHash':authority_hash(bridge),
              'signingFingerprint':key}
    write_new(bridge.data/('signing-'+rid+'.json'),json.dumps(metadata).encode())
    return {'review':rid,'senderCertificate':base64.b64encode(own).decode(),
            'senderEmail':bridge.cfg['chat_email'],'signingFingerprint':key}


def ticket(bridge,rid):
    """Revalidate grant age, public identity and native backend before a PIN."""
    if not re.fullmatch('[a-f0-9]{48}',rid):raise ValueError('Invalid signing ticket')
    path=bridge.data/('signing-'+rid+'.json')
    if path.is_symlink() or path.stat().st_size>100000:raise ValueError('Invalid signing ticket')
    meta=json.loads(path.read_text())
    age=time.time()-meta['created']
    if not 0<=age<=600:raise ValueError('Expired signing ticket')
    if 'selectedIdentity' in meta:
        if set(meta)!={'created','backendHash','selectedIdentity','signingFingerprint'} or backend_hash(bridge)!=meta['backendHash']:
            raise ValueError('Selected signing backend changed')
        from identities import revalidate_context
        meta['selectedIdentity']=revalidate_context(bridge,meta['selectedIdentity'])
    elif authority_hash(bridge)!=meta['authorityHash']:raise ValueError('Signing identity changed')
    return path,meta


def sign(bridge,request):
    """Consume before the PIN, including cancellation and ambiguous failures.

    Success does not recreate a completion/send ticket. Encryption, current
    recipient trust and single-use send review are now entirely IWA-owned.
    """
    path,meta=ticket(bridge,request['review'])
    if (not re.fullmatch('[A-F0-9]{64}',request['requestId']) or
        request['signingFingerprint']!=meta['signingFingerprint'] or
        type(request['hashAlgorithm']) is not int or request['hashAlgorithm']!=10):
        raise ValueError('Invalid signing binding')
    digest=base64.b64decode(request['digest'],validate=True)
    if len(digest)!=64:raise ValueError('Exactly one SHA-512 digest required')
    # The native operation lock serializes this unlink and the private call.
    # No peer certificate is needed for a signature over a prepared digest.
    path.unlink()
    context=meta.get('selectedIdentity')
    if context is not None:
        result=bridge.crypto('sign-digest',None,digest,service='Message',signing=request,identity=context)
    else:
        result=bridge.crypto('sign-digest',Path(bridge.cfg['cert']),digest,service='Message',signing=request)
    unchanged=backend_hash(bridge)==meta['backendHash'] if context is not None else authority_hash(bridge)==meta['authorityHash']
    if not unchanged:
        raise ValueError('Identity changed during signing')
    return result
