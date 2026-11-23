"""One-use authorization for browser-constructed signatures by the fixed token.

The IWA owns certificates, recipient trust, MIME and send confirmation. This
module owns only a short-lived grant for the installed signing identity. Grants
contain public identity hashes, never recipients, messages, PINs or digests.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time


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


def prepare(bridge):
    """Return the fixed public sender and one grant without touching hardware."""
    own=Path(bridge.cfg['cert']).read_bytes()
    if not 1<=len(own)<=65536:raise ValueError('Certificate limit')
    # Validate the installed sender's current mailbox and select exactly one
    # permitted hybrid subkey. No browser-supplied public key can select a slot.
    bridge.chat.check_cert(bridge.cfg['cert'],bridge.cfg['chat_email'])
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
    bridge.chat.write_new(bridge.data/('signing-'+rid+'.json'),json.dumps(metadata).encode())
    return {'review':rid,'senderCertificate':base64.b64encode(own).decode(),
            'senderEmail':bridge.cfg['chat_email'],'signingFingerprint':key}


def ticket(bridge,rid):
    """Revalidate the grant's age and fixed native authority before a PIN."""
    if not re.fullmatch('[a-f0-9]{48}',rid):raise ValueError('Invalid signing ticket')
    path=bridge.data/('signing-'+rid+'.json')
    if path.is_symlink() or path.stat().st_size>2048:raise ValueError('Invalid signing ticket')
    meta=json.loads(path.read_text())
    age=time.time()-meta['created']
    if not 0<=age<=600:raise ValueError('Expired signing ticket')
    if authority_hash(bridge)!=meta['authorityHash']:raise ValueError('Signing identity changed')
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
    result=bridge.crypto('sign-digest',Path(bridge.cfg['cert']),digest,
                         service='Message',signing=request)
    if authority_hash(bridge)!=meta['authorityHash']:
        raise ValueError('Identity changed during signing')
    return result
