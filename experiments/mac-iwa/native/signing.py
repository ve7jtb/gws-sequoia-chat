"""One-use native authorization for browser-constructed OpenPGP signatures.

Only public routing metadata and certificate hashes are staged. Message bytes,
PINs and signature digests are never written here. The IWA is responsible for
hashing the reviewed MIME; a native digest signer cannot inspect that plaintext.
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
    """Bind the exact locally configured public certificate, not just its ID."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(bridge, request, contact, peer, service, space='Gmail'):
    """Authorize no private operation yet; return material for the WASM worker."""
    subject=request['subject']
    if len(subject)>1000 or any(ord(c)<32 or ord(c)==127 for c in subject):
        raise ValueError('Invalid subject')
    own=Path(bridge.cfg['cert']).read_bytes()
    recipient=peer.read_bytes()
    if len(own)>65536 or len(recipient)>65536:raise ValueError('Certificate limit')
    # Current sender mailbox/key validity is checked without a PIN. The binary
    # selects exactly one v6 ML-DSA-65 + Ed25519 signing subkey from local config.
    bridge.chat.check_cert(bridge.cfg['cert'],bridge.cfg['chat_email'])
    check={'op':'signing-material','own':base64.b64encode(own).decode()}
    result=subprocess.run([str(bridge.root/'runtime/sequoia-iwa-crypto')],
        input=json.dumps(check).encode(),stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=30)
    if result.returncode or len(result.stdout)>2048:raise ValueError('Invalid signing identity')
    key=json.loads(result.stdout).get('signingFingerprint','')
    if not re.fullmatch('[A-F0-9]{64}',key):raise ValueError('Invalid signing key')
    rid=secrets.token_hex(24)
    metadata={'service':service,'space':space,'contact':contact['id'],
              'recipient':contact['email'],'fingerprint':contact['fingerprint'],
              'sender':bridge.cfg['chat_email'],'subject':subject,'created':time.time(),
              'senderHash':hashlib.sha256(own).hexdigest(),
              'recipientHash':hashlib.sha256(recipient).hexdigest(),
              'signingFingerprint':key,'stage':'prepared'}
    bridge.chat.write_new(bridge.data/('encryption-'+rid+'.json'),json.dumps(metadata).encode())
    return {'review':rid,'senderCertificate':base64.b64encode(own).decode(),
            'recipientCertificate':base64.b64encode(recipient).decode(),
            'senderEmail':metadata['sender'],'recipientEmail':metadata['recipient'],
            'recipientFingerprint':metadata['fingerprint'],'signingFingerprint':key,
            'subject':subject,'service':service}


def ticket(bridge,rid,stage):
    """Recheck current local identity/contact before every authorized stage."""
    if not re.fullmatch('[a-f0-9]{48}',rid):raise ValueError('Invalid signing ticket')
    path=bridge.data/('encryption-'+rid+'.json')
    meta=json.loads(path.read_text())
    age=time.time()-meta['created']
    if not 0<=age<=600 or meta.get('stage')!=stage:raise ValueError('Expired or consumed signing ticket')
    contact,peer=bridge.peer(meta['contact'])
    if (contact['email']!=meta['recipient'] or contact['fingerprint']!=meta['fingerprint'] or
        bridge.cfg['chat_email']!=meta['sender'] or
        certificate_hash(bridge.cfg['cert'])!=meta['senderHash'] or
        certificate_hash(peer)!=meta['recipientHash']):
        raise ValueError('Signing identity or contact changed')
    return path,meta,contact,peer


def sign(bridge,request):
    """Consume the grant before PIN prompting, including cancellation/failure.

    The application must prepare a new operation after a failure. Neither a
    replayed request nor an ambiguous native timeout silently signs again.
    """
    path,meta,_,peer=ticket(bridge,request['review'],'prepared')
    if (not re.fullmatch('[A-F0-9]{64}',request['requestId']) or
        request['signingFingerprint']!=meta['signingFingerprint'] or
        type(request['hashAlgorithm']) is not int or request['hashAlgorithm']!=10):
        raise ValueError('Invalid signing binding')
    digest=base64.b64decode(request['digest'],validate=True)
    if len(digest)!=64:raise ValueError('Exactly one SHA-512 digest required')
    # Unlink before any private operation. The host's operation lock serializes
    # this transition; successful signing creates a completion-only ticket.
    path.unlink()
    result=bridge.crypto('sign-digest',peer,digest,service=meta['service'],signing=request)
    # Rechecking the public configuration prevents an identity/contact swap
    # during the native PIN dialog from producing a sendable stale draft.
    if (certificate_hash(bridge.cfg['cert'])!=meta['senderHash'] or
        certificate_hash(peer)!=meta['recipientHash']):
        raise ValueError('Identity changed during signing')
    meta['stage']='signed'
    bridge.chat.write_new(path,json.dumps(meta).encode())
    return result
