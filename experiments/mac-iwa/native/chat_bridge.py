"""Fixed YubiKey private operations and public migration metadata for the IWA.

The browser owns contact certificates, email/fingerprint trust and Google
transport. Paths, slots, PINs and private-key selection remain native-only.
"""
from email.parser import BytesParser
from email import policy
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

# PIV_UNLOCK_DIAGNOSTICS: added for the intermittent vault failure; the cause
# remains unconfirmed after a successful 20-round run. Search this marker for
# removal points. This classifier is independent of the optional disk history:
# keep it for useful safe errors, or coordinate removal with crypto/src/main.rs,
# native/host.py, piv_soak.py and tests/test_vault_bridge.py.
# Only these fixed status codes may cross the diagnostic boundary. Native
# stdout contains session keys; neither stdout nor raw stderr is ever logged.
CRYPTO_STATUS={'MLKEM_FAILED','X25519_FAILED','ADAPTER_TIMEOUT_OR_INPUT',
               'MLKEM_RESPONSE_SIZE','X25519_RESPONSE_SIZE','CRYPTO_FAILED'}
def crypto_status(stderr):
    lines=stderr.splitlines()
    for code in sorted(CRYPTO_STATUS):
        if ('IWA_CRYPTO_STATUS='+code).encode() in lines:return code
    return 'CRYPTO_FAILED'

LIMIT=262144
# The native host is not a contact/trust database or a mail transport. Reject
# legacy APIs at the schema gate, before opening a file or prompting for a PIN.
FIELDS={
    'chat-state':set(),
    'chat-certificate-migration':set(),
    'chat-signing-material':set(),
    'chat-sign-digest':{'review','requestId','signingFingerprint','digest','hashAlgorithm'},
    'chat-decap':{'payload','service'},
    'chat-vault-material':set(),
    'chat-vault-decapsulate':{'payload','recipientKey'},
    'chat-vault-ecdh':{'peer','fingerprint'},
}

def validate(request):
    op=request.get('op')
    if op not in FIELDS or set(request)!=(FIELDS[op]|{'op'}):raise ValueError('Unsupported fields')
    for k,v in request.items():
        if k=='attachments':
            validate_attachments(v)
        elif k=='hashAlgorithm':
            if type(v) is not int or v!=10:raise ValueError('SHA-512 required')
        elif k=='confirmed':
            if v is not True:raise ValueError('Confirmation required')
        elif not isinstance(v,str) or len(v)>400000:raise ValueError('Invalid text')
    if 'page' in request and len(request['page'])>4096:raise ValueError('Page token too long')
    return op

def validate_attachments(files):
    # Browser-provided names are labels only, never native filesystem paths.
    if not isinstance(files,list) or len(files)>10:raise ValueError('At most ten attachments')
    total=0
    for item in files:
        if not isinstance(item,dict) or set(item)!={'name','data'}:raise ValueError('Invalid attachment')
        name=item['name']
        if not isinstance(name,str) or not 1<=len(name)<=150 or any(ord(c)<32 or c in '/\\' for c in name):raise ValueError('Invalid filename')
        if not isinstance(item['data'],str) or len(item['data'])>180000:raise ValueError('Attachment too large')
        total+=len(base64.b64decode(item['data'],validate=True))
        if total>131072:raise ValueError('Attachments exceed 128 KiB')

def compose_mime(chat,request,sender,recipient):
    validate_attachments(request['attachments'])
    # Construct entirely in memory; no plaintext attachment staging files.
    raw=chat.mime_bytes(sender,recipient,request['subject'],request['body'],request['html'] or None)
    msg=BytesParser(policy=policy.SMTP).parsebytes(raw)
    for item in request['attachments']:
        msg.add_attachment(base64.b64decode(item['data'],validate=True),maintype='application',subtype='octet-stream',filename=item['name'])
    raw=msg.as_bytes()
    if len(raw)>LIMIT:raise ValueError('Encoded MIME exceeds 256 KiB')
    return raw

def browser_mime(request,sender,recipient):
    """Authorize browser-composed data against the selected native contact.

    MIME construction/display belong to the IWA. This redundant metadata check
    prevents a compromised request from signing a different address or subject.
    """
    raw=base64.b64decode(request['mime'],validate=True)
    if len(raw)>LIMIT:raise ValueError('MIME exceeds 256 KiB')
    msg=BytesParser(policy=policy.SMTP).parsebytes(raw,headersonly=True)
    for name,value in [('From',sender),('To',recipient),('Subject',request['subject'])]:
        if len(msg.get_all(name,[]))!=1 or str(msg[name])!=value:raise ValueError('Compose metadata mismatch')
    return raw

def crypto_prompt(op,service):
    """Fixed labels selected by the native route, never arbitrary browser text."""
    if service=='Vault' and op=='decapsulate-browser':return 'Unlock IWA credential vault — ML-KEM-768 + X25519'
    if service=='Message' and op=='sign-digest':return 'Sign message — ML-DSA-65 + Ed25519'
    if service not in ('Chat','Gmail') or op not in ('seal','sign-browser','sign-digest','decapsulate-browser','open'):
        raise ValueError('Unsupported cryptographic prompt')
    action='Unlock decryption key for' if op=='decapsulate-browser' else ('Sign' if op in ('sign-browser','sign-digest') else ('Sign and encrypt' if op=='seal' else 'Decrypt and verify'))
    return action+' '+service+(' email' if service=='Gmail' else ' bundle')

class ChatBridge:
    def __init__(self,root,cfg,emit):
        self.root=Path(root);self.cfg=cfg;self.emit=emit
        self.data=self.root/'private/chat-state';self.data.mkdir(exist_ok=True,mode=0o700)
        spec=importlib.util.spec_from_file_location('iwa_chat_transport',self.root/'runtime/chat/chat.py')
        self.chat=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.chat)
    # PIV_UNLOCK_DIAGNOSTICS: optional local history, not part of vault security.
    # To stop recording, remove this method, its two calls below, and the
    # `started` timer. Update the history test in tests/test_vault_bridge.py.
    # Existing vault-diagnostics.json is diagnostic metadata only; removing this
    # code does not delete that file or alter vault wrappers/keys.
    def vault_diagnostic(self,code,started,exit_code):
        # A bounded local history records timing/status only, never the request,
        # PIN, certificate, vault ID, ciphertext, stdout, stderr or shared key.
        path=self.data/'vault-diagnostics.json'
        try:
            history=json.loads(path.read_text()) if path.exists() else []
            if not isinstance(history,list):history=[]
            history.append({'time':int(time.time()),'status':code,
                            'elapsed_ms':round((time.monotonic()-started)*1000),
                            'exit_code':exit_code})
            temporary=path.with_suffix('.tmp')
            with open(temporary,'w',opener=lambda p,f:os.open(p,f,0o600)) as out:
                json.dump(history[-20:],out,indent=2)
            os.replace(temporary,path)
        except (OSError,ValueError):pass # Logging must not trigger a crypto retry.
    def crypto(self,op,peer,payload,service="Chat",signing=None):
        if len(payload)>LIMIT:raise ValueError('Message too large')
        serials=subprocess.check_output([self.cfg['ykman'],'list','--serials'],stderr=subprocess.DEVNULL,timeout=25).decode().split()
        if self.cfg['serial'] not in serials:raise ValueError('Expected YubiKey not connected')
        prompt=crypto_prompt('open' if op=='open-browser' else op,service)
        self.emit({'type':'progress','message':prompt+' — use the native PIN dialog, then touch if requested.'})
        # The PIN never reaches Chrome. Supply only a bounded anonymous pipe to
        # the one-shot worker; both components share this operation's PIN.
        try:
            ui=subprocess.run([str(self.root/'build/pin-prompt'),prompt,self.cfg['serial']],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
        except subprocess.TimeoutExpired:
            # subprocess.run has killed/reaped the dialog. No crypto worker
            # has started, so this fixed label cannot mean a token PIN failure.
            # Never reflect TimeoutExpired: it can contain captured PIN bytes.
            raise ValueError('PIN dialog timed out before submission') from None
        pin=bytearray(ui.stdout)
        try:
            if ui.returncode or not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):raise ValueError('PIN cancelled or invalid')
            app=Path(self.cfg['app'])
            request={'op':op,'pin':pin.decode('ascii'),'own':base64.b64encode(Path(self.cfg['cert']).read_bytes()).decode(),'peer':base64.b64encode(peer.read_bytes()).decode(),'payload':base64.b64encode(payload).decode(),
              'config':{'python':'/usr/bin/python3','adapters':str(app/'adapters'),'openssl':str(app/'native/bin/openssl'),'provider':str(app/'native/lib/pkcs11.dylib'),'module':str(app/'native/lib/libykcs11.dylib'),'serial':self.cfg['serial']}}
            if op=='sign-digest':
                # Only these bounded digest fields cross the private-operation
                # boundary. No message, supplied certificate, slot or PIN comes
                # from the browser; the own certificate/config are local.
                request.pop('payload');request.pop('peer')
                request.update({k:signing[k] for k in ('requestId','signingFingerprint','hashAlgorithm','digest')})
            wire=json.dumps(request).encode();request.pop('pin');del ui
            # PIV_UNLOCK_DIAGNOSTICS: timer is only for the optional history.
            started=time.monotonic()
            try:
                p=subprocess.run([str(self.root/'runtime/sequoia-iwa-crypto')],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=150)
            except subprocess.TimeoutExpired:
                # PIV_UNLOCK_DIAGNOSTICS: removable history call. Keep the
                # timeout exception and no-retry behavior below.
                if service=='Vault':self.vault_diagnostic('HELPER_TIMEOUT',started,None)
                raise ValueError('Vault helper timeout') from None
            finally:del wire
            code=crypto_status(p.stderr) if p.returncode else ('OUTPUT_LIMIT' if len(p.stdout)>LIMIT*2 else 'OK')
            # PIV_UNLOCK_DIAGNOSTICS: removable history call. The exit-status
            # and output-size rejection below MUST remain if logging is removed.
            if service=='Vault':self.vault_diagnostic(code,started,p.returncode)
            if code!='OK':raise ValueError('Vault crypto '+code) if service=='Vault' else ValueError('Cryptographic operation failed; no retry')
            packet=json.loads(p.stdout)
            if op=='sign-digest':
                expected={'requestId','signingFingerprint','hashAlgorithm','digest','ed25519','mldsa65'}
                if set(packet)!=expected or any(packet[k]!=signing[k] for k in ('requestId','signingFingerprint','hashAlgorithm','digest')):
                    raise ValueError('Signature response binding mismatch')
                if len(base64.b64decode(packet['ed25519'],validate=True))!=64 or len(base64.b64decode(packet['mldsa65'],validate=True))!=3309:
                    raise ValueError('Signature component size mismatch')
                return packet
            result=base64.b64decode(packet['data'],validate=True)
            if len(result)>LIMIT:raise ValueError('Oversize cryptographic result')
            if op=='decapsulate-browser':
                # Per-message secret: relay only in memory, never persist/log.
                if len(result) not in (16,24,32) or packet.get('algorithm') not in (7,8,9):raise ValueError('Invalid session key')
                if packet.get('cipherHash')!=hashlib.sha256(payload).hexdigest():raise ValueError('Ciphertext mismatch')
                if not re.fullmatch('[A-F0-9]{64}',packet.get('recipientKey','')):raise ValueError('Invalid recipient key')
                return {'sessionKey':packet['data'],'algorithm':packet['algorithm'],'cipherHash':packet['cipherHash'],'recipientKey':packet['recipientKey']}
            if op=='open-browser':
                signature=base64.b64decode(packet['signature'],validate=True)
                if not 1<=len(signature)<=65536:raise ValueError('Invalid signature packet size')
                return {'raw':packet['data'],'signature':packet['signature'],'encrypted':True}
            return result
        finally:pin[:]=b'\0'*len(pin)
    def action(self,request):
        # A stale browser/extension cannot revive native contact mutations or
        # Google transport. Only fixed private operations and a public migration
        # snapshot remain; every request is closed-schema validated first.
        op=validate(request)
        with (self.data/'operation.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if op=='chat-certificate-migration':
                from certificate_migration import snapshot
                return snapshot(self)
            if op=='chat-signing-material':
                from signing import prepare
                return prepare(self)
            if op=='chat-sign-digest':
                from signing import sign
                return sign(self,request)
            if op=='chat-decap':
                if request['service'] not in ('Gmail','Chat'):raise ValueError('Unknown service')
                cipher=base64.b64decode(request['payload'],validate=True)
                if not 1<=len(cipher)<=LIMIT:raise ValueError('Ciphertext limit')
                # Recipient selection and hardware slots come only from local
                # configuration. The browser verifies sender/trust after AEAD.
                result=self.crypto('decapsulate-browser',Path(self.cfg['cert']),cipher,
                                   service=request['service'])
                return {**result,'cipher':request['payload']}
            if op=='chat-vault-ecdh':
                from vault_piv import recover
                return recover(self,request)
            if op=='chat-vault-material':
                raw=Path(self.cfg['cert']).read_bytes()
                if len(raw)>65536:raise ValueError('Certificate limit')
                from vault_piv import configured
                return {'certificate':base64.b64encode(raw).decode(),'serial':self.cfg['serial'],'algorithm':'ML-KEM-768 + X25519','classical':configured(self)}
            if op=='chat-vault-decapsulate':
                if not re.fullmatch('[A-F0-9]{64}',request['recipientKey']):raise ValueError('Invalid recipient')
                cipher=base64.b64decode(request['payload'],validate=True)
                if not 1<=len(cipher)<=16384:raise ValueError('Vault envelope limit')
                result=self.crypto('decapsulate-browser',Path(self.cfg['cert']),cipher,service='Vault')
                if result['recipientKey']!=request['recipientKey']:raise ValueError('Wrong PIV key')
                return result
            if op=='chat-state':
                # The configured sender certificate is hardware-binding metadata,
                # not a recipient trust decision. Never return native contacts.
                own=self.chat.check_cert(self.cfg['cert'],self.cfg['chat_email'])
                return {'account':self.cfg['chat_email'],'serial':self.cfg['serial'],
                        'identity':own,'contacts':[]}
            raise ValueError('Unknown operation')
