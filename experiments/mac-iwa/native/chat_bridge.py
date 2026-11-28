"""Fixed YubiKey private operations and public migration metadata for the IWA.

The browser owns contact certificates, email/fingerprint trust and Google
transport. Paths, slots, PINs and private-key selection remain native-only.
"""
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time

from native_state import check_certificate

# PIV_UNLOCK_DIAGNOSTICS: added for the intermittent vault failure; the cause
# remains unconfirmed after a successful 20-round run. Search this marker for
# removal points. This classifier is independent of the optional disk history:
# keep it for useful safe errors, or coordinate removal with crypto/src/main.rs,
# the retired native host and the retained standalone diagnostic tests.
# Only these fixed status codes may cross the diagnostic boundary. Native
# stdout contains session keys; neither stdout nor raw stderr is ever logged.
CRYPTO_STATUS={'MLKEM_FAILED','X25519_FAILED','ADAPTER_TIMEOUT_OR_INPUT',
               'MLKEM_RESPONSE_SIZE','X25519_RESPONSE_SIZE','CRYPTO_FAILED',
               'COMPANION_CONTEXT_FAILED','HARDWARE_SIGN_FAILED',
               'HARDWARE_DECAP_FAILED','COMPANION_WRAP_FAILED',
               'ADAPTER_START_FAILED','ADAPTER_INPUT_FAILED','ADAPTER_WAIT_FAILED',
               'ADAPTER_TIMEOUT','ADAPTER_EXIT_FAILED','ADAPTER_OUTPUT_LIMIT','ADAPTER_OUTPUT_ENCODING',
               'SIGNATURE_LENGTH_FAILED','SIGNATURE_DECODE_FAILED','SIGNATURE_COMPONENT_VERIFY_FAILED',
               'SIGNATURE_COMPOSITE_VERIFY_FAILED','PKCS11_HELPER_PUBLIC_KEY_FAILED',
               'PKCS11_HELPER_PRIVATE_KEY_FAILED','PKCS11_HELPER_SIGN_FAILED','PKCS11_HELPER_VERIFY_FAILED',
               'PKCS11_HELPER_INITIALIZE_FAILED','PKCS11_HELPER_PARAMETERS_FAILED',
               'PKCS11_HELPER_INPUT_FAILED','PKCS11_HELPER_OUTPUT_FAILED'}
# Message diagnostics are intentionally a closed vocabulary. A component's
# stderr, returned shares, certificate and PIN can never become a log field.
MESSAGE_STATUS={'PIN_DIALOG_STARTED','PIN_DIALOG_TIMEOUT','PIN_REJECTED_LOCALLY',
                'PIN_RECEIVED_LOCALLY','WORKER_STARTED','WORKER_TIMEOUT',
                'WORKER_SUCCEEDED','RESPONSE_VALIDATED','RESPONSE_REJECTED',
                'WORKER_OUTPUT_LIMIT'}|{'WORKER_'+code for code in CRYPTO_STATUS}
def crypto_status(stderr):
    lines=stderr.splitlines()
    for code in sorted(CRYPTO_STATUS):
        if ('IWA_CRYPTO_STATUS='+code).encode() in lines:return code
    return 'CRYPTO_FAILED'

def crypto_evidence(stderr):
    """Read only the worker's bounded numeric error/callback protocol.

    Library reason strings and raw provider output are intentionally excluded.
    A six-to-eight-digit PIN cannot be mistaken for the four-digit maximum
    callback count. Unknown lines, malformed fields and duplicate counts fail
    closed rather than becoming an arbitrary diagnostic text channel.
    """
    if not isinstance(stderr,bytes) or len(stderr)>32768:return {}
    codes=[];callbacks=None;callback_seen=False;pkcs11=[];pcsc=[]
    for line in stderr.splitlines():
        match=re.fullmatch(rb'IWA_CRYPTO_PCSC=(SCardTransmit|SCardBeginTransaction|SCardEndTransaction|SCardReconnect):([0-9A-F]{8}):([0-9]{1,6})(?::([0-9]{1,5})(?::([0-9A-F]{4}))?)?',line)
        if match:
            row={'method':match.group(1).decode('ascii'),'rv':match.group(2).decode('ascii'),'elapsed_ms':int(match.group(3))}
            if match.group(4):row['responseLength']=int(match.group(4))
            if match.group(5):row['statusWord']=match.group(5).decode('ascii')
            if len(pcsc)<96 and valid_pcsc(row):pcsc.append(row)
            continue
        match=re.fullmatch(rb'IWA_CRYPTO_PKCS11=(C_Login|C_SignInit|C_Sign):([0-9A-F]{8,16})',line)
        if match:
            if len(pkcs11)<16:pkcs11.append({'method':match.group(1).decode('ascii'),'rv':match.group(2).decode('ascii')})
            continue
        match=re.fullmatch(rb'IWA_CRYPTO_ERROR=([0-9A-F]{8,16})',line)
        if match:
            code=match.group(1).decode('ascii')
            if code not in codes and len(codes)<8:codes.append(code)
            continue
        if line.startswith(b'IWA_CRYPTO_PIN_CALLBACKS='):
            if callback_seen:callbacks=None;continue
            callback_seen=True
            match=re.fullmatch(rb'IWA_CRYPTO_PIN_CALLBACKS=([0-9]{1,4})',line)
            if match:callbacks=int(match.group(1))
    return {**({'pcscCalls':pcsc} if pcsc else {}),**({'pkcs11Calls':pkcs11} if pkcs11 else {}),**({'opensslErrorCodes':codes} if codes else {}),
            **({'pinCallbacks':callbacks} if callbacks is not None else {})}

def valid_pcsc(row):
    """Validate transport metadata; no arbitrary function names or body data."""
    if not isinstance(row,dict) or not {'method','rv','elapsed_ms'}<=set(row)<={'method','rv','elapsed_ms','responseLength','statusWord'}:return False
    if row['method'] not in ('SCardTransmit','SCardBeginTransaction','SCardEndTransaction','SCardReconnect') or not isinstance(row['rv'],str) or not re.fullmatch('[0-9A-F]{8}',row['rv']):return False
    if type(row['elapsed_ms']) is not int or not 0<=row['elapsed_ms']<=120000:return False
    if 'responseLength' in row and (row['method']!='SCardTransmit' or row['rv']!='00000000' or type(row['responseLength']) is not int or not 0<=row['responseLength']<=65536):return False
    if 'statusWord' in row and (row.get('responseLength',0)<2 or not isinstance(row['statusWord'],str) or not re.fullmatch('[0-9A-F]{4}',row['statusWord'])):return False
    return True

def evidence_fields(value):
    """Validate already-parsed history fields before copying them to disk."""
    if not isinstance(value,dict) or not set(value)<={'opensslErrorCodes','pinCallbacks','pkcs11Calls','pcscCalls'}:return None
    if 'pcscCalls' in value and (not isinstance(value['pcscCalls'],list) or not 1<=len(value['pcscCalls'])<=96 or not all(valid_pcsc(row) for row in value['pcscCalls'])):return None
    if 'pkcs11Calls' in value:
        rows=value['pkcs11Calls']
        if not isinstance(rows,list) or not 1<=len(rows)<=16:return None
        for row in rows:
            if not isinstance(row,dict) or set(row)!={'method','rv'} or row.get('method') not in ('C_Login','C_SignInit','C_Sign') or not isinstance(row.get('rv'),str) or not re.fullmatch('[0-9A-F]{8,16}',row['rv']):return None
    if 'opensslErrorCodes' in value:
        codes=value['opensslErrorCodes']
        if not isinstance(codes,list) or not 1<=len(codes)<=8 or any(not isinstance(c,str) or not re.fullmatch('[0-9A-F]{8,16}',c) for c in codes):return None
    if 'pinCallbacks' in value and (type(value['pinCallbacks']) is not int or not 0<=value['pinCallbacks']<=9999):return None
    return dict(value)

LIMIT=262144
# The native host is not a contact/trust database or a mail transport. Reject
# legacy APIs at the schema gate, before opening a file or prompting for a PIN.
FIELDS={
    'chat-state':set(),
    'chat-certificate-migration':set(),
    'chat-identity-current':set(),
    'chat-identity-devices':set(),
    'chat-identity-companion-read':{'serial'},
    'chat-identity-bundle-read':set(),
    'chat-identity-key-snapshot':set(),
    'chat-hardware-audit':{'identity'},
    'chat-selected-signing-material':{'identity'},
    'chat-sign-digest':{'review','requestId','signingFingerprint','digest','hashAlgorithm'},
    'chat-decryption-material':{'service'},
    'chat-selected-decryption-material':{'service','identity'},
    'chat-decapsulate-components':{'review','service','requestId','cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral'},
    'chat-vault-material':set(),
    'chat-vault-ecdh':{'peer','fingerprint'},
}

def validate(request):
    op=request.get('op')
    optional={'serial'} if op in ('chat-identity-bundle-read','chat-identity-key-snapshot') else {'inlineDigest'} if op=='chat-sign-digest' else {'certificate'} if op=='chat-identity-companion-read' else set()
    if op not in FIELDS or not (FIELDS[op]|{'op'})<=set(request) or set(request)-(FIELDS[op]|{'op'})-optional:raise ValueError('Unsupported fields')
    for k,v in request.items():
        if k=='identity':
            from identities import selection
            selection(v)
        elif k=='hashAlgorithm':
            if type(v) is not int or v!=10:raise ValueError('SHA-512 required')
        elif not isinstance(v,str) or len(v)>400000:raise ValueError('Invalid text')
    if op=='chat-decryption-material' and request['service']!='Vault':
        raise ValueError('Unknown service')
    if op=='chat-selected-decryption-material' and request['service'] not in ('Chat','Gmail','Hardware test'):
        raise ValueError('Selected identity is for messages only')
    if op=='chat-decapsulate-components':
        from decryption import validate_components
        validate_components(request)
    return op

def crypto_prompt(op,service,identity=None):
    """Only component operations have native PIN dialogs; labels are fixed.

    Tests use the same private boundary as messages. Their distinct public
    purpose changes only this label, never the slot mapping or PIN semantics.
    Retired full-message operations cannot revive native MIME or OpenPGP work.
    """
    if identity is not None:
        role='signing-' if op=='sign-digest' else 'decryption-'
        algorithms=' + '.join(row['algorithm'] for row in identity['components'] if row['role'].startswith(role))
        if not algorithms:raise ValueError('Missing operation components')
        label='Sign message' if op=='sign-digest' else 'Decrypt '+('local hardware test' if service=='Hardware test' else service)
        return label+' — '+algorithms
    if op=='sign-digest' and service=='Message':
        return 'Sign message — ML-DSA-65 + Ed25519'
    if op!='decapsulate-components':raise ValueError('Unsupported cryptographic prompt')
    if service=='Vault':return 'Unlock IWA credential vault — ML-KEM-768 + X25519'
    if service=='Hardware test':return 'Decrypt local hardware test — ML-KEM-768 + X25519'
    if service not in ('Chat','Gmail'):raise ValueError('Unsupported cryptographic prompt')
    return 'Unlock decryption key for '+service+(' email' if service=='Gmail' else ' bundle')+' — ML-KEM-768 + X25519'

class ChatBridge:
    def __init__(self,root,cfg,emit):
        self.root=Path(root);self.cfg=cfg;self.emit=emit
        self.data=self.root/'private/chat-state';self.data.mkdir(exist_ok=True,mode=0o700)
        # No standalone mail/Chat module, gws, sq executable, Java runtime or
        # legacy transport configuration is loaded by a hardware operation.
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
    def message_diagnostic(self,op,status,started,exit_code=None,evidence=None):
        """Record only fixed phase evidence, independently of crypto success.

        One private request may fail before a PIN, in the hardware component,
        in wrapping-key ECDH, or after return to WASM. The UI's request counter
        alone cannot distinguish these boundaries. This bounded metadata log
        never contains input/output bytes and cannot authorize a retry.
        """
        if op not in ('sign-digest','decapsulate-components') or status not in MESSAGE_STATUS:
            return
        if exit_code is not None and (type(exit_code) is not int or not -255<=exit_code<=255):
            exit_code=None
        entry={'time':int(time.time()),'operation':op,'status':status,
               'elapsed_ms':max(0,round((time.monotonic()-started)*1000)),
               'exit_code':exit_code}
        base_fields=set(entry)
        details=evidence_fields(evidence or {}) or {}
        entry.update(details)
        self.emit({'type':'progress','stage':'PRIVATE_OPERATION_DIAGNOSTIC',
                   'operation':op,'status':status,'message':'Native operation stage: '+status+'.',**details})
        try:
            path=self.root/'private/chat-state/message-crypto-diagnostics.json'
            # Never copy arbitrary old fields into a fresh diagnostic record.
            # A corrupted/oversized history is discarded, not echoed or parsed
            # as an operation request. No diagnostic path is browser supplied.
            history=json.loads(path.read_text()) if path.exists() and not path.is_symlink() and path.stat().st_size<=32768 else []
            if not isinstance(history,list):history=[]
            history=[item for item in history if isinstance(item,dict) and
                     base_fields<=set(item)<=base_fields|{'opensslErrorCodes','pinCallbacks','pkcs11Calls','pcscCalls'} and
                     evidence_fields({k:v for k,v in item.items() if k not in base_fields}) is not None and
                     item.get('operation') in ('sign-digest','decapsulate-components') and
                     item.get('status') in MESSAGE_STATUS and type(item.get('time')) is int and
                     type(item.get('elapsed_ms')) is int and
                     (item.get('exit_code') is None or type(item.get('exit_code')) is int)]
            temporary=path.with_suffix('.tmp')
            with open(temporary,'w',opener=lambda p,f:os.open(p,f,0o600)) as output:
                json.dump((history+[entry])[-40:],output,indent=2)
            os.replace(temporary,path)
        except (OSError,ValueError,TypeError):pass # Diagnostics never retry private work.
    def crypto(self,op,peer,payload,service="Chat",signing=None,components=None,identity=None):
        if op not in ('sign-digest','decapsulate-components'):
            raise ValueError('Unsupported private operation')
        if op=='decapsulate-components':
            from decryption import validate_components
            validate_components(components)
        if len(payload)>64:raise ValueError('Digest size limit')
        # Selected authority comes only from a consumed native grant created
        # after signed-bundle and live-public-key verification. Never mutate
        # self.cfg: existing vault enrollments and simultaneous app windows
        # must retain the configured default identity.
        chosen_serial=self.cfg['serial']
        own=None
        if identity is not None:
            if op not in ('sign-digest','decapsulate-components') or service=='Vault':
                raise ValueError('Selected identity is for message operations only')
            from identities import operation_context
            identity=operation_context(identity)
            chosen_serial=identity['serial'];own=identity['certificate']
        serials=subprocess.check_output([self.cfg['ykman'],'list','--serials'],stderr=subprocess.DEVNULL,timeout=25).decode().split()
        if chosen_serial not in serials:raise ValueError('Connect YubiKey '+chosen_serial)
        prompt=crypto_prompt(op,service,identity)
        diagnostic_started=time.monotonic()
        def diagnostic(status,exit_code=None,evidence=None):
            if service!='Vault':self.message_diagnostic(op,status,diagnostic_started,exit_code,evidence)
        self.emit({'type':'progress','message':prompt+' — use the native PIN dialog, then touch if requested.'})
        # The PIN never reaches Chrome. Supply only a bounded anonymous pipe to
        # the one-shot worker; both components share this operation's PIN.
        self.emit({'type':'progress','stage':'PIN_DIALOG_STARTED','operation':op,'message':'Waiting for the native YubiKey PIN dialog; no PIN has been submitted.'})
        diagnostic('PIN_DIALOG_STARTED')
        try:
            ui=subprocess.run([str((self.root/'build/pin-prompt').resolve()),prompt,chosen_serial],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
        except subprocess.TimeoutExpired:
            # subprocess.run has killed/reaped the dialog. No crypto worker
            # has started, so this fixed label cannot mean a token PIN failure.
            # Never reflect TimeoutExpired: it can contain captured PIN bytes.
            self.emit({'type':'progress','stage':'PIN_DIALOG_TIMEOUT','operation':op,'message':'The PIN dialog timed out. No PIN was sent to the YubiKey.'})
            diagnostic('PIN_DIALOG_TIMEOUT')
            raise ValueError('PIN dialog timed out before submission') from None
        pin=bytearray(ui.stdout)
        response_received=False
        response_validated=False
        try:
            if ui.returncode or not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):
                self.emit({'type':'progress','stage':'PIN_REJECTED_LOCALLY','operation':op,'message':'PIN entry was cancelled or rejected locally. No PIN was sent to the YubiKey.'})
                diagnostic('PIN_REJECTED_LOCALLY',ui.returncode)
                raise ValueError('PIN cancelled or invalid')
            self.emit({'type':'progress','stage':'PIN_RECEIVED_LOCALLY','operation':op,'message':'PIN received by the native helper; it has not been sent to the YubiKey yet.'})
            diagnostic('PIN_RECEIVED_LOCALLY')
            if own is None:own=base64.b64encode(Path(self.cfg['cert']).read_bytes()).decode()
            app=Path(self.cfg['app'])
            request={'op':op,'pin':pin.decode('ascii'),'own':own,
              'config':{'python':'/usr/bin/python3','adapters':str(app/'adapters'),'openssl':str(app/'native/bin/openssl'),'provider':str(app/'native/lib/pkcs11.dylib'),'module':str(app/'native/lib/libykcs11.dylib'),'serial':chosen_serial}}
            if identity is not None:request['hardware']=identity
            if op=='sign-digest':
                if 'inlineDigest' in signing:request['inlineDigest']=signing['inlineDigest']
                # Only these bounded digest fields cross the private-operation
                # boundary. No message, supplied certificate, slot or PIN comes
                # from the browser; the own certificate/config are local.
                request.update({k:signing[k] for k in ('requestId','signingFingerprint','hashAlgorithm','digest')})
            if op=='decapsulate-components':
                # The whole OpenPGP envelope and wrapped session key never
                # reach native code. Only bounded component inputs and opaque
                # bindings are allowed; expected keys remain locally configured.
                from decryption import BINDINGS
                request.update({k:components[k] for k in BINDINGS})
            wire=json.dumps(request).encode();request.pop('pin');del ui
            # PIV_UNLOCK_DIAGNOSTICS: timer is only for the optional history.
            started=time.monotonic()
            self.emit({'type':'progress','stage':'PRIVATE_WORKER_STARTED','operation':op,'message':'The native private-operation worker has started.'})
            diagnostic('WORKER_STARTED')
            try:
                p=subprocess.run([str(self.root/'runtime/sequoia-iwa-crypto')],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=150)
            except subprocess.TimeoutExpired:
                # PIV_UNLOCK_DIAGNOSTICS: removable history call. Keep the
                # timeout exception and no-retry behavior below.
                if service=='Vault':self.vault_diagnostic('HELPER_TIMEOUT',started,None)
                diagnostic('WORKER_TIMEOUT')
                raise ValueError('Vault helper timeout') from None
            finally:del wire
            code=crypto_status(p.stderr) if p.returncode else ('OUTPUT_LIMIT' if len(p.stdout)>LIMIT*2 else 'OK')
            # PIV_UNLOCK_DIAGNOSTICS: removable history call. The exit-status
            # and output-size rejection below MUST remain if logging is removed.
            if service=='Vault':self.vault_diagnostic(code,started,p.returncode)
            if code!='OK':
                diagnostic('WORKER_'+code,p.returncode,crypto_evidence(p.stderr))
                raise ValueError('Vault crypto '+code) if service=='Vault' else ValueError('Cryptographic operation failed; no retry')
            diagnostic('WORKER_SUCCEEDED',p.returncode,crypto_evidence(p.stderr))
            response_received=True
            packet=json.loads(p.stdout)
            from decryption import canonical_bytes
            companion=identity is not None and 'companion' in identity
            extra={'companion','companionShared'} if companion else set()
            if companion:
                if packet.get('companion')!=identity['companion'] or not any(canonical_bytes(packet.get('companionShared'),48)):
                    raise ValueError('Companion response binding mismatch')
            # The authenticated row determines exact share/signature sizes.
            # Legacy field names are retained for IPC compatibility; they do
            # not authorize a particular algorithm or a missing component.
            def size(role,sign):
                if identity is None:return (3309 if role.endswith('pq') else 64) if sign else 32
                row=next((r for r in identity['components'] if r['role']==role),None)
                if row is None or row['storage']=='companion':return 0
                lengths={'ML-DSA-65':3309,'ML-DSA-87':4627,'Ed25519':64,'Ed448':114,
                         'P-384':96 if sign else 48,'ECDSA-P384':96,'ECDH-P384':48,
                         'P-521':132 if sign else 66,'X25519':32,'X448':56,
                         'ML-KEM-768':32,'ML-KEM-1024':32}
                return lengths[row['algorithm']]
            if op=='sign-digest':
                expected={'requestId','signingFingerprint','hashAlgorithm','digest','ed25519','mldsa65'}|extra
                if 'inlineDigest' in signing:expected|={'inlineDigest','inlineEd25519'}
                if set(packet)!=expected or any(packet[k]!=signing[k] for k in ('requestId','signingFingerprint','hashAlgorithm','digest')):
                    raise ValueError('Signature response binding mismatch')
                canonical_bytes(packet['ed25519'],size('signing-classical',True))
                canonical_bytes(packet['mldsa65'],size('signing-pq',True))
                if 'inlineDigest' in signing:
                    if packet['inlineDigest']!=signing['inlineDigest']:raise ValueError('Inline digest mismatch')
                    canonical_bytes(packet['inlineEd25519'],64)
                response_validated=True
                diagnostic('RESPONSE_VALIDATED',p.returncode)
                return packet
            if op=='decapsulate-components':
                from decryption import BINDINGS
                if set(packet)!=set(BINDINGS)|{'mlkemSecret','x25519Secret'}|extra or any(packet[k]!=components[k] for k in BINDINGS):
                    raise ValueError('Decapsulation response binding mismatch')
                canonical_bytes(packet['mlkemSecret'],size('decryption-pq',False))
                length=size('decryption-classical',False)
                shared=canonical_bytes(packet['x25519Secret'],length)
                if length and not any(shared):raise ValueError('Invalid ECDH shared secret')
                response_validated=True
                diagnostic('RESPONSE_VALIDATED',p.returncode)
                return packet
            raise ValueError('Unsupported private response')
        finally:
            pin[:]=b'\0'*len(pin)
            if response_received and not response_validated:diagnostic('RESPONSE_REJECTED')
    def action(self,request):
        # A stale browser/extension cannot revive native contact mutations or
        # Google transport. Only fixed private operations and a public migration
        # snapshot remain; every request is closed-schema validated first.
        op=validate(request)
        with (self.data/'operation.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if op=='chat-hardware-audit':
                from hardware_audit import snapshot
                return snapshot(self,request['identity'])
            if op=='chat-identity-devices':
                from identities import devices
                return devices(self)
            if op=='chat-identity-companion-read':
                from identities import companion_preview
                return companion_preview(self,request['serial'],request.get('certificate'))
            if op=='chat-identity-current':
                from identities import current
                return current(self)
            if op in ('chat-identity-bundle-read','chat-identity-key-snapshot'):
                # Browser inspection owns bundle parsing; native is a bounded
                # read-only transport. Full native restore remains internal to
                # selected() before a private-operation grant is constructed.
                from identities import public_snapshot
                return public_snapshot(self,op=='chat-identity-bundle-read',request.get('serial'))
            if op=='chat-certificate-migration':
                from certificate_migration import snapshot
                return snapshot(self)
            if op=='chat-selected-signing-material':
                from signing import prepare
                return prepare(self,request['identity'])
            if op=='chat-sign-digest':
                from signing import sign
                return sign(self,request)
            if op=='chat-decryption-material':
                from decryption import prepare
                return prepare(self,request['service'])
            if op=='chat-selected-decryption-material':
                from decryption import prepare
                return prepare(self,request['service'],request['identity'])
            if op=='chat-decapsulate-components':
                from decryption import components
                return components(self,request)
            if op=='chat-vault-ecdh':
                from vault_piv import recover
                return recover(self,request)
            if op=='chat-vault-material':
                raw=Path(self.cfg['cert']).read_bytes()
                if len(raw)>65536:raise ValueError('Certificate limit')
                from vault_piv import configured
                return {'certificate':base64.b64encode(raw).decode(),'serial':self.cfg['serial'],'algorithm':'ML-KEM-768 + X25519','classical':configured(self)}
            if op=='chat-state':
                # The configured sender certificate is hardware-binding metadata,
                # not a recipient trust decision. Never return native contacts.
                own=check_certificate(self,self.cfg['cert'],self.cfg['chat_email'])
                return {'account':self.cfg['chat_email'],'serial':self.cfg['serial'],
                        'identity':own,'contacts':[]}
            raise ValueError('Unknown operation')


# Fixed public errors for the standalone diagnostic harness.
def operation_error(op, error=None):
    """Return fixed, operation-specific guidance without exposing CLI secrets.

    Connection failures happen before the hardware operation. Keep them separate
    from signing/decryption failures so users do not unnecessarily retry a PIN.
    """
    if op and op.startswith('chat-'):
        # Only fixed pre-crypto labels get this explanation. Never expose the
        # exception text/output or turn a private-operation error into a retry.
        if str(error)=='PIN dialog timed out before submission':
            return 'The native PIN dialog timed out before submission. No PIN was sent to the YubiKey. Start the operation again and look for the YubiKey PIN dialog or pin-prompt in the Dock or Command-Tab.'
        if str(error)=='PIN cancelled or invalid':
            return 'PIN entry was cancelled or its format was rejected locally. No PIN was sent to the YubiKey. No automatic retry was performed.'
        # Only a strictly numeric serial from our pre-PIN presence check may
        # enter this guidance. Never surface arbitrary backend exception text.
        missing=re.fullmatch(r'Connect YubiKey ([1-9][0-9]{0,9})',str(error))
        if missing and int(missing.group(1))<=2147483647:
            return 'Connect YubiKey '+missing.group(1)+'. No PIN was submitted. Retry only after connecting that key.'
    if op in ('chat-selected-signing-material','chat-selected-decryption-material'):
        return 'Selected identity review stopped. Connect the selected YubiKey and restore its current bundle if certificates changed. The signed bundle, exact public certificate and live keys must match. No PIN was submitted and no card data was changed.'
    if op in ('chat-identity-bundle-read','chat-identity-key-snapshot','chat-identity-companion-read','chat-identity-devices'):
        return 'Public YubiKey read stopped. Connect the configured YubiKey and retry with its current public bundle. No PIN was submitted and no card or identity data was changed.'
    if op=='chat-hardware-audit':
        return 'Read-only hardware audit stopped. The selected signed bundle, device, public keys or metadata could not be read consistently. No PIN was requested and unchanged status is unconfirmed.'
    if op=='chat-identity-current':
        return 'The configured public identity could not be read. No YubiKey operation was attempted.'
    if op=='chat-certificate-migration':
        return 'Legacy public-certificate export stopped. Check the old store for conflicting, malformed or oversized records. No certificates or trust were changed. No YubiKey operation was attempted.'
    if op=='chat-decryption-material':
        return 'The configured public decryption identity could not be read. No YubiKey operation was attempted.'
    if op in ('chat-sign-digest','chat-decapsulate-components'):
        return 'YubiKey operation stopped. Check the configured key and native PIN dialog. No automatic private-operation retry was performed.'
    if op and op.startswith('chat-vault-'):
        # Reflect only our fixed diagnostics, never arbitrary exceptions, native
        # stderr, PINs or secret output. Cancellation is not a token PIN failure.
        # PIV_UNLOCK_DIAGNOSTICS: these fixed component labels consume the
        # status protocol from chat_bridge.py and crypto/src/main.rs. They may
        # remain when disk history is removed. If removing the protocol too,
        # retain a generic failure response: never expose str(error)/raw stderr
        # or add an automatic private-operation retry.
        reasons={'PIN cancelled or invalid':'PIN dialog cancelled or local PIN format rejected',
                 'Vault crypto MLKEM_FAILED':'ML-KEM-768 PKCS#11 component failed',
                 'Vault crypto X25519_FAILED':'X25519 PKCS#11 component failed',
                 'Vault crypto ADAPTER_TIMEOUT_OR_INPUT':'PKCS#11 adapter timed out or rejected input',
                 'Vault crypto MLKEM_RESPONSE_SIZE':'ML-KEM-768 returned an invalid response length',
                 'Vault crypto X25519_RESPONSE_SIZE':'X25519 returned an invalid response length',
                 'Vault crypto CRYPTO_FAILED':'native cryptographic validation failed (unclassified)',
                 'Vault helper timeout':'native cryptographic helper timed out',
                 'Expected YubiKey not connected':'configured YubiKey not connected',
                 'Cryptographic operation failed; no retry':'PKCS#11 decapsulation failed',
                 'Wrong PIV key':'public-key mismatch',
                 'Required vault YubiKey absent':'configured classical PIV key not connected'}
        reason=reasons.get(str(error),'native vault operation could not complete')
        return 'Vault stopped: '+reason+'. No retry or vault write was performed.'
    if op and op.startswith('chat-'):
        return 'Unsupported or failed hardware operation. No automatic cryptographic retry was performed.'
    return 'Operation stopped. Check the key connection or native dialog. No automatic retry; unchanged status is unconfirmed unless the saved comparison completed.'
