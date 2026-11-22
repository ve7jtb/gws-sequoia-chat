"""Closed Google Chat API for the IWA. All CLI paths come from local config.

No arbitrary gws commands, URLs, executable paths, slots or PINs are accepted
from the browser. Google credentials remain in this installation's gws profile.
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

LIMIT=262144
FIELDS={'chat-decrypt':{'contact','payload','service'},'chat-verification-material':set(),'chat-state':set(),'chat-login':set(),'chat-spaces':{'page'},'chat-messages':{'space','page'},
        'chat-preview':{'certificate'},'chat-trust':{'certificate','email','fingerprint','confirmed'},
        'chat-prepare':{'space','contact','subject','mime'},'chat-send':{'review','confirmed'},
        'chat-open':{'message','contact'}}

FIELDS.update({'chat-mail-cert-save':{'message','fingerprint'},'chat-mail-cert-trust':{'message','fingerprint','email','confirmed'},'chat-mail-read':{'message'},'chat-mail-list':{'page','query'},'chat-mail-open':{'message','contact'},'chat-mail-prepare':{'contact','subject','mime'},'chat-mail-send':{'review','confirmed'},'chat-mail-connect':set(),'chat-mail-login':set()})

from cert_store import FIELDS as CERT_FIELDS
FIELDS.update(CERT_FIELDS)
FIELDS['chat-encryption-complete']={'review','cipher'}

def validate(request):
    op=request.get('op')
    if op not in FIELDS or set(request)!=(FIELDS[op]|{'op'}):raise ValueError('Unsupported fields')
    for k,v in request.items():
        if k=='attachments':
            validate_attachments(v)
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
    if service not in ('Chat','Gmail') or op not in ('seal','sign-browser','open'):
        raise ValueError('Unsupported cryptographic prompt')
    action='Sign' if op=='sign-browser' else ('Sign and encrypt' if op=='seal' else 'Decrypt and verify')
    return action+' '+service+(' email' if service=='Gmail' else ' bundle')

class ChatBridge:
    def __init__(self,root,cfg,emit):
        self.root=Path(root);self.cfg=cfg;self.emit=emit
        self.data=self.root/'private/chat-state';self.data.mkdir(exist_ok=True,mode=0o700)
        spec=importlib.util.spec_from_file_location('iwa_chat_transport',self.root/'runtime/chat/chat.py')
        self.chat=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.chat)
        # Fixed installed Google profile. Never inherit a caller's account.
        os.environ['GWS_CHAT_PROFILE']='default'
    def contacts(self):
        result=[]
        for p in sorted(self.data.glob('contact-*.json')):
            c=json.loads(p.read_text());self.chat.check_cert(self.data/(c['fingerprint']+'.pgp'),c['email'],c['fingerprint']);result.append(c)
        return result
    def peer(self,identifier):
        for c in self.contacts():
            if c['id']==identifier:return c,self.data/(c['fingerprint']+'.pgp')
        raise ValueError('Unknown trusted contact')
    def preview(self,encoded):
        raw=base64.b64decode(encoded,validate=True)
        if len(raw)>LIMIT:raise ValueError('Certificate too large')
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'public.pgp';p.write_bytes(raw);info=self.chat.public_info(p);self.chat.sq('inspect',p,batch=True)
        if not all(a in ('ML-DSA-65 + Ed25519','ML-KEM-768 + X25519') for a in info['algorithms']):raise ValueError('Level 3 hybrid v6 only')
        return raw,info
    def crypto(self,op,peer,payload,service="Chat"):
        if len(payload)>LIMIT:raise ValueError('Message too large')
        serials=subprocess.check_output([self.cfg['ykman'],'list','--serials'],stderr=subprocess.DEVNULL,timeout=25).decode().split()
        if self.cfg['serial'] not in serials:raise ValueError('Expected YubiKey not connected')
        prompt=crypto_prompt('open' if op=='open-browser' else op,service)
        self.emit({'type':'progress','message':prompt+' — use the native PIN dialog, then touch if requested.'})
        # The PIN never reaches Chrome. Supply only a bounded anonymous pipe to
        # the one-shot worker; both components share this operation's PIN.
        ui=subprocess.run([str(self.root/'build/pin-prompt'),prompt,self.cfg['serial']],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
        pin=bytearray(ui.stdout)
        try:
            if ui.returncode or not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):raise ValueError('PIN cancelled or invalid')
            app=Path(self.cfg['app'])
            request={'op':op,'pin':pin.decode('ascii'),'own':base64.b64encode(Path(self.cfg['cert']).read_bytes()).decode(),'peer':base64.b64encode(peer.read_bytes()).decode(),'payload':base64.b64encode(payload).decode(),
              'config':{'python':'/usr/bin/python3','adapters':str(app/'adapters'),'openssl':str(app/'native/bin/openssl'),'provider':str(app/'native/lib/pkcs11.dylib'),'module':str(app/'native/lib/libykcs11.dylib'),'serial':self.cfg['serial']}}
            wire=json.dumps(request).encode();request.pop('pin');del ui
            p=subprocess.run([str(self.root/'runtime/sequoia-iwa-crypto')],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=150)
            del wire
            if p.returncode or len(p.stdout)>LIMIT*2:raise ValueError('Cryptographic operation failed; no retry')
            packet=json.loads(p.stdout)
            result=base64.b64decode(packet['data'],validate=True)
            if len(result)>LIMIT:raise ValueError('Oversize cryptographic result')
            if op=='open-browser':
                signature=base64.b64decode(packet['signature'],validate=True)
                if not 1<=len(signature)<=65536:raise ValueError('Invalid signature packet size')
                return {'raw':packet['data'],'signature':packet['signature'],'encrypted':True}
            return result
        finally:pin[:]=b'\0'*len(pin)
    def prepare_browser_signature(self,request,contact,peer,mime,service,space='Gmail'):
        """Keep routing and review metadata on disk while WASM encrypts.

        The signed body and attachments travel in bounded pipes, never a staged
        plaintext file. The pending ticket includes the subject for send review. The random ticket binds completion to the native-selected contact
        and service and expires after ten minutes. It does not authorize send.
        """
        signed=self.crypto('sign-browser',peer,mime,service=service)
        rid=secrets.token_hex(24)
        metadata={'service':service,'space':space,'contact':contact['id'],
                  'recipient':contact['email'],'fingerprint':contact['fingerprint'],
                  'subject':request['subject'],'created':time.time()}
        self.chat.write_new(self.data/('encryption-'+rid+'.json'),json.dumps(metadata).encode())
        return {'review':rid,'signed':base64.b64encode(signed).decode(),
                'senderCertificate':base64.b64encode(Path(self.cfg['cert']).read_bytes()).decode(),
                'recipientCertificate':base64.b64encode(peer.read_bytes()).decode(),
                'recipientFingerprint':contact['fingerprint'],'recipientEmail':contact['email']}
    def complete_browser_encryption(self,request):
        """Stage bounded WASM ciphertext, preserving one-use native send review.

        Browser encryption is part of the trusted application. The native host
        cannot prove ciphertext plaintext equality without the recipient secret;
        it binds routing to the ticket and rechecks current contact trust instead.
        No extra signing operation or native encryption fallback is performed.
        """
        rid=request['review']
        if not re.fullmatch('[a-f0-9]{48}',rid):raise ValueError('Invalid encryption ticket')
        ticket=self.data/('encryption-'+rid+'.json')
        meta=json.loads(ticket.read_text())
        if time.time()-meta['created']>600:raise ValueError('Encryption ticket expired')
        contact,peer=self.peer(meta['contact'])
        if contact['email']!=meta['recipient'] or contact['fingerprint']!=meta['fingerprint']:raise ValueError('Contact changed')
        cipher=base64.b64decode(request['cipher'],validate=True)
        if not 1<=len(cipher)<=LIMIT:raise ValueError('Ciphertext limit')
        # Inspect only public packet metadata; no PIN or private key is used.
        check={'op':'check-ciphertext','peer':base64.b64encode(peer.read_bytes()).decode(),'payload':request['cipher']}
        checked=subprocess.run([str(self.root/'runtime/sequoia-iwa-crypto')],input=json.dumps(check).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        if checked.returncode or json.loads(checked.stdout).get('valid') is not True:raise ValueError('Invalid encrypted packet structure or recipient')
        # Consume the ticket before staging: an uncertain completion cannot be
        # retried into a second independently sendable draft.
        ticket.unlink()
        mail=meta['service']=='Gmail'
        out=self.chat.private_dir(self.data/(('mail-draft-' if mail else 'draft-')+rid))
        if mail:
            from gmail_bridge import module
            m=module(self)
            encoded=base64.b64encode(cipher).decode()
            armor=('-----BEGIN PGP MESSAGE-----\r\n\r\n'+'\r\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64))+'\r\n-----END PGP MESSAGE-----\r\n').encode()
            self.chat.write_new(out/'message.eml',m.encrypted_envelope(self.cfg['chat_email'],contact['email'],armor))
        else:
            self.chat.write_new(out/'message.pgp',cipher)
            self.chat.write_new(out/'pq-mail-sender-key.pgp',Path(self.cfg['cert']).read_bytes())
            own=self.chat.check_cert(self.cfg['cert'],self.cfg['chat_email'])
            manifest={'sender':self.cfg['chat_email'],'recipient':contact['email'],'sender_fingerprint':own['fingerprint'],'recipient_fingerprint':contact['fingerprint'],'ciphertext_sha256':hashlib.sha256(cipher).hexdigest()}
            self.chat.write_new(out/'manifest.json',json.dumps(manifest).encode())
        self.chat.write_new(out/'review.json',json.dumps({'space':meta['space'],'created':time.time()}).encode())
        return {'review':rid,'space':meta['space'],'recipient':contact['email'],'fingerprint':contact['fingerprint'],'subject':meta['subject']}
    def action(self,request):
        op=validate(request);chat=self.chat
        with (self.data/'operation.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if op=='chat-encryption-complete':return self.complete_browser_encryption(request)
            if op in CERT_FIELDS:
                from cert_store import action
                return action(self,request)
            if op.startswith('chat-mail-') and op!='chat-mail-login':
                from gmail_bridge import action
                return action(self,request)
            if op=='chat-decrypt':
                if request['service'] not in ('Gmail','Chat'):raise ValueError('Unknown service')
                contact,peer=self.peer(request['contact'])
                clear=self.crypto('open-browser',peer,base64.b64decode(request['payload'],validate=True),service=request['service'])
                return {**clear,'expectedEmail':contact['email'],'expectedFingerprint':contact['fingerprint'],'recipient':self.cfg['chat_email']}
            if op=='chat-verification-material':
                from browser_material import material
                return material(self)
            if op=='chat-state':
                own=chat.check_cert(self.cfg['cert'],self.cfg['chat_email'])
                return {'account':self.cfg['chat_email'],'serial':self.cfg['serial'],'identity':own,'contacts':self.contacts()}
            if op in ('chat-login','chat-mail-login'):
                # gws uses a browser OAuth flow and its own callback listener,
                # not an IWA loopback API. It handles Google account tokens.
                pidfile=self.data/'login.json'
                if pidfile.exists():
                    old=json.loads(pidfile.read_text())
                    if time.time()-old['time']<600:
                        try:os.kill(old['pid'],0)
                        except ProcessLookupError:pass
                        else:raise ValueError('Sign-in already running')
                env={k:v for k,v in os.environ.items() if k in ('HOME','PATH','TMPDIR','LANG')}
                # Some gws builds print the URL without opening a browser. Capture
                # only its authorization URL in an unlinked temporary stream;
                # never return raw CLI output or OAuth callback/token data.
                with tempfile.TemporaryFile() as output:
                    scopes=chat.SCOPES
                    if op=='chat-mail-login':
                        from gmail_bridge import SCOPES
                        scopes+=','+SCOPES
                    child=subprocess.Popen([str(chat.ROOT/'gws-chat'),'auth','login','--scopes',scopes],env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True)
                    pidfile.write_text(json.dumps({'pid':child.pid,'time':time.time()}))
                    for _ in range(100):
                        printed=os.pread(output.fileno(),32768,0).decode('utf-8',errors='replace')
                        match=re.search(r'https://accounts\.google\.com/[^\s]+',printed)
                        if match:
                            url=match.group(0)
                            if urlsplit(url).path not in ('/o/oauth2/auth','/o/oauth2/v2/auth'):
                                raise ValueError('Unexpected authorization path')
                            return {'started':True,'authorizationUrl':url}
                        if child.poll() is not None:break
                        time.sleep(.1)
                raise ValueError('Google sign-in did not supply an authorization URL')
            if op=='chat-spaces':
                data=chat.gws('chat','spaces','list','--params',json.dumps({'pageSize':50,'pageToken':request['page']}))
                return {'spaces':[{'name':s['name'],'title':s.get('displayName') or s['name']} for s in data.get('spaces',[])],'next':data.get('nextPageToken','')}
            if op=='chat-messages':
                data=chat.gws('chat','spaces','messages','list','--params',json.dumps({'parent':chat.space_name(request['space']),'pageSize':20,'pageToken':request['page'],'orderBy':'createTime desc'}))
                return {'messages':[{'name':m['name'],'text':m.get('text','')[:2000],'time':m.get('createTime',''),'encrypted':any(a.get('contentName')=='message.pgp' for a in m.get('attachment',[]))} for m in data.get('messages',[])],'next':data.get('nextPageToken','')}
            if op in ('chat-preview','chat-trust'):
                raw,info=self.preview(request['certificate'])
                if op=='chat-preview':return info
                address=chat.canonical_email(request['email'])
                if address not in info['emails'] or request['fingerprint']!=info['fingerprint']:raise ValueError('Identity mismatch')
                public=self.data/(info['fingerprint']+'.pgp')
                if public.exists() and public.read_bytes()!=raw:raise ValueError('Review certificate update separately')
                if not public.exists():chat.write_new(public,raw)
                cid=hashlib.sha256((address+info['fingerprint']).encode()).hexdigest()
                record={'id':cid,'email':address,'fingerprint':info['fingerprint']}
                p=self.data/('contact-'+cid+'.json')
                if not p.exists():chat.write_new(p,json.dumps(record).encode())
                return {'contacts':self.contacts()}
            if op=='chat-prepare':
                space=chat.space_name(request['space']);contact,peer=self.peer(request['contact'])
                own=chat.check_cert(self.cfg['cert'],self.cfg['chat_email'])
                mime=browser_mime(request,self.cfg['chat_email'],contact['email'])
                return self.prepare_browser_signature(request,contact,peer,mime,'Chat',space)
            if op=='chat-send':
                if not re.fullmatch('[a-f0-9]{48}',request['review']):raise ValueError('Invalid review')
                draft=self.data/('draft-'+request['review']);review=json.loads((draft/'review.json').read_text())
                if time.time()-review['created']>600:raise ValueError('Review expired')
                # Move BEFORE upload. An uncertain send can never be repeated
                # with the same review token, even if the browser disconnects.
                out=self.data/('sent-'+request['review']);draft.rename(out)
                with contextlib.redirect_stdout(io.StringIO()):return chat.send(review['space'],out,confirm=True)
            if op=='chat-open':
                contact,peer=self.peer(request['contact'])
                with tempfile.TemporaryDirectory() as td:
                    out=Path(td)/'incoming';chat.receive(chat.message_name(request['message']),out)
                    if chat.public_packets(out/'pq-mail-sender-key.pgp')!=chat.public_packets(peer):raise ValueError('Attached signer does not match trusted contact')
                    cipher=chat.read(out/'message.pgp',LIMIT)
                return {'encrypted':True,'cipher':base64.b64encode(cipher).decode()}
            raise ValueError('Unknown operation')
