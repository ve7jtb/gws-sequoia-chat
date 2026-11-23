"""Gmail transport and PGP/MIME for the standalone local browser helper.

Mail uses a distinct gws profile and narrowly scoped Gmail consent. Google OAuth
credentials never enter the browser; Sequoia does cryptography locally. Only
ciphertext plus routing headers is staged for outbound media uploads. Incoming
Gmail JSON and message bodies are bounded in memory, not staged by chat.run().
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import email.policy
import email.utils
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import tempfile
import time
import chat

SCOPES=','.join('https://www.googleapis.com/auth/'+s for s in ('gmail.readonly','gmail.send'))
MAX_JSON=32*1024*1024


def gws_memory(*args):
    """Fixed argv, bounded pipes, no shell and no file-backed stdout/stderr.

    Call only inside LocalApp.using_profile(), serialized by the app lock. No
    message body or password is placed in argv. Mail upload arguments contain
    only the pathname of an already encrypted PGP/MIME message.
    """
    proc=subprocess.Popen([str(chat.ROOT/'gws-chat'),*map(str,args)],stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    output,errors=bytearray(),bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,output)
            selector.register(proc.stderr,selectors.EVENT_READ,errors)
            deadline=time.monotonic()+120
            while selector.get_map():
                chat.require(time.monotonic()<deadline,'Gmail request timed out')
                for key,_ in selector.select(.2):
                    chunk=os.read(key.fileobj.fileno(),65536)
                    if not chunk:selector.unregister(key.fileobj);continue
                    key.data.extend(chunk)
                    chat.require(len(output)<=MAX_JSON and len(errors)<=1024*1024,'Gmail response exceeds limit')
        chat.require(proc.wait(timeout=5)==0,'Gmail request failed; check consent and account')
        result=json.loads(output);chat.require(isinstance(result,dict) and not result.get('error'),'Gmail API error')
        return result
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
        proc.stdout.close();proc.stderr.close()


def message_id(value):
    chat.require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,200}',value),'Invalid Gmail message id')
    return value


def raw_message(value):
    """Strict, bounded decoding of Gmail's RFC 5322 base64url response."""
    chat.require(isinstance(value,str) and len(value)<=28*1024*1024,'Mail exceeds limit')
    raw=base64.b64decode(value+'='*((-len(value))%4),altchars=b'-_',validate=True)
    chat.require(len(raw)<=chat.MAX_BYTES,'Mail exceeds 20 MiB')
    return raw


def encrypted_envelope(sender,recipient,ciphertext):
    """RFC 3156 two-part multipart/encrypted; actual subject stays inside.

    The first part is the Version control record and the second is armored
    OpenPGP ciphertext. Outer headers are routing metadata, not authenticated
    identity evidence. They never override verified inner content.
    """
    msg=EmailMessage(policy=email.policy.SMTP)
    msg['From']=chat.canonical_email(sender);msg['To']=chat.canonical_email(recipient)
    msg['Subject']='Encrypted OpenPGP message';msg['Date']=email.utils.formatdate(usegmt=True)
    msg['Message-ID']=email.utils.make_msgid(domain='sequoia-mail.invalid')
    msg.set_type('multipart/encrypted');msg.set_param('protocol','application/pgp-encrypted')
    control=EmailMessage(policy=email.policy.SMTP);control.set_type('application/pgp-encrypted')
    control['Content-Transfer-Encoding']='7bit';control.set_payload('Version: 1\r\n')
    encrypted=EmailMessage(policy=email.policy.SMTP);encrypted.set_type('application/octet-stream')
    encrypted['Content-Disposition']='inline; filename="encrypted.asc"'
    encrypted['Content-Transfer-Encoding']='7bit';encrypted.set_payload(ciphertext.decode('ascii'))
    msg.attach(control);msg.attach(encrypted)
    result=msg.as_bytes();chat.require(len(result)<=chat.MAX_BYTES,'Encrypted mail exceeds limit')
    return result


def parse_message(raw):
    """Bound MIME structure before rendering or selecting a crypto container."""
    chat.require(len(raw)<=chat.MAX_BYTES,'Mail exceeds limit')
    msg=BytesParser(policy=email.policy.default).parsebytes(raw)
    count=0
    def check(part,depth=0):
        nonlocal count
        count+=1;chat.require(depth<=12 and count<=100,'Excessive MIME structure')
        if part.is_multipart():
            for child in part.iter_parts():check(child,depth+1)
    check(msg);return msg


def rewritten_payload(msg):
    """Recognize only Gmail's exact two-leaf rewrite; never mix outer content.

    Ciphertext authenticity is established later by Sequoia, not by this shape.
    Additional text, attachments, nested MIME, or multiple armor blocks fail.
    Gmail also rewrites our binary/base64 variant without armoring it. Decode
    that specific octet-stream leaf strictly and preserve every ciphertext byte.
    """
    chat.require(msg.get_content_type()=='multipart/mixed','Not a rewritten envelope')
    for header in ('Content-Type','Content-Transfer-Encoding'):
        chat.require(len(msg.get_all(header,[]))<=1,'Duplicate MIME structure header')
    parts=list(msg.iter_parts());chat.require(len(parts)==2,'Ambiguous rewritten envelope')
    control=cipher=None
    for part in parts:
        chat.require(not part.is_multipart(),'Nested rewritten envelope part')
        for header in ('Content-Type','Content-Transfer-Encoding'):
            chat.require(len(part.get_all(header,[]))<=1,'Duplicate MIME structure header')
        if part.get_content_type()=='application/pgp-encrypted' and control is None:control=part
        elif part.get_content_type() in ('text/plain','application/octet-stream') and cipher is None:cipher=part
        else:raise ValueError('Ambiguous rewritten envelope')
    chat.require(control is not None and cipher is not None,'Missing rewritten envelope part')
    version=control.get_payload(decode=True) or b''
    chat.require(len(version)<=64 and version.strip()==b'Version: 1','Invalid rewritten PGP version')
    if (cipher.get_content_type()=='application/octet-stream' and
            str(cipher.get('Content-Transfer-Encoding','')).strip().lower()=='base64'):
        # email.get_payload(decode=True) deliberately tolerates malformed base64.
        # Do not use that repair behavior for this narrow compatibility path:
        # accept only MIME linear whitespace plus canonical padded base64.
        # In particular, stripping the decoded binary would corrupt valid packet
        # bytes that happen to equal a space, tab or newline at either end.
        encoded=cipher.get_payload()
        chat.require(isinstance(encoded,str),'Invalid rewritten binary payload')
        encoded=re.sub(r'[ \t\r\n]','',encoded)
        chat.require(bool(re.fullmatch(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',encoded)),
                     'Invalid rewritten ciphertext base64')
        data=base64.b64decode(encoded,validate=True)
        chat.require(0<len(data)<=chat.MAX_BYTES and base64.b64encode(data).decode('ascii')==encoded,
                     'Invalid rewritten ciphertext base64')
        # This recognizes an envelope, not a valid or trusted message. Sequoia
        # still validates the packets, authenticated encryption and signature.
        return data
    data=(cipher.get_payload(decode=True) or b'').strip()
    begin=b'-----BEGIN PGP MESSAGE-----';end=b'-----END PGP MESSAGE-----'
    chat.require(len(data)<=chat.MAX_BYTES and data.isascii() and
                 (data.startswith(begin+b'\r\n') or data.startswith(begin+b'\n')) and
                 data.endswith(end) and data.count(begin)==1 and data.count(end)==1,'Invalid rewritten ciphertext')
    return data


def pgp_payload(msg):
    """Accept the actual root crypto container, not an unrelated attachment."""
    if msg.get_content_type()=='multipart/mixed':return rewritten_payload(msg)
    chat.require(msg.get_content_type()=='multipart/encrypted' and msg.get_param('protocol')=='application/pgp-encrypted','Expected PGP/MIME encryption')
    parts=list(msg.iter_parts());chat.require(len(parts)==2,'Expected two encrypted MIME parts')
    chat.require(parts[0].get_content_type()=='application/pgp-encrypted' and
                 (parts[0].get_payload(decode=True) or b'').strip()==b'Version: 1','Invalid PGP/MIME control')
    chat.require(parts[1].get_content_type()=='application/octet-stream','Invalid ciphertext part')
    value=parts[1].get_payload(decode=True);chat.require(value and len(value)<=chat.MAX_BYTES,'Invalid ciphertext')
    return value


def display_parts(msg,sanitize):
    """Render ordinary MIME as explicitly unverified; never infer trust."""
    plain,formatted,files=[],[],[];total=0
    for part in msg.walk():
        if part.is_multipart():continue
        data=part.get_payload(decode=True) or b''
        if part.get_filename() or part.get_content_disposition()=='attachment':
            total+=len(data);chat.require(total<=chat.MAX_FILES and len(files)<20,'Attachments exceed limit')
            name=Path((part.get_filename() or 'attachment.bin').replace('\\','/')).name
            files.append({'name':name,'data':base64.b64encode(data).decode()})
        elif part.get_content_type() in ('text/plain','text/html'):
            value=part.get_content()
            (formatted if part.get_content_type()=='text/html' else plain).append(value)
    return {'text':'\n'.join(plain),'html':sanitize('\n'.join(formatted)) if formatted else '', 'attachments':files}


class MailService:
    def __init__(self,app,crypto,mime,sanitize):
        self.app,self.crypto,self.mime,self.sanitize=app,crypto,mime,sanitize
        self.profile=None;self.address=None
    def profile_for(self,base):
        """Copy only registration metadata; never copy a Chat refresh token."""
        chat.require(base in self.app.profiles() and not base.endswith('-mail'),'Choose a base Chat profile')
        target=base+'-mail';folder=self.app.private/'profiles'/target
        source=self.app.private/('gws' if base=='default' else 'profiles/'+base)/'client_secret.json'
        folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        dest=folder/'client_secret.json'
        if not dest.exists():chat.write_new(dest,chat.read(source,65536))
        return target
    def call(self,*args):
        chat.require(self.profile is not None,'Connect Gmail first')
        with self.app.using_profile(self.profile):return gws_memory('gmail',*args)
    # Resolve the authenticated mailbox from Google's profile response rather
    # than a browser-supplied email. Bind prepared outgoing mail to this account;
    # changing it invalidates pending review/send handles.
    def connect(self,data):
        profile=self.profile_for(data['profile'])
        with self.app.using_profile(profile):info=gws_memory('gmail','users','getProfile','--params',json.dumps({'userId':'me'}))
        address=chat.canonical_email(info['emailAddress'])
        self.profile,self.address=profile,address;self.app.drafts.clear()
        return {'email':address,'profile':profile}
    def login(self,data):
        chat.require(not self.app.login or self.app.login.poll() is not None,'A Google sign-in is running')
        profile=self.profile_for(data['profile']);env=os.environ.copy();env['GWS_CHAT_PROFILE']=profile
        self.app.login=subprocess.Popen([str(self.app.root/'gws-chat'),'auth','login','--scopes',SCOPES],
            env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        return {'started':True,'profile':profile}
    def listing(self,data):
        query=data.get('query','');folder=data.get('folder','INBOX')
        chat.require(isinstance(query,str) and len(query)<=1024 and folder in ('INBOX','SENT','ALL'),'Invalid mail search')
        params={'userId':'me','maxResults':20,'q':query,'pageToken':data.get('pageToken','')}
        if folder!='ALL':params['labelIds']=[folder]
        result=self.call('users','messages','list','--params',json.dumps(params))
        ids=[message_id(x['id']) for x in result.get('messages',[])[:20]]
        # Metadata only for the list; raw MIME is fetched only after a click.
        def metadata(mid):
            r=gws_memory('gmail','users','messages','get','--params',json.dumps({'userId':'me','id':mid,'format':'metadata','metadataHeaders':['From','To','Subject','Date','Content-Type']}))
            headers={h['name'].lower():h['value'] for h in r.get('payload',{}).get('headers',[])}
            return {'id':mid,'from':headers.get('from',''),'subject':headers.get('subject','(No subject)'),
                    'date':headers.get('date',''),'unread':'UNREAD' in r.get('labelIds',[])}
        with self.app.using_profile(self.profile),ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(metadata,ids))
        return {'messages':rows,'nextPageToken':result.get('nextPageToken','')}
    def fetch(self,mid):
        r=self.call('users','messages','get','--params',json.dumps({'userId':'me','id':message_id(mid),'format':'raw'}))
        return raw_message(r['raw'])
    # The initial reader is an unverified preview. Header text is transport
    # metadata and cannot establish authorship. Cryptographic validity is only
    # reported by open() after the selected certificate verifies the content.
    def read(self,data):
        msg=parse_message(self.fetch(data['message']))
        encrypted=msg.get_content_type()=='multipart/encrypted' and msg.get_param('protocol')=='application/pgp-encrypted'
        if not encrypted:
            try:rewritten_payload(msg);encrypted=True
            except ValueError:pass
        result={'encrypted':encrypted,'signatureValid':False,'sender':str(msg.get('From','')),'recipient':str(msg.get('To','')),
                'subject':str(msg.get('Subject','')),'fingerprint':'','text':'','html':'','attachments':[]}
        if not encrypted:result.update(display_parts(msg,self.sanitize))
        result['notice']='Encrypted PGP/MIME — unlock to verify the sender.' if encrypted else 'Not cryptographically verified. These headers and content can be forged.'
        return result
    def prepare(self,data):
        chat.require(self.profile and self.address,'Connect Gmail first')
        own=self.app.identities[data['identity']];peer=self.app.contacts[data['contact']]
        sender=chat.canonical_email(data['sender']);recipient=peer['email']
        chat.require(sender==self.address,'Signing email must match connected Gmail account')
        chat.check_cert(own['public'],sender);chat.check_cert(peer['public'],recipient,peer['info']['fingerprint'])
        payload=self.mime(sender,recipient,data['subject'],data['text'],data.get('html') or None,data.get('attachments',[]))
        # Include the public certificate inside the encrypted, signed MIME. It
        # is a convenience attachment, never a replacement for receiver trust.
        msg=parse_message(payload);msg.add_attachment(chat.read(own['public'],1024*1024),maintype='application',subtype='pgp-keys',filename='sender-public.pgp')
        payload=msg.as_bytes(policy=email.policy.SMTP);chat.require(len(payload)<=chat.MAX_BYTES,'MIME exceeds limit')
        with tempfile.TemporaryDirectory() as tmp:
            cert=Path(tmp)/'recipient.pgp';chat.write_new(cert,chat.hybrid_public(peer['public']))
            cipher=self.crypto(['encrypt','--for-file',cert,'--signer-file',own['secret'],'--profile','rfc9580','--compression','zip','-'],payload,data['password'])
        raw=encrypted_envelope(sender,recipient,cipher)
        review=secrets.token_urlsafe(24);self.app.drafts.clear()
        self.app.drafts[review]={'created':time.monotonic(),'service':'mail','profile':self.profile,'raw':raw}
        return {'review':review,'service':'mail','profile':self.profile,'sender':sender,'recipient':recipient,'subject':data['subject'],
                'bytes':len(raw),'recipient_fingerprint':peer['info']['fingerprint']}
    def send(self,data):
        chat.require(data.get('confirmed') is True,'Confirm sending first')
        draft=self.app.drafts.pop(data['review'])
        chat.require(draft.get('service')=='mail' and draft['profile']==self.profile,'Mail session changed')
        # Consume before upload, and never automatically retry an uncertain POST.
        # gws requires upload paths to be under its isolated profile directory.
        config=self.app.private/'profiles'/self.profile
        with tempfile.TemporaryDirectory(prefix='.mail-send-',dir=config) as tmp:
            path=Path(tmp)/'encrypted.eml';chat.write_new(path,draft['raw'])
            result=self.call('users','messages','send','--params',json.dumps({'userId':'me'}),'--json','{}',
                             '--upload',str(path),'--upload-content-type','message/rfc822')
        return {'sent':message_id(result['id']),'service':'mail'}
    def open(self,data):
        own=self.app.identities[data['identity']];peer=self.app.contacts[data['contact']]
        recipient=chat.canonical_email(data['recipient']);chat.check_cert(own['public'],recipient)
        # Contact caching does not freeze certificate validity. Require this
        # exact mailbox/fingerprint binding to remain current before fetching
        # or exposing a message, even when the key has other valid UIDs.
        chat.check_cert(peer['public'],peer['email'],peer['info']['fingerprint'])
        outer=parse_message(self.fetch(data['message']));cipher=pgp_payload(outer)
        with tempfile.TemporaryDirectory() as tmp:
            cert=Path(tmp)/'signer.pgp';chat.write_new(cert,chat.hybrid_public(peer['public']))
            plain=self.crypto(['decrypt','--recipient-file',own['secret'],'--signer-file',cert,'--signatures','1','-'],cipher,data['password'])
        # Some PGP/MIME clients sign only the inner Content-* entity. In that
        # case the body is authenticated, but routing headers and the displayed
        # outer subject are not. Check sender consistency without claiming that
        # the outer address is covered by the signature. Never silently fall
        # back when a partial or mismatched protected header is present.
        inner=parse_message(plain)
        headers_authenticated=bool(inner.get_all('From') or inner.get_all('To'))
        if headers_authenticated:
            content=chat.inspect_mime(plain,peer['email'],recipient)
        else:
            addresses=email.utils.getaddresses(outer.get_all('From',[]))
            chat.require(len(outer.get_all('From',[]))==1 and len(addresses)==1 and
                         chat.canonical_email(addresses[0][1])==peer['email'],'Outer sender differs from trusted signer')
            rendered=display_parts(inner,self.sanitize)
            return {'encrypted':True,'signatureValid':True,'headersAuthenticated':False,
                    'sender':peer['email'],'recipient':recipient,'fingerprint':peer['info']['fingerprint'],
                    'subject':str(inner.get('Subject',outer.get('Subject',''))),
                    'notice':'Body signature valid; outer From/To/Subject headers are not authenticated.',**rendered}

        return {'encrypted':True,'signatureValid':True,'headersAuthenticated':True,'sender':peer['email'],'recipient':recipient,'fingerprint':peer['info']['fingerprint'],
                'subject':content['subject'],'text':'\n'.join(content['plain']),'html':self.sanitize('\n'.join(content['html'])) if content['html'] else '',
                'attachments':[{'name':Path(n.replace('\\','/')).name,'data':base64.b64encode(v).decode()} for n,v in content['files']]}
