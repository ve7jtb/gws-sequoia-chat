#!/usr/bin/env python3
"""Loopback-only UI for the standalone gws/Sequoia integration (macOS/Linux).

The browser is a local client, not a hosted service. No PQ Mail stores are read.
Passwords and plaintext use bounded pipes/memory; Python cannot guarantee secure
memory erasure or prevent OS swap/crash dumps. Only encrypted outgoing bundles,
public contacts and transport receipts are persisted by this app.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import html
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import tempfile
import threading
import time
import webbrowser
import chat
import mail_transport

MAX_REQUEST = 16*1024*1024
WEB = Path(__file__).resolve().parent/'web'
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-src 'self' about:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class SafeHtml(HTMLParser):
    """Allow formatting only. No attributes, URLs, CSS, scripts or active tags."""
    tags = set('p br div span b strong em i u h1 h2 h3 h4 ul ol li blockquote pre code table thead tbody tr th td hr'.split())
    blocked = set('script style iframe object template svg math form'.split())
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.depth = [], 0
    def handle_starttag(self, tag, attrs):
        if tag in self.blocked: self.depth += 1
        elif not self.depth and tag in self.tags: self.parts.append('<'+tag+'>')
    def handle_endtag(self, tag):
        if tag in self.blocked: self.depth = max(0, self.depth-1)
        elif not self.depth and tag in self.tags: self.parts.append('</'+tag+'>')
    def handle_data(self, data):
        if not self.depth: self.parts.append(html.escape(data))


def safe_html(source):
    chat.require(len(source.encode()) <= 1024*1024, 'HTML exceeds 1 MiB')
    parser = SafeHtml(); parser.feed(source); parser.close()
    # A second boundary: even parser/browser disagreement cannot load resources.
    return '<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'+''.join(parser.parts)


def sq_memory(args, payload, password):
    """Bound stdout/stderr and feed the password through an inherited pipe.

    --batch and a new process session prohibit hidden fallback terminal prompts.
    The password never appears in argv, the environment, logs, or a disk file.
    Plaintext is exposed only after sq has exited with successful verification.
    """
    secret = bytearray(password.encode('utf-8'))
    chat.require(0 < len(secret) <= 1024, 'Enter the software identity password (at most 1024 UTF-8 bytes)')
    read_fd, write_fd = os.pipe()
    proc = None
    try:
        os.write(write_fd, secret); os.close(write_fd); write_fd = -1
        cmd = [str(chat.ROOT/'bin/sq'), '--home=none', '--cert-store=none', '--key-store=none', '--batch', '--password-file', '/dev/fd/'+str(read_fd), *map(str,args)]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                pass_fds=(read_fd,), start_new_session=True)
        os.close(read_fd); read_fd = -1
        def feed():
            try: proc.stdin.write(payload); proc.stdin.close()
            except (BrokenPipeError, OSError): pass
        writer = threading.Thread(target=feed, daemon=True); writer.start()
        output, errors = bytearray(), bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, output)
            selector.register(proc.stderr, selectors.EVENT_READ, errors)
            deadline = time.monotonic()+120
            while selector.get_map():
                chat.require(time.monotonic() < deadline, 'Sequoia timed out; nothing was sent')
                for key, _ in selector.select(.2):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk: selector.unregister(key.fileobj); continue
                    key.data.extend(chunk)
                    chat.require(len(output) <= chat.MAX_BYTES and len(errors) <= 1024*1024, 'Sequoia output exceeded the safety limit')
        code = proc.wait(timeout=5); writer.join(timeout=1)
        # Do not return CLI diagnostics: they can contain message data or paths.
        chat.require(code == 0, 'Sequoia could not complete the operation. Check the identity password, certificates and signature; no plaintext was released.')
        return bytes(output)
    finally:
        secret[:] = b'\0'*len(secret)
        if read_fd >= 0: os.close(read_fd)
        if write_fd >= 0: os.close(write_fd)
        if proc:
            if proc.poll() is None: proc.kill(); proc.wait()
            for stream in (proc.stdin,proc.stdout,proc.stderr):
                with contextlib.suppress(Exception): stream.close()


def mime_memory(sender, recipient, subject, text, formatted, files):
    # Reuse the CLI's MIME structure, without its file-based compose staging.
    raw = chat.mime_bytes(sender, recipient, subject, text, formatted, ())
    msg = chat.BytesParser(policy=chat.email.policy.default).parsebytes(raw)
    chat.require(len(files) <= 20, 'At most 20 attachments')
    total = 0
    for item in files:
        name = item['name']
        chat.require(isinstance(name,str) and 0 < len(name) <= 200 and not re.search(r'[\\/\x00-\x1f\x7f]',name), 'Use a plain attachment filename')
        data = base64.b64decode(item['data'],validate=True); total += len(data)
        chat.require(total <= 10*1024*1024, 'Attachments exceed 10 MiB')
        msg.add_attachment(data, maintype='application',subtype='octet-stream',filename=name)
    result = msg.as_bytes();chat.require(len(result) <= chat.MAX_BYTES, 'Message exceeds 20 MiB')
    return result


class LocalApp:
    def __init__(self, root=None):
        self.root = Path(root or chat.ROOT).resolve()
        self.private = self.root/'private'
        self.settings = self.private/'web'
        self.settings.mkdir(parents=True, exist_ok=True,mode=0o700)
        self.lock = threading.Lock()
        self.profile = None
        self.identities, self.contacts, self.drafts = {}, {}, {}
        self.login = None
        self.mail = mail_transport.MailService(self,sq_memory,mime_memory,safe_html)
        self.scan()
    def scan(self):
        self.identities = {}
        # Only immediate, explicitly created identity directories are discoverable.
        # Never traverse credential/profile directories or accept paths from HTTP.
        for public in sorted(self.private.glob('*/public.pgp')):
            secret = public.parent/'secret.pgp'
            if public.is_symlink() or secret.is_symlink() or not secret.is_file(): continue
            if public.parent.resolve().parent != self.private.resolve(): continue
            try:
                info=chat.public_info(public)
                if not all(a in chat.ALGORITHMS.values() for a in info['algorithms']): continue
                identity=hashlib.sha256(str(public).encode()).hexdigest()
                self.identities[identity]={'id':identity,'name':public.parent.name,'info':info,'public':public,'secret':secret}
            except (ValueError,OSError): continue
        self.contacts = {}
        for path in self.settings.glob('contact-*.json'):
            try:
                entry=json.loads(chat.read(path,16384));public=self.settings/(entry['fingerprint']+'.pgp')
                info=chat.check_cert(public,entry['email'],entry['fingerprint'])
                cid=hashlib.sha256((entry['email']+info['fingerprint']).encode()).hexdigest()
                self.contacts[cid]={'id':cid,'email':entry['email'],'info':info,'public':public}
            except (KeyError,ValueError,OSError): continue
    def profiles(self):
        result=[]
        if (self.private/'gws/client_secret.json').is_file(): result.append('default')
        for p in sorted((self.private/'profiles').glob('*')):
            if p.is_dir() and not p.is_symlink() and re.fullmatch('[A-Za-z0-9_-]+',p.name): result.append(p.name)
        return result
    def bootstrap(self):
        return {'profiles':[p for p in self.profiles() if not p.endswith('-mail')],'profile':self.profile,
                'mail':{'profile':self.mail.profile,'email':self.mail.address},
                'identities':[{k:v for k,v in x.items() if k not in ('public','secret')} for x in self.identities.values()],
                'contacts':[{k:v for k,v in x.items() if k!='public'} for x in self.contacts.values()]}
    @contextlib.contextmanager
    # GWS reads a process-global environment variable for profile selection.
    # action() holds the application lock across this context, including the
    # metadata worker pool, so one browser request cannot switch another's
    # account while a command is being constructed.
    def using_profile(self, profile):
        chat.require(profile in self.profiles(),'Select an existing gws profile')
        previous=os.environ.get('GWS_CHAT_PROFILE');os.environ['GWS_CHAT_PROFILE']=profile
        try: yield
        finally:
            if previous is None: os.environ.pop('GWS_CHAT_PROFILE',None)
            else: os.environ['GWS_CHAT_PROFILE']=previous
    def api(self,*args):
        chat.require(self.profile is not None,'Connect an account first')
        with self.using_profile(self.profile): return chat.gws(*args)
    # Preview handles public data only. public_info supplies current certified
    # mailbox bindings; sq inspect adds a parseability check. Neither grants
    # local trust: the separate confirmation records the user's email and full
    # fingerprint choice after independent verification.
    def contact_preview(self,data):
        raw=base64.b64decode(data['certificate'],validate=True)
        chat.require(len(raw)<=1024*1024,'Certificate exceeds 1 MiB')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'public.pgp';chat.write_new(p,raw)
            info=chat.public_info(p)
            # Sequoia must parse it as a certificate too; this never imports trust.
            chat.sq('inspect',p,batch=True)
        return raw,info
    def action(self, route, data):
        # Serialize profile changes and crypto operations: gws profile selection
        # is process-wide, and a confirmation must stay bound to its account.
        with self.lock:
            self.drafts={k:v for k,v in self.drafts.items() if time.monotonic()-v['created']<600}
            if route.startswith('mail-'):
                method={'mail-connect':self.mail.connect,'mail-login':self.mail.login,'mail-list':self.mail.listing,'mail-read':self.mail.read,
                        'mail-prepare':self.mail.prepare,'mail-send':self.mail.send,'mail-open':self.mail.open}.get(route)
                chat.require(method is not None,'Unknown mail operation')
                return method(data)
            if route=='bootstrap': return self.bootstrap()
            if route=='rescan':
                self.scan();return self.bootstrap()
            if route=='discard':
                self.drafts.clear();return {'discarded':True}
            if route=='clear':
                # Clearing disconnects this browser session and discards pending
                # sends. It does not revoke Google authorization or delete gws's
                # separately encrypted refresh-credential storage.
                self.drafts.clear();self.profile=None
                self.mail.profile=None;self.mail.address=None
                if self.login and self.login.poll() is None: self.login.terminate()
                return {'cleared':True}
            if route=='connect':
                profile=data['profile']
                with self.using_profile(profile): result=chat.gws('chat','spaces','list','--params',json.dumps({'pageSize':100}))
                self.profile=profile;self.drafts.clear();return result
            if route=='spaces': return self.api('chat','spaces','list','--params',json.dumps({'pageSize':100,'pageToken':data.get('pageToken','')}))
            if route=='messages': return self.api('chat','spaces','messages','list','--params',json.dumps({'parent':chat.space_name(data['space']),'pageSize':25,'orderBy':'createTime desc','pageToken':data.get('pageToken','')}))
            if route=='login':
                chat.require(not self.login or self.login.poll() is not None,'A Google sign-in is already running')
                profile=data['profile'];chat.require(profile in self.profiles(),'Select an existing profile')
                env=os.environ.copy();env['GWS_CHAT_PROFILE']=profile
                self.login=subprocess.Popen([str(self.root/'gws-chat'),'auth','login','--scopes',chat.SCOPES],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
                return {'started':True}
            if route=='login-status':
                return {'running':bool(self.login and self.login.poll() is None),'success':bool(self.login and self.login.poll()==0)}
            if route=='preview-contact':
                _,info=self.contact_preview(data);return info
            if route=='trust-contact':
                raw,info=self.contact_preview(data);address=chat.canonical_email(data['email'])
                chat.require(data.get('confirmed') is True and data['fingerprint'].upper()==info['fingerprint'] and address in info['emails'],'Confirm the email and full fingerprint independently')
                public=self.settings/(info['fingerprint']+'.pgp')
                if public.exists(): chat.require(chat.read(public)==raw,'A different certificate with this primary fingerprint is already saved; review updates outside this preview')
                else: chat.write_new(public,raw)
                cid=hashlib.sha256((address+info['fingerprint']).encode()).hexdigest()
                path=self.settings/('contact-'+cid+'.json')
                if not path.exists():chat.write_new(path,json.dumps({'email':address,'fingerprint':info['fingerprint']}).encode())
                self.scan();return self.bootstrap()
            if route=='remove-trust':
                contact=self.contacts[data['contact']]
                (self.settings/('contact-'+contact['id']+'.json')).unlink();self.scan();return self.bootstrap()
            if route=='prepare': return self.prepare(data)
            if route=='send': return self.send(data)
            if route=='open': return self.open(data)
            raise ValueError('Unknown operation')
    # Preparation returns an opaque review handle and keeps its ciphertext,
    # account, peer fingerprint and destination together in server memory.
    # The browser cannot replace those fields in the later send request.
    def prepare(self,data):
        chat.require(self.profile is not None,'Connect an account first')
        own=self.identities[data['identity']];peer=self.contacts[data['contact']]
        sender=chat.canonical_email(data['sender']);recipient=peer['email']
        chat.check_cert(own['public'],sender);chat.check_cert(peer['public'],recipient,peer['info']['fingerprint'])
        space=chat.space_name(data['space'])
        payload=mime_memory(sender,recipient,data['subject'],data['text'],data.get('html') or None,data.get('attachments',[]))
        with tempfile.TemporaryDirectory() as tmp:
            filtered=Path(tmp)/'recipient.pgp';chat.write_new(filtered,chat.hybrid_public(peer['public']))
            encrypted=sq_memory(['encrypt','--for-file',filtered,'--signer-file',own['secret'],'--profile','rfc9580','--compression','zip','--binary','-'],payload,data['password'])
        key=secrets.token_urlsafe(24)
        manifest={'sender':sender,'recipient':recipient,'sender_fingerprint':own['info']['fingerprint'],'recipient_fingerprint':peer['info']['fingerprint'],'ciphertext_sha256':hashlib.sha256(encrypted).hexdigest()}
        self.drafts.clear()  # A new review supersedes the old send capability.
        self.drafts[key]={'created':time.monotonic(),'ciphertext':encrypted,'public':chat.read(own['public'],1024*1024),'manifest':manifest,'space':space,'profile':self.profile}
        return {'review':key,'space':space,'profile':self.profile,'subject':data['subject'],'bytes':len(encrypted),**manifest}
    def send(self,data):
        chat.require(data.get('confirmed') is True,'Confirm sending first')
        # Consume before any network operation: an uncertain failure is never retried.
        draft=self.drafts.pop(data['review'])
        chat.require(draft['profile']==self.profile,'Account changed; prepare again')
        out=chat.private_dir(self.settings/('sent-'+secrets.token_hex(12)))
        chat.write_new(out/'message.pgp',draft['ciphertext']);chat.write_new(out/'pq-mail-sender-key.pgp',draft['public'])
        chat.write_new(out/'manifest.json',json.dumps(draft['manifest']).encode())
        with self.using_profile(self.profile),contextlib.redirect_stdout(io.StringIO()):
            result=chat.send(draft['space'],out,confirm=True)
        return result
    def open(self,data):
        own=self.identities[data['identity']];peer=self.contacts[data['contact']]
        recipient=chat.canonical_email(data['recipient']);chat.check_cert(own['public'],recipient)
        # Revalidate the selected email, not merely another live UID on this
        # cached certificate. Its binding may have expired since contact load.
        chat.check_cert(peer['public'],peer['email'],peer['info']['fingerprint'])
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'download'
            with self.using_profile(self.profile):chat.receive(chat.message_name(data['message']),directory)
            # The attachment is not a trust source. Pin the preselected contact,
            # requiring the downloaded public packets to match it exactly.
            chat.require(chat.public_packets(directory/'pq-mail-sender-key.pgp')==chat.public_packets(peer['public']),'Attached signer differs from the selected trusted certificate')
            filtered=Path(tmp)/'signer.pgp';chat.write_new(filtered,chat.hybrid_public(peer['public']))
            plaintext=sq_memory(['decrypt','--recipient-file',own['secret'],'--signer-file',filtered,'--signatures','1','-'],chat.read(directory/'message.pgp'),data['password'])
        content=chat.inspect_mime(plaintext,peer['email'],recipient)
        return {'signatureValid':True,'sender':peer['email'],'recipient':recipient,'fingerprint':peer['info']['fingerprint'],'subject':content['subject'],
                'text':'\n'.join(content['plain']),'html':safe_html('\n'.join(content['html'])) if content['html'] else '',
                'attachments':[{'name':Path(name.replace('\\','/')).name,'data':base64.b64encode(raw).decode()} for name,raw in content['files']]}


class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,app):
        super().__init__(address,Handler);self.app=app;self.token=secrets.token_urlsafe(32)
        self.origin='http://127.0.0.1:'+str(self.server_address[1]);self.host='127.0.0.1:'+str(self.server_address[1])


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass  # No passwords, URLs, message metadata or tokens in access logs.
    def setup(self):
        super().setup();self.connection.settimeout(10)
    def reply(self,status,data,kind='application/json'):
        if kind=='application/json':data=json.dumps(data).encode()
        self.send_response(status)
        for key,value in {'Content-Type':kind,'Content-Length':str(len(data)),'Cache-Control':'no-store','Pragma':'no-cache',
                          'Content-Security-Policy':CSP,'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY'}.items():self.send_header(key,value)
        self.end_headers();self.wfile.write(data)
    def host_ok(self):return self.headers.get('Host')==self.server.host
    def do_GET(self):
        if not self.host_ok():return self.reply(403,{'error':'Blocked host'})
        files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/mail.js':('mail.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
        if self.path not in files:return self.reply(404,{'error':'Not found'})
        filename,kind=files[self.path];self.reply(200,(WEB/filename).read_bytes(),kind)
    def do_POST(self):
        # Strict Host defeats DNS rebinding. Origin + per-launch bearer token
        # prevent drive-by browser requests. CORS is deliberately not enabled.
        if not self.host_ok() or self.headers.get('Origin')!=self.server.origin or self.headers.get('Sec-Fetch-Site','same-origin')!='same-origin':return self.reply(403,{'error':'Blocked origin'})
        supplied=self.headers.get('Authorization','')
        if not hmac.compare_digest(supplied,'Bearer '+self.server.token):return self.reply(403,{'error':'Open the app from its launcher'})
        if self.headers.get_content_type()!='application/json' or self.headers.get('Transfer-Encoding'):return self.reply(415,{'error':'JSON required'})
        data={}
        try:
            length=int(self.headers.get('Content-Length','0'));chat.require(0<length<=MAX_REQUEST,'Request exceeds limit')
            data=json.loads(self.rfile.read(length));chat.require(isinstance(data,dict),'Expected object')
            chat.require(self.path.startswith('/api/') and '?' not in self.path,'Unknown operation')
            result=self.server.app.action(self.path[5:],data)
            data.pop('password',None)
            self.reply(200,result)
        except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError):
            # Keep CLI errors, file paths and accidental payload fragments local.
            self.reply(400,{'error':'Operation failed. Check the selected account, identity, password and trusted certificate. A failed send is not retried; check the conversation before preparing it again.'})

        finally:
            if isinstance(data,dict): data.pop('password',None)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--no-browser',action='store_true');parser.add_argument('--port',type=int,default=0);args=parser.parse_args()
    os.umask(0o077)
    server=Server(('127.0.0.1',args.port),LocalApp())
    url=server.origin+'/#'+server.token
    print('Standalone Sequoia Chat is running on '+server.origin+' (Ctrl-C to stop).',flush=True)
    if args.no_browser:print(url,flush=True)
    else:webbrowser.open(url)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:
        server.server_close();server.app.drafts.clear()
        if server.app.login and server.app.login.poll() is None:server.app.login.terminate()


if __name__=='__main__':main()
