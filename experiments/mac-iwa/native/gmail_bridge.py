"""Bounded Gmail transport for the IWA, using the existing hardware crypto.

Only encrypted PGP/MIME is sent. Plaintext, HTML and files remain in memory until
wrapped by the signed/encrypted OpenPGP packet stream. No Gmail delete API exists.
"""
import base64,json,time,secrets,re,sys,importlib.util,tempfile,subprocess
from email.utils import getaddresses
from pathlib import Path
from email import policy
from email.parser import BytesParser
from chat_bridge import compose_mime

SCOPES=','.join('https://www.googleapis.com/auth/'+s for s in ('gmail.readonly','gmail.send'))
FIELDS={'chat-mail-read':{'message'},'chat-mail-list':{'page','query'},'chat-mail-open':{'message','contact'},'chat-mail-prepare':{'contact','subject','body','html','attachments'},'chat-mail-send':{'review','confirmed'},'chat-mail-connect':set(),'chat-mail-login':set()}

def encrypted_payload(m,msg):
    """Recognize a complete supported envelope, never a subject or filename.

    Gmail sometimes rewrites PGP/MIME to multipart/mixed; use the same strict
    parser as decryption so a normal mixed message cannot acquire a lock badge.
    This recognizes encryption packaging, not a verified signature or sender.
    """
    try:return m.pgp_payload(msg)
    except ValueError:return None

def ordinary_message(msg):
    """Return bounded, explicitly unverified content without a token operation.

    HTML is data only: the IWA's inert renderer drops attributes and active
    elements. Attachments are explicit downloads, never automatically opened.
    """
    plain,html,files=[],[],[];remaining=131072;omitted=0
    for part in msg.walk():
        if part.is_multipart():continue
        if part.get_filename() or part.get_content_disposition()=='attachment':
            data=part.get_payload(decode=True) or b''
            if len(data)>remaining or len(files)>=10:omitted+=1;continue
            remaining-=len(data)
            name=Path((part.get_filename() or 'attachment.bin').replace('\\','/')).name
            files.append({'name':name[:150],'size':len(data),'data':base64.b64encode(data).decode()})
        elif part.get_content_type() in ('text/plain','text/html'):
            try:value=part.get_content()
            except (LookupError,UnicodeError):value=(part.get_payload(decode=True) or b'').decode('utf-8',errors='replace')
            (plain if part.get_content_type()=='text/plain' else html).append(value[:32768])
    result={'verified':False,'encrypted':False,'subject':str(msg.get('Subject','(No subject)'))[:1000],
            'sender':str(msg.get('From',''))[:1000],'text':'\n'.join(plain)[:32768],
            'html':'\n'.join(html)[:32768],'attachments':files,'omittedAttachments':omitted,
            'notice':'Unencrypted Gmail message — signature and sender not verified. Display is limited to 32,768 characters per text/HTML view and 128 KiB of attachments.'}

    # Native Messaging has a smaller frame cap than Gmail's MIME limit. JSON
    # escaping can expand hostile/control-heavy text; enforce the wire budget.
    while len(json.dumps(result).encode())>400000:
        result['text']=result['text'][:len(result['text'])//2]
        result['html']=result['html'][:len(result['html'])//2]
    return result


def signed_parts(raw,msg):
    """Extract RFC 3156 signed bytes without MIME regeneration or header folding.

    Transport line endings are canonical CRLF. The delimiter's preceding CRLF
    belongs to the boundary, not the signed entity. Reject ambiguous envelopes.
    """
    if msg.get_content_type()!='multipart/signed':return None
    if msg.get_param('protocol','').lower()!='application/pgp-signature':return None
    parts=list(msg.iter_parts())
    if len(parts)!=2 or parts[1].get_content_type()!='application/pgp-signature' or msg.defects:
        raise ValueError('Malformed signed envelope')
    boundary=msg.get_boundary()
    if not boundary or len(boundary)>70:raise ValueError('Invalid boundary')
    canonical=re.sub(br'\r?\n',b'\r\n',raw)
    body=canonical.split(b'\r\n\r\n',1)[1]
    delimiters=list(re.finditer(br'(?m)^--'+re.escape(boundary.encode('ascii'))+br'(--)?[ \t]*\r?$',body))
    if len(delimiters)!=3 or delimiters[0][1] or delimiters[1][1] or not delimiters[2][1]:
        raise ValueError('Ambiguous signed boundary')
    content=body[delimiters[0].end()+1:delimiters[1].start()-2]
    signature=parts[1].get_payload(decode=True) or b''
    if len(content)>262144 or len(signature)>65536:raise ValueError('Signed message exceeds verification limit')
    return content,signature,parts[0]

def signed_message(b,raw,msg):
    """Verify public material only; attachments never enroll or grant trust."""
    result=ordinary_message(msg)
    result.update(signatureStatus='not-signed',certificateTrust='not-applicable',signatures=[])
    if msg.get_content_type()!='multipart/signed':
        if any(p.get_content_type()=='multipart/signed' for p in msg.walk()) or '-----BEGIN PGP SIGNED MESSAGE-----' in result['text']:
            result.update(signatureStatus='unsupported',certificateTrust='unknown')
        return result
    result.update(signatureStatus='unsupported',certificateTrust='unknown')
    try:parts=signed_parts(raw,msg)
    except (ValueError,IndexError,UnicodeError):
        result['signatureStatus']='invalid';return result
    if parts is None:return result
    payload,signature,content=parts
    # Display only the entity actually covered by the detached signature.
    result.update(ordinary_message(content));result['subject']=str(msg.get('Subject','(No subject)'))[:1000]
    result['sender']=str(msg.get('From',''))[:1000]
    contacts=b.contacts();certificates=[];budget=200000
    candidates=[b.data/(c['fingerprint']+'.pgp') for c in contacts]
    for path in candidates[:24]:
        data=path.read_bytes()
        if len(data)<=budget:certificates.append(base64.b64encode(data).decode());budget-=len(data)
    for part in msg.walk():
        if part.get_content_type()!='application/pgp-keys' or part.is_multipart():continue
        data=part.get_payload(decode=True) or b''
        if len(data)<=budget and len(certificates)<32:
            certificates.append(base64.b64encode(data).decode());budget-=len(data)
    request={'op':'verify-detached','payload':base64.b64encode(payload).decode(),
             'signature':base64.b64encode(signature).decode(),'certificates':certificates}
    worker=subprocess.run([str(b.root/'runtime/sequoia-iwa-crypto')],input=json.dumps(request).encode(),
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if worker.returncode or len(worker.stdout)>16384:raise ValueError('Public signature verification failed')
    signatures=json.loads(worker.stdout)['signatures']
    if not 1<=len(signatures)<=16 or any(x.get('status') not in ('valid','invalid','unknown-key') for x in signatures):
        raise ValueError('Invalid verification result')
    addresses=getaddresses(msg.get_all('From',[]))
    email=addresses[0][1].lower() if len(addresses)==1 else ''
    for sig in signatures:
        # Trust is an explicit saved email + full primary fingerprint binding.
        sig['trusted']=sig['status']=='valid' and any(c['fingerprint'].upper()==sig.get('fingerprint','').upper() and c['email'].lower()==email for c in contacts)
    result['signatures']=signatures
    result['signatureStatus']='valid' if all(x['status']=='valid' for x in signatures) else ('invalid' if any(x['status']=='invalid' for x in signatures) else 'unknown-key')
    result['certificateTrust']='trusted' if all(x['trusted'] for x in signatures) else 'untrusted'
    result['verified']=result['signatureStatus']=='valid'
    result['notice']='Outer From, To and Subject headers are not authenticated by this PGP/MIME body signature. Attached keys are not saved or trusted automatically.'
    return result


def upload_encrypted_mail(b,api,path):
    """Stage only ciphertext under gws's fixed working directory.

    gws rejects upload paths outside its working directory. Keep that boundary
    intact: use a private temporary directory beneath its configured profile,
    then remove the staging copy on success or failure. Never retry a POST here.
    """
    profile=b.root/'runtime/chat/private/gws'
    with tempfile.TemporaryDirectory(prefix='mail-upload-',dir=profile) as folder:
        staged=Path(folder)/'message.eml'
        with staged.open('xb') as output:
            staged.chmod(0o600)
            output.write(path.read_bytes())
        return api('users','messages','send','--params',json.dumps({'userId':'me'}),'--json','{}',
                   '--upload',str(staged),'--upload-content-type','message/rfc822')


def action(b,r):
    # The imported module has fixed installed paths, never browser-selected ones.
    sys.modules['chat']=b.chat
    spec=importlib.util.spec_from_file_location('iwa_mail',b.root/'runtime/chat/mail_transport.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    def api(*args):return m.gws_memory('gmail',*args)
    def account():
        p=api('users','getProfile','--params',json.dumps({'userId':'me'}))
        if p.get('emailAddress','').lower()!=b.cfg['chat_email'].lower():raise ValueError('Wrong Gmail account')
        return p['emailAddress']
    op=r['op']
    if op=='chat-mail-connect':return {'account':account()}
    if op=='chat-mail-list':
        if len(r['query'])>1024:raise ValueError('Search too long')
        account();data=api('users','messages','list','--params',json.dumps({'userId':'me','maxResults':10,'q':r['query'],'labelIds':['INBOX'],'pageToken':r['page']}));rows=[]
        for item in data.get('messages',[]):
            mid=m.message_id(item['id']);v=api('users','messages','get','--params',json.dumps({'userId':'me','id':mid,'format':'raw'}));msg=m.parse_message(m.raw_message(v['raw']))
            rows.append({'name':mid,'text':str(msg.get('From',''))[:1000]+' — '+str(msg.get('Subject',''))[:1000],'time':str(msg.get('Date',''))[:200],'encrypted':encrypted_payload(m,msg) is not None})
        return {'messages':rows,'next':data.get('nextPageToken','')}
    if op=='chat-mail-read':
        account();v=api('users','messages','get','--params',json.dumps({'userId':'me','id':m.message_id(r['message']),'format':'raw'}))
        raw=m.raw_message(v['raw']);msg=m.parse_message(raw)
        if encrypted_payload(m,msg) is not None:return {'encrypted':True}
        # An invalid declared crypto envelope is never silently treated as mail.
        if msg.get_content_type()=='multipart/encrypted':raise ValueError('Unsupported or malformed encrypted envelope')
        return signed_message(b,raw,msg)
    if op=='chat-mail-open':
        account();contact,peer=b.peer(r['contact']);v=api('users','messages','get','--params',json.dumps({'userId':'me','id':m.message_id(r['message']),'format':'raw'}))
        outer=m.parse_message(m.raw_message(v['raw']));clear=b.crypto('open',peer,m.pgp_payload(outer),service='Gmail');mime=b.chat.inspect_mime(clear,contact['email'],b.cfg['chat_email'])
        return {'verified':True,'sender':contact['email'],'fingerprint':contact['fingerprint'],'subject':mime['subject'],'text':'\n'.join(mime['plain']),'html':'\n'.join(mime['html']),'attachments':[{'name':n,'size':len(d),'data':base64.b64encode(d).decode()} for n,d in mime['files']]}
    if op=='chat-mail-prepare':
        account();contact,peer=b.peer(r['contact']);raw=compose_mime(b.chat,r,b.cfg['chat_email'],contact['email']);cipher=b.crypto('seal',peer,raw,service='Gmail')
        # Standard ASCII armor without CRC, preserving the binary v6 packets.
        encoded=base64.b64encode(cipher).decode();armor=('-----BEGIN PGP MESSAGE-----\r\n\r\n'+'\r\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64))+'\r\n-----END PGP MESSAGE-----\r\n').encode()
        rid=secrets.token_hex(24);out=b.chat.private_dir(b.data/('mail-draft-'+rid));b.chat.write_new(out/'message.eml',m.encrypted_envelope(b.cfg['chat_email'],contact['email'],armor));b.chat.write_new(out/'review.json',json.dumps({'created':time.time()}).encode())
        return {'review':rid,'space':'Gmail','recipient':contact['email'],'fingerprint':contact['fingerprint'],'subject':r['subject']}
    if op=='chat-mail-send':
        account()
        if not re.fullmatch('[a-f0-9]{48}',r['review']):raise ValueError('Bad review')
        draft=b.data/('mail-draft-'+r['review']);review=json.loads((draft/'review.json').read_text())
        if time.time()-review['created']>600:raise ValueError('Expired review')
        sent=b.data/('mail-sent-'+r['review']);draft.rename(sent)
        result=upload_encrypted_mail(b,api,sent/'message.eml')
        b.chat.write_new(sent/'sent.json',json.dumps(result).encode());return {'sent':result['id']}
    raise ValueError('Unsupported Gmail action')
