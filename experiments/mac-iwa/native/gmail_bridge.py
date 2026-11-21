"""Bounded Gmail transport for the IWA, using the existing hardware crypto.

Only encrypted PGP/MIME is sent. Plaintext, HTML and files remain in memory until
wrapped by the signed/encrypted OpenPGP packet stream. No Gmail delete API exists.
"""
import base64,json,time,secrets,re,sys,importlib.util,tempfile
from pathlib import Path
from email import policy
from email.parser import BytesParser
from chat_bridge import compose_mime

SCOPES=','.join('https://www.googleapis.com/auth/'+s for s in ('gmail.readonly','gmail.send'))
FIELDS={'chat-mail-list':{'page','query'},'chat-mail-open':{'message','contact'},'chat-mail-prepare':{'contact','subject','body','html','attachments'},'chat-mail-send':{'review','confirmed'},'chat-mail-connect':set(),'chat-mail-login':set()}

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
            mid=m.message_id(item['id']);v=api('users','messages','get','--params',json.dumps({'userId':'me','id':mid,'format':'metadata','metadataHeaders':['From','Subject','Date']}));h={x['name'].lower():x['value'] for x in v.get('payload',{}).get('headers',[])}
            rows.append({'name':mid,'text':h.get('from','')+' — '+h.get('subject',''),'time':h.get('date',''),'encrypted':True})
        return {'messages':rows,'next':data.get('nextPageToken','')}
    if op=='chat-mail-open':
        account();contact,peer=b.peer(r['contact']);v=api('users','messages','get','--params',json.dumps({'userId':'me','id':m.message_id(r['message']),'format':'raw'}))
        outer=m.parse_message(m.raw_message(v['raw']));clear=b.crypto('open',peer,m.pgp_payload(outer));mime=b.chat.inspect_mime(clear,contact['email'],b.cfg['chat_email'])
        return {'verified':True,'sender':contact['email'],'fingerprint':contact['fingerprint'],'subject':mime['subject'],'text':'\n'.join(mime['plain']),'html':'\n'.join(mime['html']),'attachments':[{'name':n,'size':len(d),'data':base64.b64encode(d).decode()} for n,d in mime['files']]}
    if op=='chat-mail-prepare':
        account();contact,peer=b.peer(r['contact']);raw=compose_mime(b.chat,r,b.cfg['chat_email'],contact['email']);cipher=b.crypto('seal',peer,raw)
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
