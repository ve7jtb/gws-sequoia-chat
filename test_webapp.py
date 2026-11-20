"""Real Sequoia with disposable protected keys and fake Google transport.

--serve starts the same isolated fixtures for browser tests, never real mail.
"""
import base64
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import chat
import webapp

PASSWORD='disposable-browser-test-password'
SPACE='spaces/TEST'
MESSAGE=SPACE+'/messages/test'

class Fixture:
    def __init__(self, levels=('3','5')):
        self.tmp=tempfile.TemporaryDirectory(prefix='sequoia-web-test-');self.root=Path(self.tmp.name).resolve()
        (self.root/'private/profiles/demo').mkdir(parents=True);self.paths={}
        for level in levels:
            for who in ('alice','bob'):
                path=self.root/'private'/(who+'-'+level)
                chat.generate(path,who+'@example.test',level,test_only=True)
                # Test-only password file. Production uses an inherited pipe.
                pw=self.root/'test-password';pw.write_text(PASSWORD);secured=path/'protected.pgp'
                chat.sq('key','password','--cert-file',path/'secret.pgp','--new-password-file',pw,'--output',secured,batch=True)
                secured.replace(path/'secret.pgp');pw.unlink();self.paths[level,who]=path
        self.app=webapp.LocalApp(self.root);self.app.profile='demo'
        for path in self.paths.values():
            info=chat.public_info(path/'public.pgp')
            self.app.action('trust-contact',{'certificate':base64.b64encode(chat.read(path/'public.pgp')).decode(),
                'email':info['emails'][0],'fingerprint':info['fingerprint'],'confirmed':True})
        self.bundle=None;self.calls=[]
    def close(self):self.tmp.cleanup()
    def ids(self,level,who):
        path=self.paths[level,who];own=next(x for x in self.app.identities.values() if x['public']==path/'public.pgp')
        contact=next(x for x in self.app.contacts.values() if x['public'].stem==own['info']['fingerprint'])
        return own['id'],contact['id']
    def prepare(self,level='3',password=PASSWORD):
        own,_=self.ids(level,'alice');_,peer=self.ids(level,'bob')
        return self.app.action('prepare',{'identity':own,'contact':peer,'sender':'alice@example.test',
            'space':SPACE,'subject':'Synthetic browser test','text':'Plain message from Alice.',
            'html':'<p><b>Formatted message</b></p><img src="https://invalid.example/track"><script>alert(1)</script>',
            'attachments':[{'name':'example.txt','data':base64.b64encode(b'Synthetic attachment').decode()}],'password':password})
    def receive(self,name,target):
        assert name==MESSAGE;target=chat.private_dir(target)
        chat.write_new(target/'message.pgp',self.bundle['ciphertext']);chat.write_new(target/'pq-mail-sender-key.pgp',self.bundle['public'])
    def open(self,level='3',password=PASSWORD,peer='alice'):
        own,_=self.ids(level,'bob');_,contact=self.ids(level,peer)
        with patch.object(chat,'receive',self.receive):
            return self.app.action('open',{'message':MESSAGE,'identity':own,'contact':contact,'recipient':'bob@example.test','password':password})
    def gws(self,*args,**kwargs):
        self.calls.append(args)
        if args[:3]==('chat','spaces','list'):return {'spaces':[{'name':SPACE,'displayName':'Synthetic interoperability test','spaceType':'SPACE'}]}
        if args[:4]==('chat','spaces','messages','list'):
            params=json.loads(args[args.index('--params')+1]);older=params.get('pageToken')=='older'
            result={'messages':[{'name':MESSAGE,'createTime':'2026-11-20T17:00:00Z','sender':{'displayName':'Alice (test)','name':'users/test'},
                'text':'Older synthetic page' if older else 'Signed and encrypted test bundle.','attachment':[{'contentName':'message.pgp'}]}]}
            if not older:result['nextPageToken']='older'
            return result
        if args[:3]==('chat','media','upload'):return {'attachmentDataRef':{'attachmentUploadToken':'test-upload'}}
        if args[:4]==('chat','spaces','messages','create'):return {'name':MESSAGE}
        raise AssertionError('Unexpected test API operation')

class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):os.umask(0o077);cls.f=Fixture()
    @classmethod
    def tearDownClass(cls):cls.f.close()
    def setUp(self):self.f.app.profile='demo';self.f.app.drafts.clear()
    def test_real_protected_level3_and_level5_round_trips(self):
        for level in ('3','5'):
            with self.subTest(level=level):
                r=self.f.prepare(level);self.f.bundle=self.f.app.drafts[r['review']];result=self.f.open(level)
                self.assertTrue(result['signatureValid']);self.assertEqual(result['subject'],'Synthetic browser test')
                self.assertIn('Plain message',result['text']);self.assertIn('<b>Formatted message</b>',result['html'])
                for unsafe in ('<img','<script','alert(1)'):self.assertNotIn(unsafe,result['html'])
                self.assertEqual(base64.b64decode(result['attachments'][0]['data']),b'Synthetic attachment')
    def test_wrong_password_and_wrong_sender_rejected(self):
        with self.assertRaises(ValueError):self.f.prepare(password='wrong password')
        self.assertFalse(self.f.app.drafts)
        r=self.f.prepare();self.f.bundle=self.f.app.drafts[r['review']]
        with self.assertRaises(ValueError):self.f.open(password='wrong password')
        with self.assertRaises(ValueError):self.f.open(peer='bob')
    def test_tampering_rejected_before_plaintext_return(self):
        r=self.f.prepare();self.f.bundle=dict(self.f.app.drafts[r['review']]);value=bytearray(self.f.bundle['ciphertext']);value[-32]^=1;self.f.bundle['ciphertext']=bytes(value)
        with self.assertRaises(ValueError):self.f.open()
    def test_send_confirmation_and_once_only(self):
        r=self.f.prepare()
        with patch.object(chat,'gws',self.f.gws):
            with self.assertRaises(ValueError):self.f.app.action('send',{'review':r['review'],'confirmed':False})
            result=self.f.app.action('send',{'review':r['review'],'confirmed':True});self.assertEqual(result['sent'],MESSAGE)
            with self.assertRaises(KeyError):self.f.app.action('send',{'review':r['review'],'confirmed':True})
        for sent in self.f.app.settings.glob('sent-*'):
            for path in sent.iterdir():
                self.assertNotIn(PASSWORD.encode(),path.read_bytes());self.assertNotIn(b'Plain message from Alice.',path.read_bytes())
    def test_account_change_discards_prepared_send(self):
        r=self.f.prepare()
        with patch.object(chat,'gws',self.f.gws):self.f.app.action('connect',{'profile':'demo'})
        with self.assertRaises(KeyError):self.f.app.action('send',{'review':r['review'],'confirmed':True})
    def test_no_trust_without_confirmation_and_no_secret_certificates(self):
        p=self.f.paths['3','alice']/'public.pgp';info=chat.public_info(p)
        with self.assertRaises(ValueError):self.f.app.action('trust-contact',{'certificate':base64.b64encode(chat.read(p)).decode(),'email':'alice@example.test','fingerprint':info['fingerprint'],'confirmed':False})
        with self.assertRaises(ValueError):self.f.app.contact_preview({'certificate':base64.b64encode(chat.read(p.parent/'secret.pgp')).decode()})
    def test_trust_persists_and_removal_persists(self):
        app=webapp.LocalApp(self.f.root);_,cid=self.f.ids('5','bob');self.assertIn(cid,app.contacts)
        app.action('remove-trust',{'contact':cid});self.assertNotIn(cid,webapp.LocalApp(self.f.root).contacts)
        peer=self.f.app.contacts[cid]
        app.action('trust-contact',{'certificate':base64.b64encode(chat.read(peer['public'])).decode(),'email':peer['email'],'fingerprint':peer['info']['fingerprint'],'confirmed':True})
    def test_mime_paths_and_external_html_blocked(self):
        for name in ('../secret','bad\nfile','C:\\bad'):
            with self.assertRaises(ValueError):webapp.mime_memory('a@b.test','c@d.test','test','hello',None,[{'name':name,'data':'AA=='}])
        safe=webapp.safe_html('<p onclick="bad()">Good</p><a href="https://bad">Link</a><svg><script>bad</script></svg>')
        self.assertIn('<p>Good</p>Link',safe)
        for unsafe in ('onclick','https://bad','<svg'):self.assertNotIn(unsafe,safe)

class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.app=webapp.LocalApp(cls.tmp.name);cls.server=webapp.Server(('127.0.0.1',0),cls.app)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.tmp.cleanup()
    def request(self,method='POST',path='/api/bootstrap',headers=None,body=b'{}'):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_address[1],timeout=5)
        h={'Origin':self.server.origin,'Authorization':'Bearer '+self.server.token,'Content-Type':'application/json'};h.update(headers or {})
        conn.request(method,path,body=body,headers=h);r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read());conn.close();return result
    def test_authorized_bootstrap_and_assets(self):
        code,headers,body=self.request();self.assertEqual(code,200);self.assertEqual(json.loads(body)['contacts'],[])
        for path in ('/','/app.js','/style.css'):
            code,headers,body=self.request('GET',path);self.assertEqual(code,200);self.assertEqual(headers['Cache-Control'],'no-store')
            self.assertNotIn(self.server.token.encode(),body);self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
    def test_cross_site_host_and_missing_token(self):
        for headers in ({'Origin':'https://evil.example'},{'Host':'evil.example'},{'Authorization':''},{'Sec-Fetch-Site':'cross-site'}):self.assertEqual(self.request(headers=headers)[0],403)
    def test_files_shell_and_malformed_requests_not_exposed(self):
        self.assertEqual(self.request('GET','/../chat.py')[0],404)
        self.assertEqual(self.request(path='/api/exec',body=b'{"cmd":"whoami"}')[0],400)
        self.assertEqual(self.request(body=b'[]')[0],400)
        self.assertEqual(self.request(headers={'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request(headers={'Content-Length':str(webapp.MAX_REQUEST+1)})[0],400)

def demo():
    os.umask(0o077);f=Fixture(('3',));r=f.prepare();f.bundle=f.app.drafts[r['review']];f.app.drafts.clear();f.app.profile=None
    with patch.object(chat,'gws',f.gws),patch.object(chat,'receive',f.receive):
        server=webapp.Server(('127.0.0.1',0),f.app);print(server.origin+'/#'+server.token,flush=True)
        try:server.serve_forever()
        except KeyboardInterrupt:pass
        finally:server.server_close();f.close()

if __name__=='__main__':
    if '--serve' in sys.argv:demo()
    else:unittest.main()
