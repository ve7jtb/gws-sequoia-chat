"""Offline Gmail/PGP-MIME tests with actual Sequoia and protected keys."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import chat
import mail_transport as mail
from test_webapp import Fixture,PASSWORD

class MailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=Fixture()
    @classmethod
    def tearDownClass(cls):cls.f.close()
    def setUp(self):
        self.app=self.f.app;self.app.drafts.clear();self.service=self.app.mail
        self.service.profile='demo-mail';self.service.address='alice@example.test'
        (self.f.root/'private/profiles/demo-mail').mkdir(exist_ok=True)
        self.raw=None;self.calls=[]
    def prepare(self,level='3'):
        own,_=self.f.ids(level,'alice');_,peer=self.f.ids(level,'bob')
        return self.app.action('mail-prepare',{'identity':own,'contact':peer,'sender':'alice@example.test','subject':'Protected subject',
            'text':'Protected mail body','html':'<p>Safe <b>formatting</b></p><img src="https://bad.example">',
            'attachments':[{'name':'test.txt','data':base64.b64encode(b'test attachment').decode()}],'password':PASSWORD})
    def fake(self,*args):
        self.calls.append(args)
        if args[:4]==('gmail','users','messages','get'):
            params=json.loads(args[args.index('--params')+1])
            if params['format']=='raw':return {'raw':base64.urlsafe_b64encode(self.raw).decode().rstrip('=')}
            return {'payload':{'headers':[{'name':'Subject','value':'Visible metadata'},{'name':'From','value':'alice@example.test'}]},'labelIds':['UNREAD']}
        if args[:4]==('gmail','users','messages','list'):return {'messages':[{'id':'abc'}],'nextPageToken':'next'}
        if args[:4]==('gmail','users','messages','send'):
            path=Path(args[args.index('--upload')+1]);self.upload=path.read_bytes();self.upload_path=path
            return {'id':'sent123'}
        raise AssertionError('Unexpected Gmail operation')
    def open(self,level='3',password=PASSWORD):
        own,_=self.f.ids(level,'bob');_,peer=self.f.ids(level,'alice')
        with patch.object(mail,'gws_memory',self.fake):
            return self.app.action('mail-open',{'identity':own,'contact':peer,'recipient':'bob@example.test','message':'abc','password':password})
    def test_real_level3_and_level5_pgp_mime_roundtrip(self):
        for level in ('3','5'):
            with self.subTest(level=level):
                review=self.prepare(level);self.raw=self.app.drafts[review['review']]['raw']
                outer=mail.parse_message(self.raw)
                self.assertEqual(outer.get_content_type(),'multipart/encrypted');self.assertEqual(len(list(outer.iter_parts())),2)
                self.assertIn(b'-----BEGIN PGP MESSAGE-----',mail.pgp_payload(outer))
                self.assertNotIn(b'Protected subject',self.raw);self.assertNotIn(b'Protected mail body',self.raw)
                result=self.open(level);self.assertTrue(result['signatureValid']);self.assertEqual(result['subject'],'Protected subject')
                self.assertIn('Protected mail body',result['text']);self.assertIn('<b>formatting</b>',result['html']);self.assertNotIn('<img',result['html'])
                self.assertEqual(base64.b64decode(result['attachments'][0]['data']),b'test attachment')
    def test_standard_body_only_pgp_mime_marks_outer_headers_unverified(self):
        from email.message import EmailMessage
        import email.policy
        own,_=self.f.ids('3','alice');_,peer=self.f.ids('3','bob')
        msg=EmailMessage(policy=email.policy.SMTP);msg.set_content('Standard PGP/MIME body')
        with tempfile.TemporaryDirectory() as tmp:
            cert=Path(tmp)/'recipient.pgp';cert.write_bytes(chat.hybrid_public(self.app.contacts[peer]['public']))
            cipher=self.service.crypto(['encrypt','--for-file',cert,'--signer-file',self.app.identities[own]['secret'],
                '--profile','rfc9580','--compression','zip','-'],msg.as_bytes(),PASSWORD)
        self.raw=mail.encrypted_envelope('alice@example.test','bob@example.test',cipher)
        result=self.open();self.assertTrue(result['signatureValid']);self.assertFalse(result['headersAuthenticated'])
        self.assertIn('Standard PGP/MIME body',result['text'])
        self.raw=self.raw.replace(b'From: alice@example.test',b'From: attacker@example.test')
        with self.assertRaises(ValueError):self.open()

    def test_gmail_rewritten_envelope_and_ambiguity_rejection(self):
        from email.message import EmailMessage
        import email.policy
        r=self.prepare();original=mail.parse_message(self.app.drafts[r['review']]['raw'])
        cipher=mail.pgp_payload(original)
        rewritten=EmailMessage(policy=email.policy.SMTP)
        rewritten['From']='alice@example.test';rewritten['To']='bob@example.test';rewritten.set_type('multipart/mixed')
        payload=EmailMessage(policy=email.policy.SMTP);payload.set_content(cipher.decode('ascii'))
        control=EmailMessage(policy=email.policy.SMTP);control.set_content(b'Version: 1\r\n',maintype='application',subtype='pgp-encrypted',cte='base64')
        rewritten.attach(payload);rewritten.attach(control);self.raw=rewritten.as_bytes()
        with patch.object(mail,'gws_memory',self.fake):self.assertTrue(self.app.action('mail-read',{'message':'abc'})['encrypted'])
        result=self.open();self.assertTrue(result['signatureValid']);self.assertIn('Protected mail body',result['text'])
        payload.replace_header('Content-Type','application/octet-stream');self.raw=rewritten.as_bytes()
        self.assertTrue(self.open()['signatureValid'])
        payload.set_content('Unverified prefix\n'+cipher.decode('ascii'));self.raw=rewritten.as_bytes()
        with self.assertRaises(ValueError):self.open()
        payload.set_content(cipher.decode('ascii')+cipher.decode('ascii'));self.raw=rewritten.as_bytes()
        with self.assertRaises(ValueError):self.open()
        payload.set_content(cipher.decode('ascii'));extra=EmailMessage();extra.set_content('Unverified extra');rewritten.attach(extra);self.raw=rewritten.as_bytes()
        with self.assertRaises(ValueError):self.open()

    def test_outer_headers_cannot_override_verified_identity(self):
        r=self.prepare();self.raw=self.app.drafts[r['review']]['raw'].replace(b'From: alice@example.test',b'From: attacker@example.test')
        result=self.open();self.assertEqual(result['sender'],'alice@example.test')
    def test_bad_password_and_tampering_rejected(self):
        r=self.prepare();self.raw=self.app.drafts[r['review']]['raw']
        with self.assertRaises(ValueError):self.open(password='wrong')
        msg=mail.parse_message(self.raw);parts=list(msg.iter_parts());parts[1].set_payload('invalid ciphertext');self.raw=msg.as_bytes()
        with self.assertRaises(ValueError):self.open()
    def test_search_metadata_and_pagination(self):
        with patch.object(mail,'gws_memory',self.fake):r=self.app.action('mail-list',{'query':'from:alice@example.test','folder':'SENT','pageToken':'cursor'})
        self.assertEqual(r['nextPageToken'],'next');self.assertTrue(r['messages'][0]['unread'])
        params=json.loads(self.calls[0][self.calls[0].index('--params')+1])
        self.assertEqual(params['q'],'from:alice@example.test');self.assertEqual(params['labelIds'],['SENT']);self.assertEqual(params['pageToken'],'cursor')
        self.assertFalse(any('raw' in a for a in self.calls))
    def test_ordinary_mail_never_claims_verification(self):
        self.raw=chat.mime_bytes('alice@example.test','bob@example.test','Plain mail','hello','<b>Bold</b><script>bad()</script>')
        with patch.object(mail,'gws_memory',self.fake):r=self.app.action('mail-read',{'message':'abc'})
        self.assertFalse(r['signatureValid']);self.assertFalse(r['encrypted']);self.assertIn('forged',r['notice']);self.assertNotIn('bad()',r['html'])
    def test_encrypted_preview_does_not_release_plaintext(self):
        r=self.prepare();self.raw=self.app.drafts[r['review']]['raw']
        with patch.object(mail,'gws_memory',self.fake):r=self.app.action('mail-read',{'message':'abc'})
        self.assertTrue(r['encrypted']);self.assertEqual(r['text'],'');self.assertEqual(r['attachments'],[])
    def test_send_confirmation_once_only_and_encrypted_staging(self):
        r=self.prepare()
        with patch.object(mail,'gws_memory',self.fake):
            with self.assertRaises(ValueError):self.app.action('mail-send',{'review':r['review'],'confirmed':False})
            sent=self.app.action('mail-send',{'review':r['review'],'confirmed':True});self.assertEqual(sent['sent'],'sent123')
            with self.assertRaises(KeyError):self.app.action('mail-send',{'review':r['review'],'confirmed':True})
        self.assertFalse(self.upload_path.exists());self.assertNotIn(b'Protected mail body',self.upload)
        self.assertNotIn(PASSWORD,str(self.calls))
    def test_sender_must_match_google_account(self):
        self.service.address='another@example.test'
        with self.assertRaises(ValueError):self.prepare()
    def test_mail_profile_copies_no_chat_tokens(self):
        source=self.f.root/'private/profiles/demo';(source/'client_secret.json').write_text('{"installed":{}}')
        (source/'credentials.enc').write_text('synthetic token marker')
        self.assertEqual(self.service.profile_for('demo'),'demo-mail')
        target=self.f.root/'private/profiles/demo-mail'
        self.assertTrue((target/'client_secret.json').exists());self.assertFalse((target/'credentials.enc').exists())
        self.assertNotIn('mail.google.com',mail.SCOPES);self.assertNotIn('gmail.modify',mail.SCOPES)
    def test_malformed_mime_base64_and_ids_rejected(self):
        for value in ('../bad','bad?id=abc',''):
            with self.assertRaises(ValueError):mail.message_id(value)
        with self.assertRaises(ValueError):mail.raw_message('%%%')
        with self.assertRaises(ValueError):mail.pgp_payload(mail.parse_message(b'Content-Type: text/plain\r\n\r\nhello'))

if __name__=='__main__':unittest.main()
