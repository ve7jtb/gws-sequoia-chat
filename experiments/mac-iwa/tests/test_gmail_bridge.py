import sys,unittest,importlib.util,tempfile,json
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT/'native'))
import gmail_bridge,chat_bridge
class GmailTests(unittest.TestCase):
 def test_closed_schema(self):
  for request in [{'op':'chat-mail-delete','message':'x'},{'op':'chat-mail-send','review':'x','confirmed':False},{'op':'chat-mail-open','message':'x','contact':'y','path':'/tmp/key'}]:
   with self.assertRaises(ValueError):chat_bridge.validate(request)
 def run_action(self,op,response):
  with tempfile.TemporaryDirectory() as d:
   b=Mock();b.root=Path(d);b.cfg={'chat_email':'me@example.invalid'};b.data=Path(d);m=Mock();m.gws_memory.return_value=response
   spec=Mock();spec.loader.exec_module=Mock()
   with patch.object(gmail_bridge.importlib.util,'spec_from_file_location',return_value=spec),patch.object(gmail_bridge.importlib.util,'module_from_spec',return_value=m):
    return gmail_bridge.action(b,op)
 def test_account_mismatch(self):
  with self.assertRaises(ValueError):self.run_action({'op':'chat-mail-connect'},{'emailAddress':'wrong@example.invalid'})
 def test_account_matches(self):
  self.assertEqual(self.run_action({'op':'chat-mail-connect'},{'emailAddress':'me@example.invalid'}),{'account':'me@example.invalid'})

 def test_upload_staging_and_cleanup(self):
  for fails in (False,True):
   with tempfile.TemporaryDirectory() as d:
    b=Mock();b.root=Path(d);profile=b.root/'runtime/chat/private/gws';profile.mkdir(parents=True)
    source=b.root/'encrypted.eml';source.write_bytes(b'encrypted synthetic fixture')
    paths=[]
    def api(*args):
     p=Path(args[args.index('--upload')+1]);paths.append(p)
     self.assertIn(profile,p.parents);self.assertEqual(p.read_bytes(),source.read_bytes())
     self.assertEqual(p.stat().st_mode & 0o777,0o600)
     self.assertIn('--json',args)
     if fails:raise ValueError('network failure')
     return {'id':'test'}
    if fails:
     with self.assertRaises(ValueError):gmail_bridge.upload_encrypted_mail(b,api,source)
    else:self.assertEqual(gmail_bridge.upload_encrypted_mail(b,api,source),{'id':'test'})
    self.assertEqual(len(paths),1);self.assertFalse(paths[0].exists());self.assertTrue(source.exists())

 def test_service_pin_labels(self):
  for service in ('Chat','Gmail'):
   for op,verb in (('seal','Sign and encrypt'),('open','Decrypt and verify')):
    self.assertEqual(chat_bridge.crypto_prompt(op,service),verb+' '+service+(' email' if service=='Gmail' else ' bundle'))
  with self.assertRaises(ValueError):chat_bridge.crypto_prompt('open','untrusted prompt')

 def test_ordinary_multipart_is_unverified_and_exact_attachment(self):
  from email.message import EmailMessage
  msg=EmailMessage();msg['Subject']='Ordinary';msg['From']='sender@example.invalid'
  msg.set_content('Plain text');msg.add_alternative('<b>HTML</b><img src="https://example.invalid/pixel">',subtype='html')
  msg.add_attachment(bytes(range(256)),maintype='application',subtype='octet-stream',filename='file.bin')
  result=gmail_bridge.ordinary_message(msg)
  self.assertFalse(result['verified']);self.assertFalse(result['encrypted'])
  self.assertIn('Plain text',result['text']);self.assertIn('<b>HTML</b>',result['html'])
  import base64
  self.assertEqual(base64.b64decode(result['attachments'][0]['data']),bytes(range(256)))
 def test_ordinary_wire_limit_and_large_attachment(self):
  from email.message import EmailMessage
  msg=EmailMessage();msg.set_content('\x01'*70000);msg.add_alternative('\x02'*70000,subtype='html')
  msg.add_attachment(b'x'*131073,maintype='application',subtype='octet-stream',filename='too-large.bin')
  result=gmail_bridge.ordinary_message(msg)
  self.assertEqual(result['omittedAttachments'],1);self.assertLessEqual(len(json.dumps(result).encode()),400000)
 def test_real_encryption_detection_rejects_ordinary_mixed(self):
  from email.message import EmailMessage
  repo=ROOT.parents[1]
  spec=importlib.util.spec_from_file_location('fixture_chat',repo/'chat.py');chat=importlib.util.module_from_spec(spec);spec.loader.exec_module(chat)
  with patch.dict(sys.modules,{'chat':chat}):
   spec=importlib.util.spec_from_file_location('fixture_mail',repo/'mail_transport.py');mail=importlib.util.module_from_spec(spec);spec.loader.exec_module(mail)
  ordinary=EmailMessage();ordinary.set_content('Encrypted OpenPGP message')
  ordinary.add_attachment(b'not encryption',maintype='application',subtype='octet-stream',filename='encrypted.asc')
  self.assertIsNone(gmail_bridge.encrypted_payload(mail,ordinary))
  armor=b'-----BEGIN PGP MESSAGE-----\r\n\r\nYWJj\r\n-----END PGP MESSAGE-----\r\n'
  encrypted=mail.parse_message(mail.encrypted_envelope('a@example.invalid','b@example.invalid',armor))
  self.assertIsNotNone(gmail_bridge.encrypted_payload(mail,encrypted))
  encrypted.set_type('multipart/mixed')
  self.assertIsNotNone(gmail_bridge.encrypted_payload(mail,encrypted))
  encrypted.attach(EmailMessage())
  self.assertIsNone(gmail_bridge.encrypted_payload(mail,encrypted))

class SignedMailTests(unittest.TestCase):
 def envelope(self):
  raw=(b'From: sender@example.invalid\r\nSubject: Unauthenticated subject\r\nContent-Type: multipart/signed; boundary="signed"; protocol="application/pgp-signature"\r\n\r\nPreamble\r\n--signed\r\nContent-Type: text/plain\r\nX-Folded: a\r\n b\r\n\r\nSigned body\r\n\r\n--signed\r\nContent-Type: application/pgp-signature\r\n\r\nfake signature\r\n--signed--\r\n')
  return raw,gmail_bridge.BytesParser(policy=gmail_bridge.policy.default).parsebytes(raw)
 def test_exact_signed_entity_and_transport_newlines(self):
  raw,msg=self.envelope();payload,signature,part=gmail_bridge.signed_parts(raw,msg)
  self.assertEqual(payload,b'Content-Type: text/plain\r\nX-Folded: a\r\n b\r\n\r\nSigned body\r\n')
  self.assertEqual(gmail_bridge.signed_parts(raw.replace(b'\r\n',b'\n'),msg)[0],payload)
 def test_trust_is_separate_from_validity_and_bound_to_email(self):
  raw,msg=self.envelope()
  with tempfile.TemporaryDirectory() as d:
   b=Mock();b.root=b.data=Path(d);(b.data/'ABC.pgp').write_bytes(b'public only')
   b.contacts.return_value=[{'fingerprint':'ABC','email':'sender@example.invalid'}]
   worker=Mock(returncode=0,stdout=json.dumps({'signatures':[{'status':'valid','fingerprint':'ABC','algorithm':'Ed25519','emails':['sender@example.invalid']}]}).encode())
   with patch.object(gmail_bridge.subprocess,'run',return_value=worker) as run:
    r=gmail_bridge.signed_message(b,raw,msg);self.assertTrue(r['verified']);self.assertFalse(r['encrypted']);self.assertEqual(r['certificateTrust'],'trusted')
    self.assertNotIn('pin',json.loads(run.call_args.kwargs['input']))
    b.contacts.return_value[0]['email']='different@example.invalid'
    r=gmail_bridge.signed_message(b,raw,msg);self.assertTrue(r['verified']);self.assertEqual(r['certificateTrust'],'untrusted')
    worker.stdout=json.dumps({'signatures':[{'status':'invalid'}]}).encode()
    r=gmail_bridge.signed_message(b,raw,msg);self.assertFalse(r['verified']);self.assertEqual(r['signatureStatus'],'invalid')
    b.crypto.assert_not_called()
 def test_malformed_signed_message_not_unsigned(self):
  raw,msg=self.envelope();msg.set_boundary('different')
  b=Mock();r=gmail_bridge.signed_message(b,raw,msg)
  self.assertEqual(r['signatureStatus'],'invalid');b.contacts.assert_not_called()
