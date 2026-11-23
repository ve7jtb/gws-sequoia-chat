"""Offline request, trust and send-confirmation tests; no Google credentials."""
import importlib.util,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch,Mock
spec=importlib.util.spec_from_file_location('chat_bridge',Path(__file__).parents[1]/'native/chat_bridge.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class ChatTests(unittest.TestCase):
 def test_extra_commands_rejected(self):
  for r in [{'op':'chat-exec','cmd':'anything'},{'op':'chat-spaces','page':'','profile':'other'},{'op':'chat-send','review':'a'*48,'confirmed':False}]:
   with self.assertRaises(ValueError):mod.validate(r)
 def test_limits(self):
  for r in [{'op':'chat-spaces','page':'x'*4097},{'op':'chat-prepare','space':'spaces/A','contact':'x','subject':'x','body':'x'*400001}]:
   with self.assertRaises(ValueError):mod.validate(r)
 def bridge(self,d):
  b=mod.ChatBridge.__new__(mod.ChatBridge);b.data=Path(d);b.chat=Mock();b.cfg={};return b
 def test_legacy_native_google_transport_is_disabled(self):
  # Browser-owned OAuth/HTTP must never fall back to an old gws credential.
  requests=[{'op':'chat-send','review':'a'*48,'confirmed':True},
            {'op':'chat-mail-send','review':'a'*48,'confirmed':True},
            {'op':'chat-login'},{'op':'chat-mail-connect'},
            {'op':'chat-spaces','page':''}]
  with tempfile.TemporaryDirectory() as d:
   b=self.bridge(d)
   for request in requests:
    with self.assertRaises(ValueError):b.action(request)
   b.chat.send.assert_not_called();b.chat.gws.assert_not_called()
 def test_legacy_browser_export_cannot_consume_or_create_disk_drafts(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.bridge(d);p=Path(d)/('draft-'+'a'*48);p.mkdir()
   (p/'review.json').write_text('{"synthetic":"unchanged"}')
   for op in ('chat-browser-export','chat-encryption-complete','chat-browser-prepare'):
    with self.assertRaises(ValueError):b.action({'op':op})
   self.assertEqual((p/'review.json').read_text(),'{"synthetic":"unchanged"}')
   b.chat.write_new.assert_not_called()
 def test_expired_review_never_sends(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.bridge(d);rid='a'*48;p=Path(d)/('draft-'+rid);p.mkdir();(p/'review.json').write_text(json.dumps({'space':'spaces/TEST','created':0}))
   with self.assertRaises(ValueError):b.action({'op':'chat-send','review':rid,'confirmed':True})
   b.chat.send.assert_not_called()
 def test_untrusted_certificate_never_calls_token(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.bridge(d);b.cfg={'chat_email':'me@example.invalid'};b.peer=Mock(return_value=({'email':'peer@example.invalid'},Path(d)/'peer.pgp'));b.chat.public_packets.side_effect=[b'wrong',b'expected'];b.crypto=Mock()
   with self.assertRaises(ValueError):b.action({'op':'chat-open','message':'spaces/TEST/messages/M','contact':'peer'})
   b.crypto.assert_not_called()

class MimeTests(unittest.TestCase):
 def test_attachment_validation(self):
  import base64
  for files in [[{'name':'../bad','data':''}],[{'name':'ok','data':'!'}],[{'name':'x','data':base64.b64encode(b'x'*131073).decode()}]]:
   with self.assertRaises(ValueError):mod.validate_attachments(files)
 def test_multipart_alternatives_and_exact_file(self):
  from email.message import EmailMessage
  from email import policy
  from email.parser import BytesParser
  import base64
  def make(sender,to,subject,text,html):
   m=EmailMessage(policy=policy.SMTP);m['From']=sender;m['To']=to;m['Subject']=subject;m.set_content(text);m.add_alternative(html,subtype='html');return m.as_bytes()
  chat=Mock();chat.mime_bytes.side_effect=make
  payload=b'\x00\xffsynthetic attachment\r\n'
  request={'subject':'Test','body':'Hello','html':'<p><strong>Hello</strong></p>','attachments':[{'name':'test.bin','data':base64.b64encode(payload).decode()}]}
  raw=mod.compose_mime(chat,request,'a@example.invalid','b@example.invalid');m=BytesParser(policy=policy.default).parsebytes(raw)
  self.assertEqual(m.get_content_type(),'multipart/mixed');self.assertEqual(m.get_body(('plain',)).get_content().strip(),'Hello');self.assertIn('<strong>',m.get_body(('html',)).get_content());self.assertEqual(next(m.iter_attachments()).get_payload(decode=True),payload)
