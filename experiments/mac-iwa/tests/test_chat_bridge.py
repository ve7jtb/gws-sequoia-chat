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

 def test_native_mime_and_standalone_runtime_dependency_are_removed(self):
  for name in ('compose_mime','browser_mime','validate_attachments'):
   self.assertFalse(hasattr(mod,name))
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'private').mkdir()
   # No runtime/chat folder or frontend modules exist. Constructing the real
   # private-component bridge must not import a hidden transport dependency.
   b=mod.ChatBridge(root,{},lambda value:None)
   self.assertFalse(hasattr(b,'chat'))
   self.assertTrue(b.data.is_dir())
 def test_removed_full_message_crypto_fails_before_presence_or_pin(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.bridge(d)
   with patch.object(mod.subprocess,'run') as run,patch.object(mod.subprocess,'check_output') as present:
    for op in ('seal','open','open-browser','sign-browser','decapsulate-browser'):
     with self.assertRaises(ValueError):mod.ChatBridge.crypto(b,op,None,b'')
    run.assert_not_called();present.assert_not_called()
