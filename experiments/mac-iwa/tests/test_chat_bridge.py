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
 def test_send_consumes_review_before_network_failure(self):
  with tempfile.TemporaryDirectory() as d:
   b=self.bridge(d);rid='a'*48;p=Path(d)/('draft-'+rid);p.mkdir();(p/'review.json').write_text(json.dumps({'space':'spaces/TEST','created':time.time()}));b.chat.send.side_effect=RuntimeError('synthetic failure')
   r={'op':'chat-send','review':rid,'confirmed':True}
   with self.assertRaises(RuntimeError):b.action(r)
   with self.assertRaises(FileNotFoundError):b.action(r)
   b.chat.send.assert_called_once();self.assertTrue((Path(d)/('sent-'+rid)).is_dir())
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
