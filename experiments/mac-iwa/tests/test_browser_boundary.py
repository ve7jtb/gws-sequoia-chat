"""The native boundary no longer owns message parsing or recipient trust."""
import base64,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
from chat_bridge import ChatBridge,validate

class BrowserBoundary(unittest.TestCase):
 def test_removed_native_certificate_and_send_routes_are_closed(self):
  # Stale extensions or direct Native Messaging clients cannot restore the old
  # trust authority. Rejection happens before a directory, PIN or card access.
  for op in ('chat-preview','chat-trust','chat-cert-list','chat-cert-untrust',
             'chat-cert-delete','chat-verification-material','chat-decrypt',
             'chat-browser-prepare','chat-browser-export','chat-browser-cert-save',
             'chat-browser-cert-trust','chat-encryption-complete','chat-prepare',
             'chat-mail-prepare','chat-send','chat-mail-send'):
   with self.assertRaises(ValueError):validate({'op':op})
 def test_decapsulation_accepts_ciphertext_and_service_only(self):
  request={'op':'chat-decap','payload':'YQ==','service':'Gmail'}
  self.assertEqual(validate(request),'chat-decap')
  for key in ('pin','module','slot','serial','path','contact','recipient','peer','certificate'):
   with self.assertRaises(ValueError):validate({**request,key:'unexpected'})
 def test_decapsulation_uses_only_installed_identity_and_returns_no_trust(self):
  with tempfile.TemporaryDirectory() as tmp:
   b=ChatBridge.__new__(ChatBridge);b.data=Path(tmp);own=Path(tmp)/'configured-own'
   b.cfg={'cert':str(own),'chat_email':'me@example.invalid'};b.chat=Mock()
   b.crypto=Mock(return_value={'sessionKey':'test-only','algorithm':9,'cipherHash':'0'*64,'recipientKey':'A'*64})
   r=b.action({'op':'chat-decap','payload':'YQ==','service':'Gmail'})
   b.crypto.assert_called_once_with('decapsulate-browser',own,b'a',service='Gmail')
   self.assertEqual(set(r),{'sessionKey','algorithm','cipherHash','recipientKey','cipher'})
   for payload,service in [('','Gmail'),('!','Gmail'),(base64.b64encode(bytes(262145)).decode(),'Gmail'),('YQ==','untrusted')]:
    with self.assertRaises(ValueError):b.action({'op':'chat-decap','payload':payload,'service':service})
   self.assertEqual(b.crypto.call_count,1)
 def test_state_never_loads_or_infers_native_contact_trust(self):
  with tempfile.TemporaryDirectory() as tmp:
   b=ChatBridge.__new__(ChatBridge);b.data=Path(tmp)
   b.cfg={'cert':'configured-own','chat_email':'me@example.invalid','serial':'123'};b.chat=Mock()
   b.chat.check_cert.return_value={'fingerprint':'A'*64}
   # A corrupt old contact must not prevent discovery of the own hardware key.
   (b.data/'contact-stale.json').write_text('invalid JSON')
   r=b.action({'op':'chat-state'})
   self.assertEqual(r['contacts'],[]);self.assertEqual(r['serial'],'123')

if __name__=='__main__':unittest.main()
