"""The native boundary no longer owns message parsing or recipient trust."""
import base64,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
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
 def test_legacy_envelope_decapsulation_routes_are_disabled(self):
  # All untrusted recipient packets now go to WASM. A stale IWA must not use
  # the former native parser/session-key path after the component migration.
  for request in ({'op':'chat-decap','payload':'YQ==','service':'Gmail'},
                  {'op':'chat-vault-decapsulate','payload':'YQ==','recipientKey':'A'*64}):
   with self.assertRaises(ValueError):validate(request)
 def test_state_never_loads_or_infers_native_contact_trust(self):
  with tempfile.TemporaryDirectory() as tmp:
   b=ChatBridge.__new__(ChatBridge);b.data=Path(tmp)
   b.cfg={'cert':'configured-own','chat_email':'me@example.invalid','serial':'123'};b.chat=Mock()
   b.chat.check_cert.return_value={'fingerprint':'A'*64}
   # A corrupt old contact must not prevent discovery of the own hardware key.
   (b.data/'contact-stale.json').write_text('invalid JSON')
   with patch('chat_bridge.check_certificate',return_value={'fingerprint':'A'*64}):r=b.action({'op':'chat-state'})
   self.assertEqual(r['contacts'],[]);self.assertEqual(r['serial'],'123')

if __name__=='__main__':unittest.main()
