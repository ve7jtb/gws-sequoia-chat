import base64,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native'))
import chat_bridge,vault_piv
class VaultBridge(unittest.TestCase):
 def test_closed_requests(self):
  self.assertEqual(chat_bridge.validate({'op':'chat-vault-material'}),'chat-vault-material')
  for r in [{'op':'chat-vault-material','pin':'secret'},{'op':'chat-vault-ecdh','peer':'a','fingerprint':'b','slot':'9a'}]:
   with self.assertRaises(ValueError):chat_bridge.validate(r)
 def test_vault_prompt_is_not_a_message_prompt(self):
  self.assertEqual(chat_bridge.crypto_prompt('decapsulate-components','Vault'),'Unlock IWA credential vault — ML-KEM-768 + X25519')
  with self.assertRaises(ValueError):chat_bridge.crypto_prompt('seal','Vault')
 def test_classical_config_has_fixed_serial_slot_and_curve(self):
  b=Mock();b.cfg={};self.assertIsNone(vault_piv.configured(b))
  good={'serial':'123','slot':'82','algorithm':'ECDH-P384','public':base64.b64encode(bytes(120)).decode()}
  b.cfg={'vault_piv':good};self.assertEqual(len(vault_piv.configured(b)['fingerprint']),64)
  for k,v in [('slot','9a'),('serial','*'),('algorithm','RSA'),('public','!')]:
   b.cfg={'vault_piv':{**good,k:v}}
   with self.assertRaises(ValueError):vault_piv.configured(b)
 def test_old_vault_packet_route_rejected_before_private_operation(self):
  # The new one-use component route is shared by vault and message operations;
  # it cannot silently fall back to native OpenPGP packet/session-key recovery.
  with tempfile.TemporaryDirectory() as t:
   b=chat_bridge.ChatBridge.__new__(chat_bridge.ChatBridge);b.data=Path(t);b.crypto=Mock()
   with self.assertRaises(ValueError):b.action({'op':'chat-vault-decapsulate','payload':'YQ==','recipientKey':'A'*64})
   b.crypto.assert_not_called()

class VaultDiagnostics(unittest.TestCase):
 def test_closed_status_codes(self):
  self.assertEqual(chat_bridge.crypto_status(b'IWA_CRYPTO_STATUS=MLKEM_FAILED\n'), 'MLKEM_FAILED')
  for value in (b'PIN=private', b'IWA_CRYPTO_STATUS=MLKEM_FAILED private', b'IWA_CRYPTO_STATUS=unknown'):
   self.assertEqual(chat_bridge.crypto_status(value),'CRYPTO_FAILED')
 def test_history_is_bounded_and_contains_no_request_data(self):
  import json,time
  with tempfile.TemporaryDirectory() as t:
   b=chat_bridge.ChatBridge.__new__(chat_bridge.ChatBridge);b.data=Path(t)
   for _ in range(25):b.vault_diagnostic('OK',time.monotonic(),0)
   p=Path(t)/'vault-diagnostics.json';history=json.loads(p.read_text())
   self.assertEqual(len(history),20)
   self.assertEqual(set(history[-1]),{'time','status','elapsed_ms','exit_code'})
   self.assertEqual(p.stat().st_mode & 0o777,0o600)
