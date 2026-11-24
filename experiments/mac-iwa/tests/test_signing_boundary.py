"""Profile-specific signing grants: old default signing authority is removed.

SelectedIdentity tests cover expiry, cancellation, substitution and one-use
consumption. These regressions cover the new narrow protocol extensions without
opening a device, prompting for a PIN, or manufacturing card certificates.
"""
import base64,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import signing,identities
from chat_bridge import validate,crypto_prompt,ChatBridge
from test_selected_identity import SELECT,CONTEXT,PUBLIC,COMPONENTS

class SigningBoundary(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.b=ChatBridge.__new__(ChatBridge);self.b.root=self.b.data=Path(self.tmp.name)
  self.b.crypto=Mock(return_value={});self.b.emit=Mock()
 def grant(self,context):
  with patch('identities.selected',return_value=(context,PUBLIC)),patch('signing.backend_hash',return_value='code'):
   p=signing.prepare(self.b,SELECT)
  return {'op':'chat-sign-digest','review':p['review'],'requestId':'A'*64,'hashAlgorithm':10,'signingFingerprint':PUBLIC['signingFingerprint'],'digest':base64.b64encode(bytes(64)).decode()}
 def test_retired_default_signing_route_cannot_reappear(self):
  with self.assertRaises(ValueError):validate({'op':'chat-signing-material'})
  with self.assertRaises(ValueError):signing.prepare(self.b)
  self.b.crypto.assert_not_called()
 def test_inline_second_signature_is_only_for_verified_v5_profile(self):
  for profile,inline,success in [('level3',False,True),('level3',True,False),('level3-v5-hybrid',False,False),('level3-v5-hybrid',True,True)]:
   context={**CONTEXT,'profile':profile};request=self.grant(context)
   if inline:request['inlineDigest']=base64.b64encode(bytes([4])*64).decode()
   with patch('signing.backend_hash',return_value='code'),patch('identities.revalidate_context',return_value=context):
    if success:signing.sign(self.b,request)
    else:
     with self.assertRaises(ValueError):signing.sign(self.b,request)
 def test_public_cache_cannot_override_a_certificate_hash(self):
  identities.selection({**SELECT,'certificate':CONTEXT['certificate']})
  with self.assertRaises(ValueError):identities.selection({**SELECT,'certificate':'YQ=='})
  identities.selection({**SELECT,'fingerprint':'A'*40})
 def test_grant_rejects_arbitrary_role_storage_algorithm_or_slot(self):
  for field,value in [('role','certify-anything'),('storage','file'),('algorithm','RSA'),('slot','81')]:
   rows=[dict(r) for r in COMPONENTS];rows[0][field]=value
   with self.assertRaises(ValueError):identities.operation_context({**CONTEXT,'components':rows})
 def test_prompt_names_actual_algorithms_from_native_mapping(self):
  p384={**CONTEXT,'components':[{'role':'signing-classical','algorithm':'ECDSA-P384'}]}
  self.assertEqual(crypto_prompt('sign-digest','Message',p384),'Sign message — ECDSA-P384')
  self.assertEqual(crypto_prompt('decapsulate-components','Vault'),'Unlock IWA credential vault — ML-KEM-768 + X25519')

if __name__=='__main__':unittest.main()
