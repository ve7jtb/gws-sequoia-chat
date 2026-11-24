"""Public identity review never grants trust or controls private operations.

Only synthetic certificates and mocked subprocesses are used. Live keys, PINs,
card writes, saved contact trust and native identity configuration are untouched.
"""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import identities
from chat_bridge import ChatBridge,validate
from host import operation_error

ENCODED=base64.b64encode(b'PQMZIP01synthetic').decode()

class IdentityBoundary(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.cert=self.root/'public.asc';self.cert.write_bytes(b'public')
  self.b=ChatBridge.__new__(ChatBridge);self.b.root=self.b.data=self.root
  self.b.cfg={'cert':str(self.cert),'serial':'123456','app':'/fixed/app'}
  self.b.emit=Mock();self.b.crypto=Mock()
 def response(self,source='yubikey'):
  return {'source':source,'serial':'123456','bundleSignatureVerified':True,'liveKeysMatched':True}
 def test_closed_schema_never_accepts_identity_authority_from_browser(self):
  for op in ('chat-identity-current','chat-identity-restore','chat-identity-import'):
   request={'op':op,**({'bundle':ENCODED} if op.endswith('import') else {})}
   self.assertEqual(validate(request),op)
   for name in ('serial','slot','path','helper','objectHelper','pin','trust','config','certificate'):
    with self.assertRaises(ValueError):validate({**request,name:'not allowed'})
 def test_import_rejects_secret_or_uncompressed_input_before_subprocess(self):
  for raw in (b'',b'PQMAILS1old',b'-----BEGIN PGP PRIVATE KEY BLOCK-----',b'PQMZIP01'+b'x'*65536):
   with self.subTest(size=len(raw)),patch('identities.subprocess.run') as run:
    with self.assertRaises(ValueError):self.b.action({'op':'chat-identity-import','bundle':base64.b64encode(raw).decode()})
    run.assert_not_called();self.b.crypto.assert_not_called()
  with self.assertRaises(ValueError):identities.bundle_bytes(ENCODED+'\n')
 def test_restore_and_import_use_only_fixed_helper_and_serial(self):
  before=dict(self.b.cfg)
  for op,source in [('chat-identity-restore','yubikey'),('chat-identity-import','file')]:
   request={'op':op,**({'bundle':ENCODED} if source=='file' else {})}
   with patch('identities.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.response(source)).encode())) as run:
    self.assertEqual(self.b.action(request),self.response(source))
    args=run.call_args;payload=json.loads(args.kwargs['input'])
    self.assertEqual(args.args[0],[str(self.root/'runtime/sequoia-iwa-crypto')])
    self.assertEqual(payload['objectHelper'],'/fixed/app/native/bin/hybrid-mail-provision')
    self.assertEqual(payload['serial'],'123456')
    self.assertEqual(set(payload),{'op','objectHelper','serial'}|({'bundle'} if source=='file' else set()))
    self.assertIs(args.kwargs['stderr'],subprocess.DEVNULL)
   self.b.crypto.assert_not_called();self.assertEqual(self.b.cfg,before)
 def test_missing_live_proof_wrong_device_or_source_fail_closed(self):
  for change in ({'liveKeysMatched':False},{'bundleSignatureVerified':False},{'serial':'789'},{'source':'file'}):
   with patch('identities.run_public',return_value={**self.response(),**change}):
    with self.assertRaises(ValueError):identities.preview(self.b)
 def test_current_configuration_does_not_claim_live_presence(self):
  result={'certificate':'cHVibGlj','fingerprint':'A'*64,'slots':[]}
  with patch('identities.run_public',return_value=result) as run:
   self.assertEqual(identities.current(self.b),{**result,'serial':'123456'})
   self.assertEqual(run.call_args.args[1],{'op':'identity-current','certificate':'cHVibGlj'})
   self.assertNotIn('liveKeysMatched',result)
  self.b.emit.assert_not_called();self.b.crypto.assert_not_called()
 def test_oversized_or_failed_result_is_never_exposed(self):
  for result in (SimpleNamespace(returncode=1,stdout=b'secret'),SimpleNamespace(returncode=0,stdout=b'x'*(identities.MAX_REPLY+1))):
   with patch('identities.subprocess.run',return_value=result):
    with self.assertRaisesRegex(ValueError,'Public identity review failed'):identities.run_public(self.b,{})
  text=operation_error('chat-identity-import',ValueError('sensitive native output'))
  self.assertNotIn('sensitive native output',text);self.assertIn('No PIN',text)

if __name__=='__main__':unittest.main()
