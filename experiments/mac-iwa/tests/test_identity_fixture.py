"""Run the installed-style public restore protocol against a synthetic card.

The helper offers only serial/key/get and contains published public test data.
Unknown operations fail: accidentally adding a PIN or write would break tests.
Set IWA_CRYPTO_TEST_BIN to the built native helper to enable these regressions.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

FIXTURE=Path(__file__).parents[1]/'crypto/tests/data/restore-level3.json'
# This fixture transport is intentionally tiny and independent of Rust framing
# code. Its public bank is assembled in Python from the signed BC test vector.
HELPER='''#!/usr/bin/python3
import base64,hashlib,json,sys
v=json.load(open({fixture}))
b=base64.b64decode(v['hybrid']);generation=17
objects={{0x5f5000:b'PQMIDX01'+generation.to_bytes(8,'big')+len(b).to_bytes(4,'big')+hashlib.sha256(b).digest()}}
for i in range((len(b)+2047)//2048):objects[0x5f5001+i]=b'PQMCHK01'+generation.to_bytes(8,'big')+i.to_bytes(4,'big')+b[i*2048:(i+1)*2048]
assert sys.argv[1:]==['objects','123456']
for line in sys.stdin:
 r=json.loads(line);op=r['op']
 if op=='serial':
  assert set(r)=={{'op'}};value=123456
 elif op=='key':
  assert set(r)=={{'op','slot'}};value=v['keys'].get(r['slot'])
 elif op=='get':
  assert set(r)=={{'op','tag'}};raw=objects.get(r['tag']);value=None if raw is None else base64.b64encode(raw).decode()
 else:raise AssertionError('A public restore attempted a forbidden operation')
 print(json.dumps({{'value':value}}),flush=True)
'''


def fixture_preview(binary,source='yubikey'):
 """Exercise the pipe entry point and return public-only JSON for UI tests."""
 with tempfile.TemporaryDirectory() as tmp:
  helper=Path(tmp)/'public-object-helper'
  helper.write_text(HELPER.format(fixture=repr(str(FIXTURE.resolve()))));helper.chmod(0o700)
  request={'op':'identity-restore','objectHelper':str(helper),'serial':'123456'}
  if source=='file':request['bundle']=json.loads(FIXTURE.read_text())['hybrid']
  result=subprocess.run([str(binary)],input=json.dumps(request).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
  return json.loads(result.stdout)


@unittest.skipUnless(os.environ.get('IWA_CRYPTO_TEST_BIN'),'Set IWA_CRYPTO_TEST_BIN to the new native helper')
class IdentityFixture(unittest.TestCase):
 def test_on_key_and_file_restore_have_identical_verified_material(self):
  card=fixture_preview(os.environ['IWA_CRYPTO_TEST_BIN'])
  file=fixture_preview(os.environ['IWA_CRYPTO_TEST_BIN'],'file')
  self.assertEqual(card['generation'],17);self.assertEqual(file['generation'],0)
  self.assertEqual(card['source'],'yubikey');self.assertEqual(file['source'],'file')
  for name in ('serial','bundleHash','certificates','slots','bundleSignatureVerified','liveKeysMatched'):
   self.assertEqual(card[name],file[name],name)
  self.assertEqual(len(card['certificates']),3);self.assertEqual(len(card['slots']),10)
  raw=base64.b64decode(json.loads(FIXTURE.read_text())['hybrid'])
  self.assertEqual(card['bundleHash'],hashlib.sha256(raw).hexdigest())
  self.assertTrue(card['bundleSignatureVerified']);self.assertTrue(card['liveKeysMatched'])
  self.assertNotIn('trust',card)
 def test_selected_identity_binds_canonical_full_certificate_and_current_keys(self):
  # Exercise the actual Rust public parser on the authenticated BC fixture,
  # including a second pass to establish stable native/WASM hash semantics.
  card=fixture_preview(os.environ['IWA_CRYPTO_TEST_BIN'])
  cert=next(c for c in card['certificates'] if c['label']=='OpenPGP v6')['certificate']
  def inspect(encoded):
   result=subprocess.run([os.environ['IWA_CRYPTO_TEST_BIN']],input=json.dumps({'op':'identity-canonical','certificate':encoded}).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=30)
   return json.loads(result.stdout)
  info=inspect(cert);self.assertEqual(info,inspect(info['certificate']))
  self.assertEqual(info['certificateHash'],hashlib.sha256(base64.b64decode(info['certificate'])).hexdigest())
  for field in ('fingerprint','signingFingerprint','recipientKey'):self.assertRegex(info[field],r'^[A-F0-9]{64}$')
  self.assertTrue(info['emails']);self.assertNotEqual(info['fingerprint'],info['signingFingerprint'])
 def test_configured_identity_display_uses_public_parser_only(self):
  card=fixture_preview(os.environ['IWA_CRYPTO_TEST_BIN'])
  certificate=card['certificates'][0]['certificate']
  result=subprocess.run([os.environ['IWA_CRYPTO_TEST_BIN']],input=json.dumps({'op':'identity-current','certificate':certificate}).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=30)
  value=json.loads(result.stdout)
  self.assertEqual(value['certificate'],certificate)
  self.assertEqual(len(value['slots']),4)
  self.assertNotIn('liveKeysMatched',value)

if __name__=='__main__':unittest.main()
