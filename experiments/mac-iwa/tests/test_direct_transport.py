"""Read-only legacy export; migration never grants trust or changes source files."""
import base64,hashlib,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
from certificate_migration import snapshot,validate_public

class MigrationSnapshot(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  # Public parser correctness is covered separately; these use bounded synthetic bytes.
  self.validation=patch('certificate_migration.validate_public');self.validation.start();self.addCleanup(self.validation.stop)
  self.data=Path(self.tmp.name);self.b=SimpleNamespace(data=self.data,root=self.data)
  self.fp='A'*64;self.raw=b'synthetic public certificate'
  (self.data/(self.fp+'.pgp')).write_bytes(self.raw)
  (self.data/'contact-example.json').write_text(json.dumps({'id':'old-id','email':'peer@example.invalid','fingerprint':self.fp}))
 def hashes(self):return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.data.iterdir() if p.is_file()}
 def test_export_only_public_data_with_stable_review_digest(self):
  (self.data/'credentials.json').write_text('{"refresh_token":"NEVER EXPORT"}')
  (self.data/'other-file').write_bytes(b'private')
  before=self.hashes();r=snapshot(self.b)
  self.assertEqual(set(r),{'version','certificates','saved','bindings','sourceDigest'})
  self.assertEqual(r['certificates'],[base64.b64encode(self.raw).decode()])
  self.assertEqual(r['bindings'],[{'email':'peer@example.invalid','fingerprint':self.fp}])
  self.assertEqual(r,snapshot(self.b));self.assertEqual(before,self.hashes())
  self.assertNotIn('NEVER EXPORT',json.dumps(r))
 def test_matching_duplicates_deduplicate_but_conflicting_copies_stop(self):
  p=self.data/('mail-cert-'+self.fp+'.pgp');p.write_bytes(self.raw)
  self.assertEqual(len(snapshot(self.b)['certificates']),1)
  p.write_bytes(b'different certificate update')
  with self.assertRaises(ValueError):snapshot(self.b)
 def test_dangling_trust_and_control_characters_rejected(self):
  p=self.data/'mail-trust-other.json'
  for record in ({'email':'other@example.invalid','fingerprint':'B'*64},{'email':'bad\n@example.invalid','fingerprint':self.fp}):
   p.write_text(json.dumps(record))
   with self.assertRaises(ValueError):snapshot(self.b)
 def test_symlinks_and_oversize_records_do_not_escape_public_store(self):
  p=self.data/(self.fp+'.pgp');p.unlink();p.symlink_to(self.data/'credentials.json')
  (self.data/'credentials.json').write_text('private')
  with self.assertRaises(ValueError):snapshot(self.b)
  p.unlink();p.write_bytes(bytes(200001))
  with self.assertRaises(ValueError):snapshot(self.b)
 def test_certificate_count_and_trust_count_limits(self):
  for n in range(25):(self.data/(format(n,'064X')+'.pgp')).write_bytes(b'public')
  with self.assertRaises(ValueError):snapshot(self.b)
 def test_digest_covers_bindings_and_public_bytes(self):
  one=snapshot(self.b)['sourceDigest']
  (self.data/'contact-example.json').write_text(json.dumps({'email':'different@example.invalid','fingerprint':self.fp}))
  self.assertNotEqual(one,snapshot(self.b)['sourceDigest'])

class NativePublicCheck(unittest.TestCase):
 def test_native_parser_must_confirm_public_fingerprint_before_export(self):
  b=SimpleNamespace(root=Path('/fixed-test-root'))
  for response in (SimpleNamespace(returncode=1,stdout=b''),SimpleNamespace(returncode=0,stdout=b'{"fingerprint":"wrong"}')):
   with patch('certificate_migration.subprocess.run',return_value=response):
    with self.assertRaises(ValueError):validate_public(b,'A'*64,b'not-public')
  with patch('certificate_migration.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'fingerprint':'A'*64}).encode())) as run:
   validate_public(b,'A'*64,b'public')
   self.assertEqual(json.loads(run.call_args.kwargs['input'])['op'],'inspect-public')
   self.assertEqual(run.call_args.args[0],['/fixed-test-root/runtime/sequoia-iwa-crypto'])

if __name__=='__main__':unittest.main()
