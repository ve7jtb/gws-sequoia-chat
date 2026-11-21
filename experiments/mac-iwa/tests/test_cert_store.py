import sys,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import cert_store,chat_bridge
class CertificateStoreTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.data=Path(self.tmp.name)
  self.fp='A'*40;self.other='B'*64
  for name in (self.fp+'.pgp','mail-cert-'+self.fp+'.pgp',self.other+'.pgp'):(self.data/name).write_bytes(b'public')
  for name,email,fp in [('contact-one','a@example.invalid',self.fp),('mail-trust-two','a@example.invalid',self.fp),('mail-trust-three','b@example.invalid',self.fp),('contact-other','c@example.invalid',self.other)]:
   (self.data/(name+'.json')).write_text(json.dumps({'fingerprint':fp,'email':email}))
  self.b=SimpleNamespace(data=self.data,contacts=lambda:[])
 def operate(self,op,**fields):
  with patch.object(cert_store,'inventory',return_value=[]):return cert_store.action(self.b,{'op':op,**fields})
 def test_untrust_preserves_keys_and_other_email(self):
  self.operate('chat-cert-untrust',fingerprint=self.fp,email='a@example.invalid',confirmed=True)
  self.assertTrue((self.data/(self.fp+'.pgp')).exists());self.assertTrue((self.data/('mail-cert-'+self.fp+'.pgp')).exists())
  self.assertEqual(sorted(r['email'] for _,r in cert_store.bindings(self.data)),['b@example.invalid','c@example.invalid'])
 def test_delete_removes_both_copies_and_bindings_only_for_selected_key(self):
  self.operate('chat-cert-delete',fingerprint=self.fp,confirmed=True)
  self.assertEqual(set(cert_store.certificates(self.data)),{self.other})
  self.assertEqual([r['email'] for _,r in cert_store.bindings(self.data)],['c@example.invalid'])
 def test_confirmation_and_exact_fingerprint_required(self):
  for fields in ({'fingerprint':self.fp,'confirmed':False},{'fingerprint':'../x','confirmed':True}):
   with self.assertRaises(ValueError):self.operate('chat-cert-delete',**fields)
  self.assertEqual(len(list(cert_store.bindings(self.data))),4)
 def test_closed_schema(self):
  with self.assertRaises(ValueError):chat_bridge.validate({'op':'chat-cert-delete','fingerprint':self.fp,'confirmed':True,'path':'/tmp/arbitrary'})
  with self.assertRaises(ValueError):chat_bridge.validate({'op':'chat-cert-untrust','fingerprint':self.fp,'email':'a@example.invalid','confirmed':False})
