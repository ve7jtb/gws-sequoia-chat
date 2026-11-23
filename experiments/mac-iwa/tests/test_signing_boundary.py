"""No-token tests for the fixed signing authority after IWA trust migration."""
import base64,json,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import signing
from chat_bridge import ChatBridge,validate

class SigningBoundary(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.b=ChatBridge.__new__(ChatBridge);self.b.root=self.b.data=Path(self.tmp.name)
  self.own=self.b.data/'own';self.own.write_bytes(b'configured public sender')
  self.b.cfg={'cert':str(self.own),'chat_email':'sender@example.invalid','serial':'123','app':'fixed-app'}
  self.b.chat=Mock();self.b.chat.write_new.side_effect=lambda p,data:p.write_bytes(data)
  self.b.crypto=Mock(return_value={'signature':'test response'})
 def prepare(self):
  with patch('signing.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'signingFingerprint':'C'*64}).encode())):
   return signing.prepare(self.b)
 def request(self,p):
  return {'op':'chat-sign-digest','review':p['review'],'requestId':'A'*64,'hashAlgorithm':10,'signingFingerprint':'C'*64,'digest':base64.b64encode(bytes(64)).decode()}
 def test_prepare_and_sign_have_no_recipient_pin_or_slot_authority(self):
  self.assertEqual(validate({'op':'chat-signing-material'}),'chat-signing-material')
  for name in ('mime','payload','pin','slot','serial','senderCertificate','recipient','contact','subject','service','config'):
   with self.assertRaises(ValueError):validate({'op':'chat-signing-material',name:'substitute'})
  p=self.prepare();r=self.request(p);self.assertEqual(validate(r),'chat-sign-digest')
  for name in ('mime','payload','pin','slot','serial','senderCertificate','config','contact'):
   with self.assertRaises(ValueError):validate({**r,name:'substitute'})
  for alg in (True,9,'10'):
   with self.assertRaises(ValueError):validate({**r,'hashAlgorithm':alg})
  self.assertEqual(set(p),{'review','senderCertificate','senderEmail','signingFingerprint'})
  self.b.crypto.assert_not_called()
 def test_success_calls_one_digest_and_leaves_no_completion_ticket(self):
  p=self.prepare();r=self.request(p)
  meta=json.loads((self.b.data/('signing-'+p['review']+'.json')).read_text())
  self.assertEqual(set(meta),{'created','authorityHash','signingFingerprint'})
  self.assertEqual(signing.sign(self.b,r),{'signature':'test response'})
  self.b.crypto.assert_called_once_with('sign-digest',self.own,bytes(64),service='Message',signing=r)
  self.assertFalse(list(self.b.data.glob('signing-*.json')))
  self.assertFalse(list(self.b.data.glob('encryption-*.json')))
  with self.assertRaises(FileNotFoundError):signing.sign(self.b,r)
  self.assertEqual(self.b.crypto.call_count,1)
 def test_private_failure_cannot_be_retried(self):
  p=self.prepare();r=self.request(p);self.b.crypto.side_effect=ValueError('Cancelled or failed')
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  with self.assertRaises(FileNotFoundError):signing.sign(self.b,r)
  self.assertEqual(self.b.crypto.call_count,1)
 def test_invalid_key_hash_digest_rejected_before_prompt(self):
  p=self.prepare();r=self.request(p)
  for key,value in [('digest','YQ=='),('signingFingerprint','D'*64),('requestId','a'*64),('hashAlgorithm',9)]:
   with self.assertRaises(ValueError):signing.sign(self.b,{**r,key:value})
  self.b.crypto.assert_not_called()
 def test_expiry_and_native_identity_changes_prevent_signing(self):
  p=self.prepare();r=self.request(p);path=self.b.data/('signing-'+p['review']+'.json')
  meta=json.loads(path.read_text());meta['created']=time.time()-601;path.write_text(json.dumps(meta))
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  p=self.prepare();r=self.request(p);original=self.own.read_bytes();self.own.write_bytes(b'new cert')
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  self.own.write_bytes(original)
  for key in ('serial','app','chat_email'):
   p=self.prepare();r=self.request(p);original=self.b.cfg[key];self.b.cfg[key]='changed'
   with self.assertRaises(ValueError):signing.sign(self.b,r)
   self.b.cfg[key]=original
  self.b.crypto.assert_not_called()
 def test_identity_change_during_pin_cannot_return_signature(self):
  p=self.prepare();r=self.request(p)
  self.b.crypto.side_effect=lambda *a,**k:self.own.write_bytes(b'new cert')
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  with self.assertRaises(FileNotFoundError):signing.ticket(self.b,p['review'])
 def test_signing_label_names_algorithm_without_untrusted_recipient(self):
  from chat_bridge import crypto_prompt
  self.assertEqual(crypto_prompt('sign-digest','Message'),'Sign message — ML-DSA-65 + Ed25519')
  with self.assertRaises(ValueError):crypto_prompt('open','Message')

if __name__=='__main__':unittest.main()
