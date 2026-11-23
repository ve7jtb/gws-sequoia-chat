"""No-token regression tests for the narrowed native digest-signing authority."""
import base64,hashlib,json,sys,tempfile,time,unittest
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
  self.own=self.b.data/'own';self.peer=self.b.data/'peer'
  self.own.write_bytes(b'configured public sender');self.peer.write_bytes(b'trusted public recipient')
  self.b.cfg={'cert':str(self.own),'chat_email':'sender@example.invalid'}
  self.contact={'id':'contact','email':'recipient@example.invalid','fingerprint':'B'*64}
  self.b.peer=Mock(return_value=(self.contact,self.peer));self.b.chat=Mock()
  self.b.chat.write_new.side_effect=lambda p,data:p.write_bytes(data)
  self.b.crypto=Mock(return_value={'signature':'test response'})
 def prepare(self,service='Chat'):
  with patch('signing.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'signingFingerprint':'C'*64}).encode())):
   return signing.prepare(self.b,{'subject':'Synthetic test'},self.contact,self.peer,service,'spaces/test')
 def request(self,prepared):
  return {'op':'chat-sign-digest','review':prepared['review'],'requestId':'A'*64,'hashAlgorithm':10,'signingFingerprint':'C'*64,'digest':base64.b64encode(bytes(64)).decode()}
 def test_prepare_and_sign_accept_no_body_pin_slot_or_key_override(self):
  for op in ('chat-prepare','chat-mail-prepare','chat-browser-prepare'):
   request={'op':op,'contact':'id','subject':'Subject'}
   if op=='chat-prepare':request['space']='spaces/test'
   if op=='chat-browser-prepare':request.update(space='spaces/test',service='Chat')
   self.assertEqual(validate(request),op)
   with self.assertRaises(ValueError):validate({**request,'mime':'body'})
  p=self.prepare();r=self.request(p);self.assertEqual(validate(r),'chat-sign-digest')
  for name in ('mime','payload','pin','slot','serial','senderCertificate','config'):
   with self.assertRaises(ValueError):validate({**r,name:'substitute'})
  for alg in (True,9,'10'):
   with self.assertRaises(ValueError):validate({**r,'hashAlgorithm':alg})
  self.assertNotIn('signed',p);self.assertEqual(p['senderEmail'],'sender@example.invalid')
  self.assertEqual(p['subject'],'Synthetic test');self.b.crypto.assert_not_called()
 def test_success_calls_only_one_digest_and_uses_completion_only_ticket(self):
  p=self.prepare();r=self.request(p)
  self.assertEqual(signing.sign(self.b,r),{'signature':'test response'})
  self.b.crypto.assert_called_once_with('sign-digest',self.peer,bytes(64),service='Chat',signing=r)
  ticket=self.b.data/('encryption-'+p['review']+'.json')
  meta=json.loads(ticket.read_text());self.assertEqual(meta['stage'],'signed')
  self.assertNotIn('digest',meta);self.assertNotIn('requestId',meta)
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  self.assertEqual(self.b.crypto.call_count,1)
 def test_private_failure_cannot_be_retried_or_completed(self):
  p=self.prepare();r=self.request(p);self.b.crypto.side_effect=ValueError('Cancelled or failed')
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  with self.assertRaises(FileNotFoundError):signing.sign(self.b,r)
  with self.assertRaises(FileNotFoundError):signing.ticket(self.b,p['review'],'signed')
  self.assertEqual(self.b.crypto.call_count,1)
 def test_invalid_key_hash_and_digest_rejected_before_prompt(self):
  p=self.prepare();r=self.request(p)
  for key,value in [('digest','YQ=='),('signingFingerprint','D'*64),('requestId','a'*64),('hashAlgorithm',9)]:
   with self.assertRaises(ValueError):signing.sign(self.b,{**r,key:value})
  self.b.crypto.assert_not_called()
 def test_expiry_or_sender_recipient_change_prevents_signing(self):
  p=self.prepare();r=self.request(p);path=self.b.data/('encryption-'+p['review']+'.json')
  meta=json.loads(path.read_text());meta['created']=time.time()-601;path.write_text(json.dumps(meta))
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  for target in (self.own,self.peer):
   p=self.prepare();r=self.request(p);original=target.read_bytes();target.write_bytes(b'new cert')
   with self.assertRaises(ValueError):signing.sign(self.b,r)
   target.write_bytes(original)
  self.b.crypto.assert_not_called()
 def test_identity_change_during_pin_dialog_cannot_complete(self):
  p=self.prepare();r=self.request(p)
  self.b.crypto.side_effect=lambda *a,**k:self.own.write_bytes(b'new cert')
  with self.assertRaises(ValueError):signing.sign(self.b,r)
  with self.assertRaises(FileNotFoundError):signing.ticket(self.b,p['review'],'signed')
 def test_unsigned_ticket_cannot_stage_ciphertext(self):
  p=self.prepare()
  with self.assertRaises(ValueError):self.b.complete_browser_encryption({'review':p['review'],'cipher':'YQ=='})
 def test_offline_prepare_never_receives_mime_or_touches_network(self):
  import direct_transport
  self.b.chat.space_name.side_effect=lambda x:x
  self.b.prepare_browser_signature=Mock(return_value={'review':'prepared'})
  r={'op':'chat-browser-prepare','service':'Chat','space':'spaces/test','contact':'contact','subject':'Test'}
  self.assertEqual(direct_transport.action(self.b,r),{'review':'prepared'})
  self.b.prepare_browser_signature.assert_called_once_with(r,self.contact,self.peer,'Chat','spaces/test')

if __name__=='__main__':unittest.main()
