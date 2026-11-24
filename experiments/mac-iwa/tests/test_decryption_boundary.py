"""No-token regressions for one-use component decapsulation authority.

These tests exercise the actual Python gates and pipe protocol with synthetic
keys/secrets. They never launch a PIN UI, contact hardware or persist a secret.
"""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import decryption
from chat_bridge import ChatBridge,crypto_prompt,validate


def encoded(value,size):return base64.b64encode(bytes([value])*size).decode()


class DecryptionBoundary(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.b=ChatBridge.__new__(ChatBridge);self.b.root=self.b.data=Path(self.tmp.name)
  self.own=self.b.data/'own';self.own.write_bytes(b'configured public recipient')
  self.b.cfg={'cert':str(self.own),'chat_email':'owner@example.invalid','serial':'123','app':'fixed-app','ykman':'fixed-ykman'}
  self.b.chat=Mock();self.b.chat.write_new.side_effect=lambda p,data:p.write_bytes(data)
  self.b.crypto=Mock(return_value={'components':'synthetic complete response'})
 def prepare(self,service='Gmail'):
  with patch('decryption.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'recipientKey':'C'*64}).encode())):
   return decryption.prepare(self.b,service)
 def request(self,p,service='Gmail'):
  return {'op':'chat-decapsulate-components','review':p['review'],'service':service,
    'requestId':'A'*64,'cipherHash':'b'*64,'recipientKey':'C'*64,
    'mlkemCiphertext':encoded(3,1088),'x25519Ephemeral':encoded(9,32)}
 def test_schema_exposes_only_fixed_component_inputs(self):
  self.assertEqual(validate({'op':'chat-decryption-material','service':'Gmail'}),'chat-decryption-material')
  for op in ('chat-decap','chat-vault-decapsulate'):
   with self.assertRaises(ValueError):validate({'op':op,'payload':'YQ==','service':'Gmail'})
  p=self.prepare();r=self.request(p)
  self.assertEqual(validate(r),'chat-decapsulate-components')
  for name in ('payload','cipher','esk','sessionKey','algorithm','pin','serial','slot','module','path','config','recipientCertificate'):
   with self.assertRaises(ValueError):validate({**r,name:'substitute'})
  for service in ('unknown','',None):
   with self.assertRaises(ValueError):validate({'op':'chat-decryption-material','service':service})
  self.b.crypto.assert_not_called()
 def test_prepare_stores_public_authority_only_and_no_hardware_call(self):
  p=self.prepare();self.assertEqual(set(p),{'review','recipientCertificate','recipientKey'})
  m=json.loads((self.b.data/('decryption-'+p['review']+'.json')).read_text())
  self.assertEqual(set(m),{'created','authorityHash','recipientKey','service'})
  self.b.crypto.assert_not_called()
 def test_success_and_cancel_each_consume_grant_before_private_call(self):
  for failure in (False,True):
   p=self.prepare();r=self.request(p);path=self.b.data/('decryption-'+p['review']+'.json')
   def private(*args,**kwargs):
    self.assertFalse(path.exists(),'Grant must be consumed before the PIN dialog')
    if failure:raise ValueError('Cancelled')
    return {'components':'synthetic complete response'}
   self.b.crypto.reset_mock();self.b.crypto.side_effect=private
   if failure:
    with self.assertRaises(ValueError):self.b.action(r)
   else:self.assertEqual(self.b.action(r),{'components':'synthetic complete response'})
   self.b.crypto.assert_called_once_with('decapsulate-components',self.own,b'',service='Gmail',components=r)
   with self.assertRaises(FileNotFoundError):self.b.action(r)
   self.assertEqual(self.b.crypto.call_count,1)
 def test_invalid_binding_or_component_is_rejected_before_pin(self):
  p=self.prepare();r=self.request(p)
  for name,value in [('review','../bad'),('requestId','a'*64),('cipherHash','A'*64),
      ('recipientKey','D'*64),('service','Vault'),('mlkemCiphertext',encoded(3,1087)),
      ('x25519Ephemeral',encoded(0,32)),('x25519Ephemeral',encoded(9,31))]:
   with self.subTest(field=name),self.assertRaises(ValueError):self.b.action({**r,name:value})
  self.b.crypto.assert_not_called()
 def test_noncanonical_base64_rejected_before_pin(self):
  p=self.prepare();r=self.request(p)
  # Nonzero unused pad bits can decode to the same bytes; reject instead of
  # allowing operation binding to depend on two textual representations.
  changed=r['x25519Ephemeral'][:-2]+'l='
  with self.assertRaises(ValueError):self.b.action({**r,'x25519Ephemeral':changed})
  self.b.crypto.assert_not_called()
 def test_expiry_and_changed_fixed_authority_rejected_before_pin(self):
  p=self.prepare();r=self.request(p);path=self.b.data/('decryption-'+p['review']+'.json')
  m=json.loads(path.read_text());m['created']=time.time()-601;path.write_text(json.dumps(m))
  with self.assertRaises(ValueError):self.b.action(r)
  for field in ('serial','app','chat_email'):
   p=self.prepare();r=self.request(p);old=self.b.cfg[field];self.b.cfg[field]='changed'
   with self.assertRaises(ValueError):self.b.action(r)
   self.b.cfg[field]=old
  p=self.prepare();r=self.request(p);self.own.write_bytes(b'changed cert')
  with self.assertRaises(ValueError):self.b.action(r)
  self.b.crypto.assert_not_called()
 def test_identity_changed_during_private_operation_discards_result(self):
  p=self.prepare();r=self.request(p)
  self.b.crypto.side_effect=lambda *a,**k:self.own.write_bytes(b'changed cert')
  with self.assertRaises(ValueError):self.b.action(r)
  with self.assertRaises(FileNotFoundError):self.b.action(r)
  self.assertEqual(self.b.crypto.call_count,1)
 def test_prompt_uses_fixed_service_and_algorithms(self):
  self.assertEqual(crypto_prompt('decapsulate-components','Vault'),'Unlock IWA credential vault — ML-KEM-768 + X25519')
  self.assertEqual(crypto_prompt('decapsulate-components','Gmail'),'Unlock decryption key for Gmail email — ML-KEM-768 + X25519')
  with self.assertRaises(ValueError):crypto_prompt('decapsulate-components','arbitrary')
 def actual_pipe(self,reply,request=None):
  # Exercise ChatBridge.crypto itself using its real strict response checks.
  # Only subprocess.run/check_output are mocked, so malformed native results
  # cannot accidentally acquire a permissive fake response validator.
  p=self.prepare();r=self.request(p) if request is None else request
  result={k:r[k] for k in decryption.BINDINGS}
  result.update({'mlkemSecret':encoded(7,32),'x25519Secret':encoded(8,32)})
  if reply is not None:result.update(reply)
  self.b.emit=Mock()
  with patch('chat_bridge.subprocess.check_output',return_value=b'123\n'),patch('chat_bridge.subprocess.run',side_effect=[
      subprocess.CompletedProcess([],0,b'123456'),subprocess.CompletedProcess([],0,json.dumps(result).encode(),b'')]) as run:
   value=ChatBridge.crypto(self.b,'decapsulate-components',self.own,b'',service='Gmail',components=r)
   wire=json.loads(run.call_args_list[1].kwargs['input'])
   self.assertEqual(set(wire),set(decryption.BINDINGS)|{'op','pin','own','config'})
   self.assertEqual(wire['op'],'decapsulate-components')
   self.assertNotIn('cipher',wire);self.assertNotIn('payload',wire);self.assertNotIn('esk',wire)
   return value
 def test_native_pipe_passes_only_components_and_returns_no_session_key(self):
  r=self.actual_pipe(None)
  self.assertEqual(set(r),set(decryption.BINDINGS)|{'mlkemSecret','x25519Secret'})
 def test_bad_or_partial_native_results_never_escape(self):
  for reply in ({'requestId':'B'*64},{'cipherHash':'c'*64},{'recipientKey':'D'*64},
      {'x25519Ephemeral':encoded(1,32)},{'mlkemSecret':encoded(7,31)},
      {'x25519Secret':encoded(0,32)},{'sessionKey':'unexpected'}):
   with self.subTest(fields=list(reply)),self.assertRaises(ValueError):self.actual_pipe(reply)


if __name__=='__main__':unittest.main()
