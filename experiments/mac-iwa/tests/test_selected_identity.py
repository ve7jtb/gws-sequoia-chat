"""Selected public identities never become browser-selected private authority.

Mocks stand in for public card reads and PIN operations. No test touches a real
YubiKey, saves a credential, or rewrites an application identity/configuration.
"""
import base64,hashlib,json,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import identities,signing,decryption
from chat_bridge import ChatBridge,validate
import host

RAW=b'canonical synthetic public certificate'
ENC=base64.b64encode(RAW).decode()
SELECT={'serial':'222','bundleHash':'b'*64,'fingerprint':'C'*64,
        'certificateHash':hashlib.sha256(RAW).hexdigest(),'email':'owner@example.invalid'}
COMPONENTS=[{'role':role,'algorithm':alg,'storage':'piv','slot':slot,'publicKey':base64.b64encode(bytes([n])*40).decode()} for n,(role,alg,slot) in enumerate([('signing-pq','ML-DSA-65','9c'),('signing-classical','Ed25519','84'),('decryption-pq','ML-KEM-768','9d'),('decryption-classical','X25519','85')],1)]
CONTEXT={**SELECT,'certificate':ENC,'profile':'level3','components':COMPONENTS}
PUBLIC={'certificate':ENC,'certificateHash':SELECT['certificateHash'],'fingerprint':SELECT['fingerprint'],
        'emails':[SELECT['email']],'signingFingerprint':'D'*64,'recipientKey':'E'*64}
SNAPSHOT={'serial':'222','bundleHash':'b'*64,'source':'yubikey','bundleSignatureVerified':True,
          'liveKeysMatched':True,'certificates':[{'kind':'openpgp','label':'OpenPGP v6','certificate':ENC,'profile':'level3','components':COMPONENTS}]}

class SelectedIdentity(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.b=ChatBridge.__new__(ChatBridge);self.b.root=self.b.data=Path(self.tmp.name)
  self.b.cfg={'serial':'111','cert':'missing-default-cert','chat_email':'default@example.invalid',
              'app':str(self.b.root/'app'),'ykman':'fixed-ykman'}
  self.b.chat=Mock();self.b.chat.write_new.side_effect=lambda p,data:p.write_bytes(data)
  self.b.emit=Mock();self.b.crypto=Mock(return_value={'result':'synthetic'})
 def public_restore(self,choice=None,snapshot=None,public=None,connected=b'222\n'):
  with patch('identities.subprocess.check_output',return_value=connected),patch('identities.preview',return_value=snapshot or SNAPSHOT) as read,patch('identities.run_public',return_value=public or PUBLIC),patch('identities.companion_preview',side_effect=ValueError('No companion')):
   result=identities.selected(self.b,choice or SELECT)
   read.assert_called_once_with(self.b,selected_serial='222',compatibility_certificate=None)
   return result
 def prepare_sign(self):
  with patch('identities.selected',return_value=(CONTEXT,PUBLIC)),patch('signing.backend_hash',return_value='backend'):
   return signing.prepare(self.b,SELECT)
 def prepare_decrypt(self,service='Gmail'):
  with patch('identities.selected',return_value=(CONTEXT,PUBLIC)),patch('decryption.backend_hash',return_value='backend'):
   return decryption.prepare(self.b,service,SELECT)
 def sign_request(self,p):
  return {'op':'chat-sign-digest','review':p['review'],'requestId':'F'*64,
   'signingFingerprint':'D'*64,'hashAlgorithm':10,'digest':base64.b64encode(bytes(64)).decode()}
 def decrypt_request(self,p):
  return {'op':'chat-decapsulate-components','review':p['review'],'service':'Gmail','requestId':'F'*64,
   'cipherHash':'a'*64,'recipientKey':'E'*64,'mlkemCiphertext':base64.b64encode(bytes([3])*1088).decode(),
   'x25519Ephemeral':base64.b64encode(bytes([9])*32).decode()}
 def test_new_routes_are_exact_and_vault_cannot_borrow_message_identity(self):
  self.assertEqual(validate({'op':'chat-selected-signing-material','identity':SELECT}),'chat-selected-signing-material')
  self.assertEqual(validate({'op':'chat-selected-decryption-material','identity':SELECT,'service':'Gmail'}),'chat-selected-decryption-material')
  for extra in ('certificate','slot','app','module','pin','recipientKey','signingFingerprint'):
   with self.assertRaises(ValueError):validate({'op':'chat-selected-signing-material','identity':{**SELECT,extra:'substitute'}})
  with self.assertRaises(ValueError):validate({'op':'chat-selected-decryption-material','identity':SELECT,'service':'Vault'})
  with self.assertRaises(ValueError):decryption.prepare(self.b,'Vault',SELECT)
 def test_selection_rejects_noncanonical_identifiers_and_untrusted_email_syntax(self):
  for name,value in [('serial','../222'),('serial','0222'),('serial','2147483648'),('fingerprint','c'*64),
      ('certificateHash','A'*64),('bundleHash','invalid'),('email','Owner@example.invalid'),('email','x\n@example.invalid')]:
   with self.subTest(name=name),self.assertRaises(ValueError):identities.selection({**SELECT,name:value})
 def test_alternate_serial_is_authenticated_without_modifying_default(self):
  before=dict(self.b.cfg);context,public=self.public_restore()
  self.assertEqual(context,CONTEXT);self.assertEqual(public,PUBLIC);self.assertEqual(self.b.cfg,before)
 def test_backend_hash_binds_code_but_is_independent_of_default_enrollment(self):
  # Real synthetic files distinguish a code substitution from changing the
  # unrelated default vault enrollment. None is executed by this test.
  self.b.cfg['ykman']=str(self.b.root/'fixed-ykman')
  app=Path(self.b.cfg['app'])
  paths=[self.b.root/'runtime/sequoia-iwa-crypto',Path(self.b.cfg['ykman'])]
  paths += [app/name for name in ('native/bin/openssl','native/bin/pqmail-pkcs11-sign',
    'native/bin/pqmail-pkcs11-kem','native/lib/pkcs11.dylib','native/lib/libykcs11.dylib',
    'adapters/pkcs11-mu.py','adapters/pkcs11-kem.py','adapters/ykman-mu.py')]
  for path in paths:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixed synthetic code')
  original=signing.backend_hash(self.b)
  self.b.cfg.update(serial='333',cert='different-default',chat_email='different@example.invalid')
  self.assertEqual(original,signing.backend_hash(self.b))
  paths[0].write_bytes(b'changed synthetic code');self.assertNotEqual(original,signing.backend_hash(self.b))
 def test_wrong_key_rejected_before_public_restore_or_pin(self):
  with patch('identities.subprocess.check_output',return_value=b'111\n'),patch('identities.preview') as read:
   with self.assertRaisesRegex(ValueError,'Connect YubiKey 222'):identities.selected(self.b,SELECT)
   read.assert_not_called();self.b.crypto.assert_not_called()
 def test_bundle_fingerprint_exact_certificate_and_email_each_bind_selection(self):
  for change in ({'bundleHash':'c'*64},{'fingerprint':'D'*64},{'certificateHash':'d'*64},{'email':'other@example.invalid'}):
   with self.subTest(change=change),self.assertRaises(ValueError):self.public_restore(choice={**SELECT,**change})
  self.b.crypto.assert_not_called()
 def test_missing_or_ambiguous_v6_view_is_not_promoted(self):
  for certs in ([],SNAPSHOT['certificates']*2):
   with self.assertRaises(ValueError):self.public_restore(snapshot={**SNAPSHOT,'certificates':certs})
 def test_redeemed_context_checks_canonical_public_packets_again_before_pin(self):
  with patch('identities.run_public',return_value=PUBLIC):self.assertEqual(identities.revalidate_context(self.b,CONTEXT),CONTEXT)
  for changed in ({'emails':[]},{'certificateHash':'a'*64},{'certificate':'YQ=='}):
   with patch('identities.run_public',return_value={**PUBLIC,**changed}),self.assertRaises(ValueError):identities.revalidate_context(self.b,CONTEXT)
  # Bad grant hashes/encodings are rejected even before invoking the public parser.
  with patch('identities.run_public') as parser,self.assertRaises(ValueError):identities.revalidate_context(self.b,{**CONTEXT,'certificate':'YQ=='})
  parser.assert_not_called()
 def test_sign_grant_echoes_selected_identity_and_is_one_use(self):
  p=self.prepare_sign();r=self.sign_request(p);self.assertEqual(p['identity'],SELECT)
  path=self.b.data/('signing-'+p['review']+'.json');record=json.loads(path.read_text())
  self.assertEqual(record['selectedIdentity'],CONTEXT);self.assertNotIn('authorityHash',record)
  with patch('signing.backend_hash',return_value='backend'),patch('identities.revalidate_context',return_value=CONTEXT):
   signing.sign(self.b,r)
   self.b.crypto.assert_called_once_with('sign-digest',None,bytes(64),service='Message',signing=r,identity=CONTEXT)
   with self.assertRaises(FileNotFoundError):signing.sign(self.b,r)
  self.assertFalse(path.exists());self.assertEqual(self.b.cfg['serial'],'111')
 def test_decryption_grant_echoes_selection_and_consumes_before_private_call(self):
  p=self.prepare_decrypt();r=self.decrypt_request(p);self.assertEqual(p['identity'],SELECT)
  path=self.b.data/('decryption-'+p['review']+'.json')
  def private(*a,**kw):self.assertFalse(path.exists());return {'result':'synthetic'}
  self.b.crypto.side_effect=private
  with patch('decryption.backend_hash',return_value='backend'),patch('identities.revalidate_context',return_value=CONTEXT):
   decryption.components(self.b,r)
   self.b.crypto.assert_called_once_with('decapsulate-components',None,b'',service='Gmail',components=r,identity=CONTEXT)
   with self.assertRaises(FileNotFoundError):decryption.components(self.b,r)
 def test_failed_selected_private_operation_is_not_retried(self):
  for kind in ('sign','decrypt'):
   p=self.prepare_sign() if kind=='sign' else self.prepare_decrypt()
   request=self.sign_request(p) if kind=='sign' else self.decrypt_request(p)
   function=signing.sign if kind=='sign' else decryption.components
   self.b.crypto.reset_mock();self.b.crypto.side_effect=ValueError('Synthetic rejected PIN')
   with patch('signing.backend_hash',return_value='backend'),patch('decryption.backend_hash',return_value='backend'),patch('identities.revalidate_context',return_value=CONTEXT):
    with self.assertRaises(ValueError):function(self.b,request)
    with self.assertRaises(FileNotFoundError):function(self.b,request)
   self.assertEqual(self.b.crypto.call_count,1)
 def test_changed_backend_or_expired_selected_grant_fails_before_pin(self):
  for kind in ('sign','decrypt'):
   p=self.prepare_sign() if kind=='sign' else self.prepare_decrypt()
   request=self.sign_request(p) if kind=='sign' else self.decrypt_request(p)
   function=signing.sign if kind=='sign' else decryption.components
   with patch('signing.backend_hash',return_value='changed'),patch('decryption.backend_hash',return_value='changed'),self.assertRaises(ValueError):function(self.b,request)
   path=self.b.data/(('signing-' if kind=='sign' else 'decryption-')+p['review']+'.json')
   record=json.loads(path.read_text());record['created']=time.time()-601;path.write_text(json.dumps(record))
   with self.assertRaises(ValueError):function(self.b,request)
  self.b.crypto.assert_not_called()
 def test_selected_private_pipe_uses_selected_serial_and_certificate(self):
  p=self.prepare_sign();request=self.sign_request(p)
  reply={k:request[k] for k in ('requestId','signingFingerprint','hashAlgorithm','digest')}
  reply.update(ed25519=base64.b64encode(bytes(64)).decode(),mldsa65=base64.b64encode(bytes(3309)).decode())
  with patch('chat_bridge.subprocess.check_output',return_value=b'222\n'),patch('chat_bridge.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,b'123456'),subprocess.CompletedProcess([],0,json.dumps(reply).encode(),b'')]) as run:
   ChatBridge.crypto(self.b,'sign-digest',None,bytes(64),service='Message',signing=request,identity=CONTEXT)
   self.assertEqual(run.call_args_list[0].args[0][-1],'222')
   wire=json.loads(run.call_args_list[1].kwargs['input']);self.assertEqual(wire['config']['serial'],'222');self.assertEqual(wire['own'],ENC)
   self.assertEqual(self.b.cfg['serial'],'111');self.assertNotIn('slot',wire['config'])
 def test_wrong_key_between_prepare_and_redemption_never_prompts(self):
  with patch('chat_bridge.subprocess.check_output',return_value=b'111\n'),patch('chat_bridge.subprocess.run') as run:
   with self.assertRaisesRegex(ValueError,'Connect YubiKey 222'):
    ChatBridge.crypto(self.b,'sign-digest',None,bytes(64),service='Message',signing={},identity=CONTEXT)
   run.assert_not_called()
 def test_connect_guidance_only_exposes_bounded_numeric_serials(self):
  message=host.operation_error('chat-selected-signing-material',ValueError('Connect YubiKey 222'))
  self.assertIn('Connect YubiKey 222',message);self.assertIn('No PIN was submitted',message)
  for text in ('Connect YubiKey 222 secret','Connect YubiKey ../123','Connect YubiKey 9999999999'):
   self.assertNotIn(text,host.operation_error('chat-selected-signing-material',ValueError(text)))

if __name__=='__main__':unittest.main()
