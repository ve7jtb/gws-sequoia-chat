# Historical Python MIME/trust code is a regression oracle only. Its explicit
# test executable is not the installed production hardware worker.
import sys,json,base64,tempfile,shutil,os,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import gmail_bridge as g
import cert_store
def check_fixture(kind):
 fixture=json.loads(Path(os.environ['IWA_PUBLIC_TEST_FIXTURES']+'/'+kind+'.json').read_text())
 # Both fixtures self-certify the same mailbox as their MIME From header.
 email='sender@example.invalid'
 raw=b'From: sender@example.invalid\r\nSubject: Signed public fixture\r\nContent-Type: multipart/signed; boundary=outer; protocol="application/pgp-signature"\r\n\r\n--outer\r\n'+base64.b64decode(fixture['payload'])+b'\r\n--outer\r\nContent-Type: application/pgp-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n'+fixture['signature'].encode()+b'\r\n--outer--\r\n'
 raw=raw.replace(b'From: sender@example.invalid',('From: '+email).encode())
 with tempfile.TemporaryDirectory() as d:
  root=Path(d);(root/'runtime').mkdir();(root/'runtime/sequoia-iwa-crypto').symlink_to(os.environ['IWA_CRYPTO_ORACLE_BIN'])
  b=SimpleNamespace(root=root,data=root,contacts=lambda:[])
  msg=g.BytesParser(policy=g.policy.default).parsebytes(raw)
  result=g.signed_message(b,raw,msg)
  assert result['signatureStatus']=='valid',result
  assert result['certificateTrust']=='untrusted' and not result['encrypted']
  fp=result['signatures'][0]['fingerprint'];(root/(fp+'.pgp')).write_bytes(base64.b64decode(fixture['certificates'][0]))
  b.contacts=lambda:[{'fingerprint':fp,'email':email}]
  result=g.signed_message(b,raw,msg);assert result['certificateTrust']=='trusted'
  # Saving is independent of trust; exact certificate bytes persist across
  # new helper instances without exposing the key as an encryption recipient.
  b.contacts=lambda:[]
  b.chat=SimpleNamespace(write_new=lambda path,data:path.write_bytes(data))
  request={'op':'chat-mail-cert-save','fingerprint':fp}
  g.save_signer(b,result,request)
  assert not list(root.glob('mail-trust-*.json'))
  result=g.signed_message(b,raw,msg);assert result['certificateTrust']=='untrusted'
  assert result['certificateActions'][0]['saved']
  for bad_email in ('other@example.invalid',''):
   try:g.save_signer(b,result,{'op':'chat-mail-cert-trust','fingerprint':fp,'email':bad_email,'confirmed':True})
   except ValueError:pass
   else:raise AssertionError('Unrelated email acquired trust')
  g.save_signer(b,result,{'op':'chat-mail-cert-trust','fingerprint':fp,'email':email,'confirmed':True})
  b=SimpleNamespace(root=root,data=root,contacts=lambda:[])
  result=g.signed_message(b,raw,msg);assert result['certificateTrust']=='trusted'
  assert all('certificate' not in x for x in g.public_result(result)['signatures'])
  altered=raw.replace(b'Signed test body.',b'TAMPERED body.')
  tampered=g.signed_message(b,altered,g.BytesParser(policy=g.policy.default).parsebytes(altered))
  assert tampered['signatureStatus']=='invalid' and tampered['certificateTrust']=='trusted'
  assert not tampered['verified'] and 'forged' in tampered['warning']
  assert tampered['certificateActions']==[]
  listed=cert_store.inventory(b);row=next(c for c in listed if c['fingerprint']==fp)
  assert row['version']==(6 if kind=='v6' else 4)
  assert row['trustedEmails']==[email]
  cert_store.action(b,{'op':'chat-cert-untrust','fingerprint':fp,'email':email,'confirmed':True})
  assert g.signed_message(b,raw,msg)['certificateTrust']=='untrusted'
  assert any(p.exists() for p in cert_store.paths(root,fp))
  cert_store.action(b,{'op':'chat-cert-delete','fingerprint':fp,'confirmed':True})
  assert not any(p.exists() for p in cert_store.paths(root,fp))
  # An attached key can still verify mathematically after deletion, but cannot
  # restore the user's removed trust or save itself back into the inventory.
  result=g.signed_message(b,raw,msg)
  assert result['signatureStatus']=='valid' and result['certificateTrust']=='untrusted'
  assert not result['certificateActions'][0]['saved']
  bad=raw.replace(b'Signed test body.',b'TAMPERED body.');result=g.signed_message(b,bad,g.BytesParser(policy=g.policy.default).parsebytes(bad));assert result['signatureStatus']=='invalid'

 print('PASS',kind,'real MIME attached certificate, valid/untrusted, valid/trusted, tamper rejection; no PIN')

@unittest.skipUnless(os.environ.get('IWA_PUBLIC_TEST_FIXTURES') and os.environ.get('IWA_CRYPTO_ORACLE_BIN'), 'Generate Rust public fixtures and set IWA_CRYPTO_ORACLE_BIN')
class PublicPipelineTests(unittest.TestCase):
 def test_v4(self):check_fixture('v4')
 def test_v6(self):check_fixture('v6')
