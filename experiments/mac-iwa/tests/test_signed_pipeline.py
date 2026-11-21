import sys,json,base64,tempfile,shutil,os,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import gmail_bridge as g
def check_fixture(kind):
 fixture=json.loads(Path(os.environ['IWA_PUBLIC_TEST_FIXTURES']+'/'+kind+'.json').read_text())
 raw=b'From: sender@example.invalid\r\nSubject: Signed public fixture\r\nContent-Type: multipart/signed; boundary=outer; protocol="application/pgp-signature"\r\n\r\n--outer\r\n'+base64.b64decode(fixture['payload'])+b'\r\n--outer\r\nContent-Type: application/pgp-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n'+fixture['signature'].encode()+b'\r\n--outer--\r\n'
 with tempfile.TemporaryDirectory() as d:
  root=Path(d);(root/'runtime').mkdir();(root/'runtime/sequoia-iwa-crypto').symlink_to(os.environ['IWA_CRYPTO_TEST_BIN'])
  b=SimpleNamespace(root=root,data=root,contacts=lambda:[])
  msg=g.BytesParser(policy=g.policy.default).parsebytes(raw)
  result=g.signed_message(b,raw,msg)
  assert result['signatureStatus']=='valid',result
  assert result['certificateTrust']=='untrusted' and not result['encrypted']
  fp=result['signatures'][0]['fingerprint'];(root/(fp+'.pgp')).write_bytes(base64.b64decode(fixture['certificates'][0]))
  b.contacts=lambda:[{'fingerprint':fp,'email':'sender@example.invalid'}]
  result=g.signed_message(b,raw,msg);assert result['certificateTrust']=='trusted'
  bad=raw.replace(b'Signed test body.',b'TAMPERED body.');result=g.signed_message(b,bad,g.BytesParser(policy=g.policy.default).parsebytes(bad));assert result['signatureStatus']=='invalid'

 print('PASS',kind,'real MIME attached certificate, valid/untrusted, valid/trusted, tamper rejection; no PIN')

@unittest.skipUnless(os.environ.get('IWA_PUBLIC_TEST_FIXTURES') and os.environ.get('IWA_CRYPTO_TEST_BIN'), 'Generate Rust public fixtures and set IWA_CRYPTO_TEST_BIN')
class PublicPipelineTests(unittest.TestCase):
 def test_v4(self):check_fixture('v4')
 def test_v6(self):check_fixture('v6')
