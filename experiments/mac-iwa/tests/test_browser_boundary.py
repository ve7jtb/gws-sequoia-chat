"""Authorization checks at the new browser/native MIME boundary."""
import base64,hashlib,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
from chat_bridge import browser_mime,validate
from browser_material import material
class BrowserBoundary(unittest.TestCase):
 def test_compose_metadata_cannot_substitute_recipient(self):
  raw=b'From: alice@example.invalid\r\nTo: bob@example.invalid\r\nSubject: Test\r\n\r\nBody'
  r={'mime':base64.b64encode(raw).decode(),'subject':'Test'}
  self.assertEqual(browser_mime(r,'alice@example.invalid','bob@example.invalid'),raw)
  with self.assertRaises(ValueError):browser_mime(r,'alice@example.invalid','mallory@example.invalid')
  r['mime']=base64.b64encode(raw.replace(b'To: bob',b'To: mallory@example.invalid\r\nTo: bob')).decode()
  with self.assertRaises(ValueError):browser_mime(r,'alice@example.invalid','bob@example.invalid')
 def test_readonly_material_has_no_secret_fields(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'credentials.json').write_text('{"refresh_token":"not-public"}')
   self.assertEqual(material(SimpleNamespace(data=p)),{'certificates':[],'saved':[],'bindings':[]})
 def test_decrypt_route_rejects_paths_and_pin(self):
  good={'op':'chat-decrypt','contact':'id','payload':'YQ==','service':'Gmail'}
  self.assertEqual(validate(good),'chat-decrypt')
  for key in ['pin','module','slot','serial','path']:
   with self.assertRaises(ValueError):validate({**good,key:'unexpected'})

class EncryptionBoundary(unittest.TestCase):
 def test_completion_allows_only_cipher_and_ticket(self):
  good={'op':'chat-encryption-complete','review':'a'*48,'cipher':'YQ=='}
  self.assertEqual(validate(good),'chat-encryption-complete')
  for key in ['pin','recipient','space','subject','service','module']:
   with self.assertRaises(ValueError):validate({**good,key:'substitute'})
 def test_expired_and_changed_contacts_never_stage_ciphertext(self):
  from chat_bridge import ChatBridge
  from unittest.mock import Mock
  import time
  with tempfile.TemporaryDirectory() as tmp:
   b=ChatBridge.__new__(ChatBridge);b.data=Path(tmp)
   rid='a'*48;p=b.data/('encryption-'+rid+'.json')
   metadata={'created':0,'contact':'id','recipient':'b@example.invalid','fingerprint':'f'}
   p.write_text(json.dumps(metadata))
   with self.assertRaises(ValueError):b.complete_browser_encryption({'review':rid,'cipher':'YQ=='})
   metadata['created']=time.time();p.write_text(json.dumps(metadata))
   b.peer=Mock(return_value=({'email':'different@example.invalid','fingerprint':'f'},Path(tmp)/'peer'))
   with self.assertRaises(ValueError):b.complete_browser_encryption({'review':rid,'cipher':'YQ=='})
   self.assertTrue(p.exists())
 def test_one_use_completion_requires_encrypted_recipient_check(self):
  from chat_bridge import ChatBridge
  from unittest.mock import Mock,patch
  import time
  with tempfile.TemporaryDirectory() as tmp:
   b=ChatBridge.__new__(ChatBridge);b.root=b.data=Path(tmp)
   b.cfg={'chat_email':'a@example.invalid','cert':str(b.data/'own')}
   (b.data/'own').write_bytes(b'public sender');peer=b.data/'peer';peer.write_bytes(b'public recipient')
   contact={'id':'id','email':'b@example.invalid','fingerprint':'f'}
   b.peer=Mock(return_value=(contact,peer));b.chat=Mock()
   b.chat.check_cert.return_value={'fingerprint':'own'}
   def mkdir(p):p.mkdir();return p
   b.chat.private_dir.side_effect=mkdir
   b.chat.write_new.side_effect=lambda p,data:p.write_bytes(data)
   rid='a'*48;ticket=b.data/('encryption-'+rid+'.json')
   ticket.write_text(json.dumps({'created':time.time(),'service':'Chat','space':'spaces/TEST','contact':'id','recipient':contact['email'],'fingerprint':'f','subject':'Test','stage':'signed','sender':b.cfg['chat_email'],'senderHash':hashlib.sha256((b.data/'own').read_bytes()).hexdigest(),'recipientHash':hashlib.sha256(peer.read_bytes()).hexdigest()}))
   request={'review':rid,'cipher':'YQ=='}
   with patch('chat_bridge.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout=b'')):
    with self.assertRaises(ValueError):b.complete_browser_encryption(request)
   self.assertTrue(ticket.exists())
   with patch('chat_bridge.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'{"valid":true}')):
    result=b.complete_browser_encryption(request)
    self.assertEqual(result['space'],'spaces/TEST')
    self.assertFalse(ticket.exists())
    with self.assertRaises(FileNotFoundError):b.complete_browser_encryption(request)


class DecapsulationBoundary(unittest.TestCase):
 def test_live_route_uses_decapsulation_only(self):
  from chat_bridge import ChatBridge
  from unittest.mock import Mock
  with tempfile.TemporaryDirectory() as tmp:
   b=ChatBridge.__new__(ChatBridge);b.data=Path(tmp);b.cfg={'chat_email':'me@example.invalid'};b.chat=Mock()
   b.peer=Mock(return_value=({'email':'sender@example.invalid','fingerprint':'F'*64},Path(tmp)/'public'))
   b.crypto=Mock(return_value={'sessionKey':'test-only','algorithm':9,'cipherHash':'0'*64,'recipientKey':'A'*64})
   result=b.action({'op':'chat-decrypt','contact':'saved','payload':'YQ==','service':'Gmail'})
   self.assertEqual(b.crypto.call_args.args[0],'decapsulate-browser')
   self.assertEqual(result['cipher'],'YQ==');self.assertEqual(result['recipient'],'me@example.invalid')
   self.assertNotIn('raw',result);self.assertNotIn('signature',result)
