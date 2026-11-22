"""Authorization checks at the new browser/native MIME boundary."""
import base64,json,sys,tempfile,unittest
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
