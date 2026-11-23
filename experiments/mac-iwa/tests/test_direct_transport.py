"""Offline send-ticket tests: no Google network, tokens or hardware access."""
import base64,importlib.util,json,sys,tempfile,time,types,unittest
from pathlib import Path
NATIVE=Path(__file__).resolve().parents[1]/'native'
# Keep this unit test independent of installed Sequoia utilities.
class ExportTests(unittest.TestCase):
 def setUp(self):
  self.old=sys.modules.get('chat_bridge');sys.modules['chat_bridge']=types.SimpleNamespace(LIMIT=262144)
  spec=importlib.util.spec_from_file_location('direct_test',NATIVE/'direct_transport.py');self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
  self.temp=tempfile.TemporaryDirectory();self.data=Path(self.temp.name);self.rid='a'*48
  self.contact={'id':'peer','email':'peer@example.org','fingerprint':'A'*64}
  self.bridge=types.SimpleNamespace(data=self.data,peer=lambda _: (self.contact,None),contacts=lambda:[self.contact],chat=types.SimpleNamespace(space_name=lambda s:s))
  self.draft=self.data/('draft-'+self.rid);self.draft.mkdir();(self.draft/'review.json').write_text(json.dumps({'space':'spaces/test','created':time.time(),'contact':'peer','recipient':'peer@example.org','fingerprint':'A'*64}))
  (self.draft/'manifest.json').write_text(json.dumps({'recipient':'peer@example.org','recipient_fingerprint':'A'*64}))
  (self.draft/'message.pgp').write_bytes(b'\x00\xffcipher');(self.draft/'pq-mail-sender-key.pgp').write_bytes(b'public')
  self.req={'op':'chat-browser-export','review':self.rid,'service':'Chat','confirmed':True}
 def tearDown(self):
  self.temp.cleanup()
  if self.old is None:sys.modules.pop('chat_bridge',None)
  else:sys.modules['chat_bridge']=self.old
 def test_export_is_one_use_and_preserves_bytes(self):
  r=self.m.action(self.bridge,self.req);self.assertEqual(base64.b64decode(r['cipher']),b'\x00\xffcipher');self.assertFalse(self.draft.exists())
  with self.assertRaises(FileNotFoundError):self.m.action(self.bridge,self.req)
 def test_removed_or_changed_trust_blocks_export(self):
  self.contact['fingerprint']='B'*64
  with self.assertRaises(ValueError):self.m.action(self.bridge,self.req)
  self.assertTrue(self.draft.exists())
 def test_confirmation_and_expiry(self):
  with self.assertRaises(ValueError):self.m.action(self.bridge,{**self.req,'confirmed':False})
  p=self.draft/'review.json';r=json.loads(p.read_text());r['created']=0;p.write_text(json.dumps(r))
  with self.assertRaises(ValueError):self.m.action(self.bridge,self.req)
if __name__=='__main__':unittest.main()
