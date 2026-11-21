import sys,unittest,importlib.util,tempfile,json
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT/'native'))
import gmail_bridge,chat_bridge
class GmailTests(unittest.TestCase):
 def test_closed_schema(self):
  for request in [{'op':'chat-mail-delete','message':'x'},{'op':'chat-mail-send','review':'x','confirmed':False},{'op':'chat-mail-open','message':'x','contact':'y','path':'/tmp/key'}]:
   with self.assertRaises(ValueError):chat_bridge.validate(request)
 def run_action(self,op,response):
  with tempfile.TemporaryDirectory() as d:
   b=Mock();b.root=Path(d);b.cfg={'chat_email':'me@example.invalid'};b.data=Path(d);m=Mock();m.gws_memory.return_value=response
   spec=Mock();spec.loader.exec_module=Mock()
   with patch.object(gmail_bridge.importlib.util,'spec_from_file_location',return_value=spec),patch.object(gmail_bridge.importlib.util,'module_from_spec',return_value=m):
    return gmail_bridge.action(b,op)
 def test_account_mismatch(self):
  with self.assertRaises(ValueError):self.run_action({'op':'chat-mail-connect'},{'emailAddress':'wrong@example.invalid'})
 def test_account_matches(self):
  self.assertEqual(self.run_action({'op':'chat-mail-connect'},{'emailAddress':'me@example.invalid'}),{'account':'me@example.invalid'})

 def test_upload_staging_and_cleanup(self):
  for fails in (False,True):
   with tempfile.TemporaryDirectory() as d:
    b=Mock();b.root=Path(d);profile=b.root/'runtime/chat/private/gws';profile.mkdir(parents=True)
    source=b.root/'encrypted.eml';source.write_bytes(b'encrypted synthetic fixture')
    paths=[]
    def api(*args):
     p=Path(args[args.index('--upload')+1]);paths.append(p)
     self.assertIn(profile,p.parents);self.assertEqual(p.read_bytes(),source.read_bytes())
     self.assertEqual(p.stat().st_mode & 0o777,0o600)
     self.assertIn('--json',args)
     if fails:raise ValueError('network failure')
     return {'id':'test'}
    if fails:
     with self.assertRaises(ValueError):gmail_bridge.upload_encrypted_mail(b,api,source)
    else:self.assertEqual(gmail_bridge.upload_encrypted_mail(b,api,source),{'id':'test'})
    self.assertEqual(len(paths),1);self.assertFalse(paths[0].exists());self.assertTrue(source.exists())
