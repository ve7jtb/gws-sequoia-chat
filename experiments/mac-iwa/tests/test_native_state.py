"""Native grant/certificate utilities must not depend on the mail frontend."""
import base64
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import native_state


class NativeState(unittest.TestCase):
 def test_exclusive_write_never_overwrites_or_follows_symlinks(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'grant';native_state.write_new(p,b'public authorization')
   self.assertEqual(p.read_bytes(),b'public authorization')
   self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
   with self.assertRaises(FileExistsError):native_state.write_new(p,b'replace')
   link=Path(d)/'link';link.symlink_to(p)
   with self.assertRaises(FileExistsError):native_state.write_new(link,b'replace')
   self.assertEqual(p.read_bytes(),b'public authorization')
 def test_public_validation_uses_current_native_parser_not_old_frontend(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'public';p.write_bytes(b'public fixture')
   b=SimpleNamespace(root=Path(d))
   with patch('identities.run_public',return_value={'fingerprint':'A'*64,'emails':['owner@example.test']}) as run:
    result=native_state.check_certificate(b,p,'owner@example.test')
    self.assertEqual(result['fingerprint'],'A'*64)
    run.assert_called_once_with(b,{'op':'identity-canonical','certificate':base64.b64encode(p.read_bytes()).decode()})
    with self.assertRaises(ValueError):native_state.check_certificate(b,p,'wrong@example.test')
   with patch('identities.run_public') as run:
    for email in ('bad\n@example.test','Name <owner@example.test>',''):
     with self.assertRaises(ValueError):native_state.check_certificate(b,p,email)
    run.assert_not_called()
 def test_public_validation_rejects_symlink_oversize_and_unvalidated_metadata(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'public';p.write_bytes(b'public fixture');link=Path(d)/'link';link.symlink_to(p)
   b=SimpleNamespace(root=Path(d))
   with patch('identities.run_public') as run:
    with self.assertRaises(ValueError):native_state.check_certificate(b,link,'owner@example.test')
    p.write_bytes(bytes(65537))
    with self.assertRaises(ValueError):native_state.check_certificate(b,p,'owner@example.test')
    run.assert_not_called()
   p.write_bytes(b'public fixture')
   for metadata in ({'fingerprint':'not-valid','emails':['owner@example.test']},
     {'fingerprint':'A'*64,'emails':[]},{'fingerprint':42,'emails':['owner@example.test']},
     {'fingerprint':'A'*64,'emails':'owner@example.test'},
     {'fingerprint':'A'*64,'emails':['owner@example.test',None]},[]):
    with patch('identities.run_public',return_value=metadata),self.assertRaises(ValueError):
     native_state.check_certificate(b,p,'owner@example.test')

if __name__=='__main__':unittest.main()
