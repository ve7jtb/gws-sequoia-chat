"""Isolated harness policy tests; all card/native calls are mocked.

The test card differs from the enrolled vault serial on purpose. These tests
must not load user settings, spawn a PIN prompt, read a card or change a policy.
"""
import copy,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
import hardware_profiles as harness
from chat_bridge import validate as validate_native_request

class HardwareProfiles(unittest.TestCase):
 def test_reviewed_backend_override_changes_only_in_memory_app_path(self):
  original={'serial':'111','app':'/installed/backend','chat_email':'original@example.invalid','cert':'original-certificate','nested':{'unchanged':True}}
  raw=json.dumps(original).encode()
  self.assertEqual(harness.isolated_configuration(raw),original)
  with tempfile.TemporaryDirectory() as temporary:
   staged=Path(temporary)/'reviewed-backend';staged.mkdir()
   isolated=harness.isolated_configuration(raw,staged)
   self.assertEqual(isolated,{**original,'app':str(staged.resolve())})
   # A later mutation of the runtime copy cannot silently rewrite the installed
   # source or the independent expected configuration used by the final audit.
   expected=copy.deepcopy(isolated);isolated['nested']['unchanged']=False
   self.assertEqual(json.loads(raw),original)
   audit=harness.configuration_audit(raw,raw,expected,isolated)
   self.assertEqual(audit,{'installedConfigurationUnchanged':True,'isolatedConfigurationUnchanged':False})
   self.assertEqual(harness.configuration_audit(raw,raw+b' ',expected,expected),
    {'installedConfigurationUnchanged':False,'isolatedConfigurationUnchanged':True})
 def test_missing_or_non_directory_backend_override_is_rejected(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);plain=root/'file';plain.write_text('not a backend directory')
   with self.assertRaises(FileNotFoundError):harness.isolated_configuration(b'{}',root/'absent')
   with self.assertRaises(ValueError):harness.isolated_configuration(b'{}',plain)
 def test_browser_native_requests_still_cannot_override_backend_paths(self):
  # The diagnostic flag is intentionally absent from the production schema;
  # selected device support must not become browser-selected executable paths.
  for field in ('app','backendApp','backend-app','backend_app','config'):
   with self.assertRaises(ValueError):validate_native_request({'op':'chat-identity-bundle-read','serial':'222',field:'/staged/backend'})
 def test_closed_modes_do_not_mix_ordinary_and_companion_profiles(self):
  self.assertEqual(harness.selected_profiles(None,True),['LEVEL5_COMPANION'])
  for profile in harness.ORDINARY_PROFILES:self.assertEqual(harness.selected_profiles(profile,False),[profile])
  for value,mode in [('level3',True),('LEVEL5_COMPANION',False),('level5',False),('level3,level3',False),('path/to/helper',True)]:
   with self.assertRaises(ValueError):harness.selected_profiles(value,mode)
 def test_selected_serial_is_independent_of_default_vault_enrollment(self):
  bridge=SimpleNamespace(cfg={'serial':'111','chat_email':'other@example.invalid','cert':'unused'})
  original=copy.deepcopy(bridge.cfg)
  view={'profile':'LEVEL5_COMPANION','certificate':'public-only'}
  with patch.object(harness,'companion_preview',return_value=view) as read,patch.object(harness,'preview') as ordinary,patch.object(harness,'run_public',return_value={'emails':['test@example.invalid']}):
   self.assertEqual(harness.public_preflight(bridge,'222','test@example.invalid',['LEVEL5_COMPANION'],True,None),view)
   read.assert_called_once_with(bridge,'222',None);ordinary.assert_not_called()
  self.assertEqual(bridge.cfg,original)
 def test_ordinary_level5_preflight_authenticates_selected_email_and_profile(self):
  bridge=SimpleNamespace(cfg={'serial':'111'})
  profile='level5-v4-hybrid-p384';view={'certificates':[{'kind':'openpgp','profile':profile,'certificate':'public'}]}
  with patch.object(harness,'preview',return_value=view) as read,patch.object(harness,'run_public',return_value={'emails':['test@example.invalid']}):
   harness.public_preflight(bridge,'222','test@example.invalid',[profile],False,None)
   read.assert_called_once_with(bridge,selected_serial='222',compatibility_certificate=None)
   with self.assertRaises(ValueError):harness.public_preflight(bridge,'222','other@example.invalid',[profile],False,None)
   with self.assertRaises(ValueError):harness.public_preflight(bridge,'222','test@example.invalid',['level3'],False,None)
  self.assertEqual(bridge.cfg['serial'],'111')
 def test_pipe_allows_only_selected_reads_grants_and_component_operations(self):
  for companion in (False,True):
   op='chat-identity-companion-read' if companion else 'chat-identity-bundle-read'
   harness.authorize_request(op,{'serial':'222'},'222',companion)
   for wrong in ({},{'serial':'111'}):
    with self.assertRaises(ValueError):harness.authorize_request(op,wrong,'222',companion)
   for op in ('chat-hardware-audit','chat-selected-signing-material','chat-selected-decryption-material'):
    harness.authorize_request(op,{'identity':{'serial':'222'}},'222',companion)
    with self.assertRaises(ValueError):harness.authorize_request(op,{'identity':{'serial':'111'}},'222',companion)
   for op in ('chat-sign-digest','chat-decapsulate-components'):harness.authorize_request(op,{},'222',companion)
 def test_pipe_excludes_vault_accounts_and_writes_even_with_valid_serial(self):
  for op in ('chat-vault-material','chat-vault-ecdh','chat-state','chat-send','piv-reset','key-generate','put-object'):
   with self.assertRaises(ValueError):harness.authorize_request(op,{'serial':'222'},'222',True)
  with self.assertRaises(ValueError):harness.authorize_request('chat-decapsulate-components',{'service':'Vault'},'222',True)
  with self.assertRaises(ValueError):harness.authorize_request('chat-identity-bundle-read',{'serial':'222'},'222',True)
  with self.assertRaises(ValueError):harness.authorize_request('chat-identity-companion-read',{'serial':'222'},'222',False)

if __name__=='__main__':unittest.main()
