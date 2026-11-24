"""Read-only audit protocol with synthetic ykman responses; never a real key."""
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).parents[1]/'native'))
import hardware_audit as audit
from chat_bridge import validate,ChatBridge,crypto_prompt

IDENTITY={'serial':'123456','bundleHash':'a'*64,'fingerprint':'B'*64,
          'certificateHash':'c'*64,'email':'owner@example.test'}
KEY=b'public DER fixture'
META=b'Slot: 9C (Signature)\nAlgorithm: MlDsa65\nOrigin: generated\nPIN policy: Always\nTouch policy: Cached\n'


class HardwareAudit(unittest.TestCase):
 def setUp(self):
  self.b=SimpleNamespace(cfg={'ykman':'fixed-installed-ykman'},emit=Mock())
  self.calls=[];self.info_reads=0;self.slot_reads={}
 def tool(self,argv,**kwargs):
  self.assertEqual(argv[0],'fixed-installed-ykman');self.assertIs(kwargs['stdin'],subprocess.DEVNULL)
  self.assertEqual(kwargs['timeout'],25);self.calls.append(argv[1:])
  args=argv[1:]
  if args==['list','--serials']:return subprocess.CompletedProcess(argv,0,b'123456\n',b'')
  self.assertEqual(args[:3],['--device','123456','piv'])
  if args[3:]==['info']:
   self.info_reads+=1;return subprocess.CompletedProcess(argv,0,b'PIN tries remaining: 3/3\n',b'')
  self.assertEqual(args[3],'keys')
  if args[4]=='info':
   self.assertEqual(len(args),6);slot=args[5];self.assertIn(slot,audit.PUBLIC_SLOTS)
   self.slot_reads[slot]=self.slot_reads.get(slot,0)+1
   if slot=='9c':return subprocess.CompletedProcess(argv,0,META,b'')
   return subprocess.CompletedProcess(argv,1,b'',b'Error: APDU error: SW=0x6A88\n')
  self.assertEqual(args[4:],['export','--format','der','9c','-'])
  return subprocess.CompletedProcess(argv,0,KEY,b'')
 def run_audit(self,tool=None,hashes=('f'*64,'f'*64)):
  with patch.object(audit,'selected',return_value=({**IDENTITY,'certificate':'public'},{})) as selected,patch.object(audit,'backend_hash',side_effect=hashes),patch.object(audit.subprocess,'run',side_effect=tool or self.tool):
   result=audit.snapshot(self.b,IDENTITY)
   selected.assert_called_once_with(self.b,IDENTITY)
   return result
 def test_snapshot_schema_complete_and_only_fixed_read_commands(self):
  self.assertEqual(validate({'op':'chat-hardware-audit','identity':IDENTITY}),'chat-hardware-audit')
  for extra in ('pin','slot','path','serial','command','reset'):
   with self.assertRaises(ValueError):validate({'op':'chat-hardware-audit','identity':IDENTITY,extra:'forbidden'})
  r=self.run_audit()
  self.assertEqual(set(r),{'format','version','identity','slots','pinRetries','backendHash'})
  self.assertEqual(r['format'],'sequoia-iwa-hardware-audit');self.assertEqual(r['identity'],IDENTITY)
  self.assertEqual([row['slot'] for row in r['slots']],list(audit.PUBLIC_SLOTS))
  self.assertEqual(self.slot_reads,{slot:2 for slot in audit.PUBLIC_SLOTS})
  self.assertEqual(self.info_reads,2);self.assertEqual(r['pinRetries'],{'remaining':3,'maximum':3})
  self.assertEqual(r['slots'][1],{'slot':'9c','publicKeySha256':hashlib.sha256(KEY).hexdigest(),'algorithm':'MlDsa65','origin':'generated','pinPolicy':'Always','touchPolicy':'Cached'})
  self.assertTrue(all(value is None for k,value in r['slots'][0].items() if k!='slot'))
  self.assertFalse(any(word in {'generate','import','reset','set-pin-retries','verify-pin','set-touch-policy'} for call in self.calls for word in call))
 def test_usb_or_apdu_failure_is_never_an_empty_slot(self):
  for error in (b'PCSC failure',b'APDU error: SW=0x6982',b'APDU error: SW=0x6A88\nUSB failure',
    b'Error: Failed to get slot metadata: Connection error: APDU error: SW=0x6A88\nUSB failure',
    b'Error: Failed to get slot metadata: Unknown error: APDU error: SW=0x6A88'):
   def broken(argv,**kw):
    r=self.tool(argv,**kw)
    if argv[-2:]==['info','9a']:return subprocess.CompletedProcess(argv,1,b'',error)
    return r
   with self.subTest(error=error),self.assertRaises(ValueError):self.run_audit(broken)
 def test_exact_ykman_empty_slot_diagnostics_are_supported(self):
  # The installed beta ykman emits the long form. All supported forms denote
  # only object-not-found; none may contain extra diagnostics or arbitrary text.
  for error in (b'APDU error: SW=0x6A88\n',b'Error: APDU error: SW=0x6A88\n',
    b'Error: Failed to get slot metadata: Connection error: APDU error: SW=0x6A88\n'):
   self.setUp()
   def empty(argv,**kw):
    r=self.tool(argv,**kw)
    if r.returncode:r.stderr=error
    return r
   with self.subTest(error=error):
    result=self.run_audit(empty)
    self.assertIsNone(result['slots'][0]['publicKeySha256'])
 def test_missing_duplicate_or_control_policy_metadata_fails(self):
  for raw in (META.replace(b'Touch policy: Cached\n',b''),META+b'PIN policy: Once\n',META.replace(b'Cached',b'Cached\x00secret')):
   def broken(argv,**kw):
    r=self.tool(argv,**kw)
    return subprocess.CompletedProcess(argv,0,raw,b'') if argv[-2:]==['info','9c'] else r
   with self.subTest(raw=raw),self.assertRaises(ValueError):self.run_audit(broken)
 def test_key_policy_pin_count_backend_or_presence_changes_abort(self):
  for change in ('key','policy','pin','backend','presence'):
   self.setUp();exports=0;presence=0
   def changing(argv,**kw):
    nonlocal exports,presence
    r=self.tool(argv,**kw)
    if argv[1:]==['list','--serials']:
     presence+=1
     if change=='presence' and presence==2:r.stdout=b'654321\n'
    if argv[-2:]==['info','9c'] and change=='policy' and self.slot_reads['9c']==2:r.stdout=META.replace(b'Cached',b'Never')
    if argv[-1]=='-' and 'export' in argv:
     exports+=1
     if change=='key' and exports==2:r.stdout=b'new public key'
    if argv[-1]=='info' and change=='pin' and self.info_reads==2:r.stdout=b'PIN tries remaining: 2/3\n'
    return r
   with self.subTest(change=change),self.assertRaises(ValueError):
    self.run_audit(changing,('f'*64,'e'*64) if change=='backend' else ('f'*64,'f'*64))
 def test_failed_selected_identity_never_runs_audit_or_pin(self):
  with patch.object(audit,'selected',side_effect=ValueError('changed bundle')),patch.object(audit.subprocess,'run') as run:
   with self.assertRaises(ValueError):audit.snapshot(self.b,IDENTITY)
   run.assert_not_called()
 def test_bounded_tool_output_and_timeout_never_retry(self):
  for effect in (subprocess.TimeoutExpired(['fixed'],25),subprocess.CompletedProcess([],0,b'x'*16385,b'')):
   with patch.object(audit.subprocess,'run',side_effect=effect if isinstance(effect,Exception) else None,return_value=effect) as run:
    with self.assertRaises((ValueError,subprocess.TimeoutExpired)):audit.command(self.b,['list','--serials'])
    self.assertEqual(run.call_count,1)
 def test_hardware_test_uses_component_boundary_and_fixed_label(self):
  self.assertEqual(validate({'op':'chat-selected-decryption-material','identity':IDENTITY,'service':'Hardware test'}),'chat-selected-decryption-material')
  self.assertEqual(crypto_prompt('decapsulate-components','Hardware test'),'Decrypt local hardware test — ML-KEM-768 + X25519')
  with self.assertRaises(ValueError):crypto_prompt('open','Hardware test')

if __name__=='__main__':unittest.main()
