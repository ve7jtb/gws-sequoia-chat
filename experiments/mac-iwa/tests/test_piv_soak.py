"""Control-flow tests use no hardware/PIN and no real vault."""
import importlib.util,subprocess,time,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('soak',Path(__file__).parents[1]/'piv_soak.py')
soak=importlib.util.module_from_spec(spec);spec.loader.exec_module(soak)
class Soak(unittest.TestCase):
 def test_failure_stops_without_retry(self):
  seen=[]
  def step(n):
   seen.append(n)
   if n==2:raise RuntimeError('failure')
  with self.assertRaises(RuntimeError):soak.run_rounds(5,step,time.monotonic()+10)
  self.assertEqual(seen,[1,2])
 def test_expired_authorization_never_starts(self):
  with self.assertRaises(RuntimeError):soak.run_rounds(1,lambda _:self.fail(),0)
 def test_touch_required_is_rejected(self):
  before={'slots':{s:{'metadata':'Touch policy: Never'} for s in ('9c','84','9d','85')}}
  soak.no_touch(before)
  before['slots']['9d']['metadata']='Touch policy: Always'
  with self.assertRaises(RuntimeError):soak.no_touch(before)
 def test_native_errors_do_not_echo_secret(self):
  result=subprocess.CompletedProcess([],1,b'PRIVATE OUTPUT',b'PRIVATE PIN\nIWA_CRYPTO_STATUS=X25519_FAILED\n')
  with patch.object(soak.subprocess,'run',return_value=result):
   with self.assertRaisesRegex(RuntimeError,'^X25519_FAILED$'):soak.request(['fake'],{'pin':'PRIVATE'})
 def test_timeout_does_not_echo_input(self):
  with patch.object(soak.subprocess,'run',side_effect=subprocess.TimeoutExpired(['fake'],1,output=b'PRIVATE')):
   with self.assertRaisesRegex(RuntimeError,'^HELPER_TIMEOUT$'):soak.request(['fake'],{})
