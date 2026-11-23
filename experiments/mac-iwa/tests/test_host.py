"""Protocol rejection checks; no token or user credentials are used."""
import importlib.util,io,json,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('host',Path(__file__).parents[1]/'native/host.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
class HostTests(unittest.TestCase):
 def test_connection_errors_do_not_request_pin(self):
  for op in ('chat-mail-login','chat-mail-connect','chat-mail-list'):
   message=host.operation_error(op)
   self.assertIn('Gmail read and send permissions',message)
   self.assertIn('No YubiKey operation was attempted',message)
  self.assertIn('Gmail operation stopped',host.operation_error('chat-mail-open'))
  self.assertIn('Chat operation stopped',host.operation_error('chat-open'))
 def test_public_migration_errors_do_not_echo_details_or_request_pin(self):
  for op in ('chat-certificate-migration','chat-signing-material'):
   message=host.operation_error(op,ValueError('private low-level detail'))
   self.assertIn('No YubiKey operation was attempted',message)
   self.assertNotIn('private low-level detail',message)
 def test_valid_frame(self):
  raw=b'{"op":"status"}'
  self.assertEqual(host.frame_read(io.BytesIO(struct.pack('=I',len(raw))+raw)),{'op':'status'})
 def test_truncated(self):
  for raw in (b'\x01',struct.pack('=I',10)+b'{}'):
   with self.assertRaises(ValueError):host.frame_read(io.BytesIO(raw))
 def test_limits(self):
  for size in (0,host.MAX_FRAME+1,0xffffffff):
   with self.assertRaises(ValueError):host.frame_read(io.BytesIO(struct.pack('=I',size)))
 def test_closed_operations(self):
  for obj in ({'op':'reset'},{'op':'test','serial':'OTHER'},{'op':'sign','pin':'test'},{'op':'test','path':'/tmp/x'}):
   with self.assertRaises(ValueError):host.validate_request(obj)
 def test_non_object(self):
  with self.assertRaises(ValueError):host.frame_read(io.BytesIO(struct.pack('=I',2)+b'[]'))
if __name__=='__main__':unittest.main()
