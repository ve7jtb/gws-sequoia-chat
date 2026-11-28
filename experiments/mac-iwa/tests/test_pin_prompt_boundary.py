"""PIN presentation failures must stop before any private-key subprocess runs."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native'))
import chat_bridge
from chat_bridge import operation_error


class PinPromptBoundary(unittest.TestCase):
    def bridge(self, root):
        # Bypass native state-directory creation; this boundary needs only
        # the fixed device identity and the prompt subprocess. No token exists.
        bridge = chat_bridge.ChatBridge.__new__(chat_bridge.ChatBridge)
        bridge.root = Path(root)
        bridge.cfg = {'ykman': '/unused/ykman', 'serial': '12345678'}
        bridge.emit = Mock()
        return bridge

    def assert_stops_before_crypto(self, outcome, expected):
        with tempfile.TemporaryDirectory() as root:
            bridge = self.bridge(root)
            with patch.object(chat_bridge.subprocess, 'check_output', return_value=b'12345678\n'), \
                 patch.object(chat_bridge.subprocess, 'run') as run:
                if isinstance(outcome, Exception):
                    run.side_effect = outcome
                else:
                    run.return_value = outcome
                with self.assertRaisesRegex(ValueError, expected):
                    bridge.crypto('sign-digest', None, bytes(64), service='Message', signing={})
                # A second subprocess invocation would be the private crypto
                # worker. Cancellation/timeouts must never reach that boundary.
                self.assertEqual(run.call_count, 1)
                self.assertEqual(Path(run.call_args.args[0][0]).name, 'pin-prompt')
                self.assertEqual(run.call_args.kwargs['stdout'], subprocess.PIPE)
                self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
                stages=[call.args[0].get('stage') for call in bridge.emit.call_args_list if 'stage' in call.args[0] and call.args[0]['stage']!='PRIVATE_OPERATION_DIAGNOSTIC']
                self.assertEqual(stages[0],'PIN_DIALOG_STARTED')
                self.assertNotIn('PRIVATE_WORKER_STARTED',stages)
                self.assertNotIn('PIN_RECEIVED_LOCALLY',stages)
                self.assertIn(stages[-1],('PIN_DIALOG_TIMEOUT','PIN_REJECTED_LOCALLY'))
                self.assertNotIn('sensitive-example',repr(bridge.emit.call_args_list))

    def test_timeout_is_fixed_label_and_never_submits_pin(self):
        error = subprocess.TimeoutExpired(['pin-prompt'], 180, output=b'sensitive-example')
        self.assert_stops_before_crypto(error, '^PIN dialog timed out before submission$')

    def test_cancel_and_local_format_errors_never_submit_pin(self):
        for code, data in [(2, b''), (3, b''), (0, b'x'), (0, b'12345\x00')]:
            with self.subTest(code=code, length=len(data)):
                self.assert_stops_before_crypto(subprocess.CompletedProcess([], code, data),
                                               '^PIN cancelled or invalid$')

    def test_timeout_and_cancel_messages_distinguish_no_pin_submission(self):
        for op in ['chat-decapsulate-components', 'chat-sign-digest', 'chat-vault-ecdh']:
            for reason in ['PIN dialog timed out before submission', 'PIN cancelled or invalid']:
                self.assertIn('No PIN was sent', operation_error(op, ValueError(reason)))

    def test_unknown_errors_never_echo_secrets_or_claim_safe_submission(self):
        for op in ['chat-decapsulate-components', 'chat-sign-digest', 'chat-vault-ecdh']:
            message = operation_error(op, ValueError('sensitive-example'))
            self.assertNotIn('sensitive-example', message)
            self.assertNotIn('No PIN was sent', message)
