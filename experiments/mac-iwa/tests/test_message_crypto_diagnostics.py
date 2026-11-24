"""Closed message-operation phase evidence without secrets or hardware access."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native'))
import chat_bridge


class MessageCryptoDiagnostics(unittest.TestCase):
    def bridge(self, root):
        # Every external command is mocked by the caller. This object needs
        # only a public placeholder and a private directory for fixed metadata.
        root = Path(root)
        (root / 'private/chat-state').mkdir(parents=True)
        (root / 'public.asc').write_bytes(b'public-placeholder')
        bridge = chat_bridge.ChatBridge.__new__(chat_bridge.ChatBridge)
        bridge.root = root
        bridge.data = root / 'private/chat-state'
        bridge.cfg = {'serial': '123', 'ykman': '/unused/ykman',
                      'cert': str(root / 'public.asc'), 'app': str(root / 'app')}
        bridge.emit = Mock()
        return bridge

    def request(self):
        return {'requestId': 'A' * 64, 'signingFingerprint': 'B' * 64,
                'hashAlgorithm': 10, 'digest': base64.b64encode(bytes(64)).decode()}

    def response(self):
        # These placeholder component bytes never reach a card or real crypto
        # worker. The bridge validates their binding and width only; native and
        # WASM cryptographic verification have their own independent tests.
        return {**self.request(), 'ed25519': base64.b64encode(bytes(64)).decode(),
                'mldsa65': base64.b64encode(bytes(3309)).decode()}

    def exercise(self, result, expected_error=None):
        with tempfile.TemporaryDirectory() as root:
            bridge = self.bridge(root)
            pin = b'654321'
            prompt = subprocess.CompletedProcess([], 0, pin)
            with patch.object(chat_bridge.subprocess, 'check_output', return_value=b'123\n'), \
                 patch.object(chat_bridge.subprocess, 'run', side_effect=[prompt, result]) as run:
                if expected_error:
                    with self.assertRaisesRegex(ValueError, expected_error):
                        bridge.crypto('sign-digest', None, bytes(64), 'Message', signing=self.request())
                else:
                    self.assertEqual(bridge.crypto('sign-digest', None, bytes(64), 'Message',
                                                  signing=self.request()), self.response())
                self.assertEqual(run.call_count, 2, 'Never retry either PIN entry or private work')
            path = bridge.data / 'message-crypto-diagnostics.json'
            raw = path.read_text()
            history = json.loads(raw)
            self.assertNotIn(pin.decode(), raw)
            self.assertNotIn('sensitive-example', raw)
            self.assertNotIn('sensitive-example', repr(bridge.emit.call_args_list))
            self.assertNotIn(pin.decode(), repr(bridge.emit.call_args_list))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for entry in history:
                fields={'time', 'operation', 'status', 'elapsed_ms', 'exit_code'}
                self.assertTrue(fields <= set(entry) <= fields | {'opensslErrorCodes','pinCallbacks','pkcs11Calls','pcscCalls'})
                self.assertEqual(entry['operation'], 'sign-digest')
                self.assertIn(entry['status'], chat_bridge.MESSAGE_STATUS)
            self.assertFalse((bridge.data / 'vault-diagnostics.json').exists())
            return [item['status'] for item in history]

    def test_success_distinguishes_worker_from_validated_reply(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(self.response()).encode(), b'')
        self.assertEqual(self.exercise(result), ['PIN_DIALOG_STARTED', 'PIN_RECEIVED_LOCALLY',
                         'WORKER_STARTED', 'WORKER_SUCCEEDED', 'RESPONSE_VALIDATED'])

    def test_component_failure_is_fixed_and_not_a_response_failure(self):
        result = subprocess.CompletedProcess([], 1, b'sensitive-example',
                    b'IWA_CRYPTO_STATUS=COMPANION_WRAP_FAILED\nsensitive-example\n')
        statuses = self.exercise(result, '^Cryptographic operation failed; no retry$')
        self.assertEqual(statuses[-1], 'WORKER_COMPANION_WRAP_FAILED')
        self.assertNotIn('WORKER_SUCCEEDED', statuses)
        self.assertNotIn('RESPONSE_REJECTED', statuses)

    def test_malformed_success_output_is_a_response_failure(self):
        result = subprocess.CompletedProcess([], 0, b'{"sensitive-example":"private"}', b'')
        statuses = self.exercise(result, '^Signature response binding mismatch$')
        self.assertEqual(statuses[-2:], ['WORKER_SUCCEEDED', 'RESPONSE_REJECTED'])
        self.assertNotIn('RESPONSE_VALIDATED', statuses)

    def test_timeout_discards_captured_output(self):
        error = subprocess.TimeoutExpired(['worker'], 150,
                                         output=b'sensitive-example', stderr=b'sensitive-example')
        statuses = self.exercise(error, '^Vault helper timeout$')
        self.assertEqual(statuses[-1], 'WORKER_TIMEOUT')
        self.assertNotIn('WORKER_SUCCEEDED', statuses)

    def test_history_filters_unknown_fields_and_is_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            bridge = self.bridge(root)
            path = bridge.data / 'message-crypto-diagnostics.json'
            path.write_text(json.dumps([{'status': 'WORKER_SUCCEEDED', 'pin': 'sensitive-example'}]))
            for _ in range(45):
                bridge.message_diagnostic('sign-digest', 'WORKER_STARTED', time.monotonic())
            before = path.read_bytes()
            self.assertEqual(len(json.loads(before)), 40)
            self.assertNotIn(b'sensitive-example', before)
            # An arbitrary caller cannot use diagnostics as a text log.
            bridge.message_diagnostic('sign-digest', 'sensitive-example', time.monotonic())
            bridge.message_diagnostic('sensitive-example', 'WORKER_STARTED', time.monotonic())
            self.assertEqual(before, path.read_bytes())

    def test_rust_boundary_codes_require_exact_status_lines(self):
        # Every compile-time status remains closed at the Python boundary,
        # including adapter-stage and post-adapter signature verification.
        for code in chat_bridge.CRYPTO_STATUS:
            self.assertEqual(chat_bridge.crypto_status(('IWA_CRYPTO_STATUS=' + code + '\n').encode()), code)
            self.assertEqual(chat_bridge.crypto_status(('IWA_CRYPTO_STATUS=' + code + ' sensitive-example\n').encode()), 'CRYPTO_FAILED')

    def test_specific_helper_failure_survives_without_backend_text(self):
        result = subprocess.CompletedProcess([], 1, b'sensitive-example',
                    b'IWA_CRYPTO_STATUS=PKCS11_HELPER_VERIFY_FAILED\nsensitive-example\n')
        statuses = self.exercise(result, '^Cryptographic operation failed; no retry$')
        self.assertEqual(statuses[-1], 'WORKER_PKCS11_HELPER_VERIFY_FAILED')

    def test_numeric_worker_evidence_is_bounded_and_no_reason_text_is_saved(self):
        raw=(b'IWA_CRYPTO_STATUS=PKCS11_HELPER_PARAMETERS_FAILED\n'
             b'IWA_CRYPTO_ERROR=40800005\nIWA_CRYPTO_PIN_CALLBACKS=2\nsensitive-example\n')
        self.assertEqual(chat_bridge.crypto_evidence(raw),
                         {'opensslErrorCodes':['40800005'],'pinCallbacks':2})
        result=subprocess.CompletedProcess([],1,b'sensitive-example',raw)
        self.assertEqual(self.exercise(result,'^Cryptographic operation failed; no retry$')[-1],
                         'WORKER_PKCS11_HELPER_PARAMETERS_FAILED')
        with tempfile.TemporaryDirectory() as root:
            bridge=self.bridge(root)
            bridge.message_diagnostic('sign-digest','WORKER_PKCS11_HELPER_SIGN_FAILED',
                                      time.monotonic(),1,chat_bridge.crypto_evidence(raw))
            # A subsequent phase retains only the reviewed optional numeric
            # fields in history; arbitrary reason strings are never eligible.
            bridge.message_diagnostic('sign-digest','WORKER_STARTED',time.monotonic())
            history=json.loads((bridge.data/'message-crypto-diagnostics.json').read_text())
            self.assertEqual(history[0]['opensslErrorCodes'],['40800005'])
            self.assertEqual(history[0]['pinCallbacks'],2)
        self.assertEqual(chat_bridge.crypto_evidence(b'IWA_CRYPTO_ERROR=40800005 reason\nIWA_CRYPTO_ERROR=030000ea\nIWA_CRYPTO_PIN_CALLBACKS=654321\n'),{})
        self.assertEqual(chat_bridge.crypto_evidence(b'IWA_CRYPTO_PIN_CALLBACKS=2\nIWA_CRYPTO_PIN_CALLBACKS=2\n'),{})
        self.assertEqual(chat_bridge.crypto_evidence(b'x'*32769),{})
        self.assertIsNone(chat_bridge.evidence_fields({'pinCallbacks':True}))
        self.assertIsNone(chat_bridge.evidence_fields({'opensslErrorCodes':['sensitive-example']}))
        self.assertIsNone(chat_bridge.evidence_fields({'reason':'sensitive-example'}))

    def test_pkcs11_evidence_is_fixed_bounded_and_preserved(self):
        raw=b'IWA_CRYPTO_STATUS=PKCS11_HELPER_SIGN_FAILED\nIWA_CRYPTO_PKCS11=C_Login:00000000\nIWA_CRYPTO_PKCS11=C_SignInit:00000000\nIWA_CRYPTO_PKCS11=C_Sign:00000030\n'
        evidence=chat_bridge.crypto_evidence(raw)
        self.assertEqual(evidence['pkcs11Calls'],[{'method':'C_Login','rv':'00000000'},{'method':'C_SignInit','rv':'00000000'},{'method':'C_Sign','rv':'00000030'}])
        self.exercise(subprocess.CompletedProcess([],1,b'',raw),'^Cryptographic operation failed; no retry$')
        self.assertEqual(len(chat_bridge.crypto_evidence(b'IWA_CRYPTO_PKCS11=C_Sign:00000030\n'*20)['pkcs11Calls']),16)
        self.assertEqual(chat_bridge.crypto_evidence(b'IWA_CRYPTO_PKCS11=C_Reset:00000030\nIWA_CRYPTO_PKCS11=C_Sign:00000030 secret\n'),{})
        self.assertIsNone(chat_bridge.evidence_fields({'pkcs11Calls':[{'method':'C_Sign','rv':'00000030','pin':'sensitive-example'}]}))

    def test_pcsc_success_and_failure_metadata_never_accept_body_data(self):
        raw=b'IWA_CRYPTO_PCSC=SCardTransmit:00000000:17:2:6985\nIWA_CRYPTO_PCSC=SCardTransmit:80100016:6500\n'
        rows=chat_bridge.crypto_evidence(raw)['pcscCalls']
        self.assertEqual(rows,[{'method':'SCardTransmit','rv':'00000000','elapsed_ms':17,'responseLength':2,'statusWord':'6985'},{'method':'SCardTransmit','rv':'80100016','elapsed_ms':6500}])
        self.exercise(subprocess.CompletedProcess([],0,json.dumps(self.response()).encode(),raw))
        self.assertEqual(len(chat_bridge.crypto_evidence(raw*70)['pcscCalls']),96)
        for bad in [b'IWA_CRYPTO_PCSC=SCardTransmit:80100016:10:2:9000',b'IWA_CRYPTO_PCSC=SCardTransmit:00000000:10:1:9000',b'IWA_CRYPTO_PCSC=SCardTransmit:00000000:120001',b'IWA_CRYPTO_PCSC=SCardTransmit:00000000:10:65537',b'IWA_CRYPTO_PCSC=SCardTransmit:00000000:10:2:9000 sensitive-example']:
            self.assertEqual(chat_bridge.crypto_evidence(bad),{})
        self.assertIsNone(chat_bridge.evidence_fields({'pcscCalls':[{**rows[0],'data':'sensitive-example'}]}))
