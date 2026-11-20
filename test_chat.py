"""Offline integration and adversarial tests with real Sequoia, no Google login."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import chat


class ChatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.umask(0o077)
        cls.temp = tempfile.TemporaryDirectory(prefix='standalone-chat-tests-')
        cls.root = Path(cls.temp.name)
        cls.keys = {}
        for level in ('3', '5'):
            for who in ('alice', 'bob'):
                path = cls.root/(level+'-'+who)
                info = chat.generate(path, who+'@example.test', level, test_only=True)
                cls.keys[level, who] = (path, info)

    @classmethod
    def tearDownClass(cls):
        # Disposable fixtures are removed even when a test fails; they are not
        # credentials to be backed up, distributed, or used for real messages.
        cls.temp.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.root))

    def prepare(self, level='3', compression='zip'):
        alice, a = self.keys[level, 'alice']
        bob, b = self.keys[level, 'bob']
        payload = self.work/'attachment.dat'
        payload.write_bytes(bytes(range(256))*384)
        output = self.work/'outgoing'
        chat.pack(alice, bob/'public.pgp', b['fingerprint'], 'alice@example.test', 'bob@example.test',
                  'Synthetic bundle', 'Plain alternative', '<p><b>HTML alternative</b></p>', [payload],
                  output, compression, batch=True)
        return alice, a, bob, b, output, payload

    def test_hybrid_round_trips(self):
        for level in ('3', '5'):
            for compression in ('zip', 'zlib'):
                with self.subTest(level=level, compression=compression):
                    self.setUp()
                    alice, a, bob, b, out, payload = self.prepare(level, compression)
                    target = self.work/'received'
                    result = chat.unpack(bob, out/'message.pgp', alice/'public.pgp', a['fingerprint'],
                                         'alice@example.test', 'bob@example.test', target, batch=True)
                    self.assertTrue(result['signature_valid'])
                    self.assertEqual((target/'attachment-01.bin').read_bytes(), payload.read_bytes())
                    self.assertIn('Plain alternative', (target/'body.txt').read_text())
                    self.assertIn('<b>HTML alternative</b>', (target/'body-html-source.txt').read_text())
                    self.assertFalse(any(out.glob('.compose-*')))
                    self.assertFalse(any(target.glob('.verify-*')))

    def test_mixed_certificate_uses_only_hybrid_subkeys(self):
        alice, info = self.keys['3', 'alice']
        mixed_secret = self.work/'mixed-secret.pgp'
        chat.sq('key', 'subkey', 'add', '--cert-file', alice/'secret.pgp',
                '--cipher-suite', 'cv25519', '--can-encrypt', 'transport',
                '--without-password', '--output', mixed_secret, batch=True)
        mixed_public = self.work/'mixed-public.pgp'
        chat.sq('key', 'delete', '--cert-file', mixed_secret, '--output', mixed_public, batch=True)
        self.assertTrue(any(a.startswith('Classical') for a in chat.public_info(mixed_public)['algorithms']))
        filtered = self.work/'filtered.pgp'
        filtered.write_bytes(chat.hybrid_public(mixed_public))
        self.assertEqual(chat.public_info(filtered)['fingerprint'], info['fingerprint'])
        self.assertTrue(all(a in chat.ALGORITHMS.values() for a in chat.public_info(filtered)['algorithms']))
        bob, b = self.keys['3', 'bob']
        out = self.work/'mixed-outgoing'
        chat.pack(bob, mixed_public, info['fingerprint'], 'bob@example.test', 'alice@example.test',
                  'Hybrid selection', 'synthetic', None, [], out, batch=True)
        result = chat.unpack(alice, out/'message.pgp', bob/'public.pgp', b['fingerprint'],
                             'bob@example.test', 'alice@example.test', self.work/'mixed-open', batch=True)
        self.assertTrue(result['signature_valid'])

    def test_wrong_signer_fails_without_exposing_plaintext(self):
        alice, a, bob, b, out, _ = self.prepare()
        target = self.work/'rejected'
        with self.assertRaises(ValueError):
            chat.unpack(bob, out/'message.pgp', bob/'public.pgp', b['fingerprint'],
                        'bob@example.test', 'bob@example.test', target, batch=True)
        self.assertFalse((target/'verified.mime').exists())
        self.assertEqual(list(target.iterdir()), [])

    def test_tampering_fails_without_plaintext(self):
        alice, a, bob, b, out, _ = self.prepare()
        data = bytearray((out/'message.pgp').read_bytes()); data[-32] ^= 1
        (out/'message.pgp').write_bytes(data)
        target = self.work/'rejected'
        with self.assertRaises(ValueError):
            chat.unpack(bob, out/'message.pgp', alice/'public.pgp', a['fingerprint'],
                        'alice@example.test', 'bob@example.test', target, batch=True)
        self.assertFalse((target/'verified.mime').exists())

    def test_full_fingerprint_required(self):
        alice, info = self.keys['3', 'alice']
        for fp in ('BAD', '0'*64, info['fingerprint'][-16:]):
            with self.assertRaises(ValueError):
                chat.check_cert(alice/'public.pgp', 'alice@example.test', fp)

    def test_no_secret_material_in_public_attachment(self):
        alice, _ = self.keys['3', 'alice']
        with self.assertRaises(ValueError):
            chat.public_info(alice/'secret.pgp')

    def test_wrong_signed_recipient_fails(self):
        raw = chat.mime_bytes('alice@example.test', 'mallory@example.test', 'test', 'text')
        with self.assertRaises(ValueError):
            chat.inspect_mime(raw, 'alice@example.test', 'bob@example.test')

    def test_header_injection_fails(self):
        with self.assertRaises(ValueError):
            chat.mime_bytes('alice@example.test', 'bob@example.test', 'hello\r\nBcc: mallory@example.test', 'body')

    def test_send_uses_two_uploads_and_fixed_caption(self):
        alice, a, bob, b, out, _ = self.prepare()
        calls = []
        def fake(*args, **kwargs):
            calls.append(args)
            if args[:3] == ('chat', 'media', 'upload'):
                return {'attachmentDataRef': {'attachmentUploadToken': 'synthetic-upload-'+str(len(calls))}}
            return {'name': 'spaces/TEST/messages/123'}
        with patch.object(chat, 'gws', fake):
            result = chat.send('spaces/TEST', out, confirm=True)
            with self.assertRaises(ValueError):
                chat.send('spaces/TEST', out, confirm=True)
        self.assertEqual(len(calls), 4)
        self.assertEqual(result['sent'], 'spaces/TEST/messages/123')
        body = json.loads(calls[-1][calls[-1].index('--json')+1])
        self.assertNotIn('Synthetic bundle', body['text'])
        self.assertNotIn('Plain alternative', json.dumps(calls))
        self.assertEqual(len(body['attachment']), 1)
        self.assertIn('Certificate message: spaces/TEST/messages/123', body['text'])

    def test_linked_certificate_checks_conversation_and_sender(self):
        result = {'name':'spaces/TEST/messages/bundle', 'sender':{'name':'users/alice'},
                  'text':'PQ Mail signed OpenPGP bundle. Certificate message: spaces/TEST/messages/cert'}
        with patch.object(chat, 'gws', return_value={'sender':{'name':'users/alice'}}):
            chat.linked_certificate_message(result)
        with patch.object(chat, 'gws', return_value={'sender':{'name':'users/other'}}):
            with self.assertRaises(ValueError): chat.linked_certificate_message(result)
        result['text']='Certificate message: spaces/OTHER/messages/cert'
        with patch.object(chat, 'gws') as call:
            with self.assertRaises(ValueError): chat.linked_certificate_message(result)
            call.assert_not_called()

    def test_receive_rejects_arbitrary_download_url(self):
        def fake(*args, **kwargs):
            return {'attachment': [{'contentName': 'message.pgp', 'downloadUri': 'https://evil.invalid/secret'}]}
        with patch.object(chat, 'gws', fake):
            with self.assertRaises(ValueError):
                chat.receive('spaces/TEST/messages/123', self.work/'download')

    def test_transfer_staging_stays_in_isolated_profile(self):
        source = self.work/'message.pgp'
        source.write_bytes(b'synthetic encrypted payload')
        calls = []
        def fake_run(argv, output=None, cap=None):
            if '--upload' in argv:
                staged = Path(argv[argv.index('--upload')+1])
                self.assertEqual(staged.read_bytes(), source.read_bytes())
                self.assertTrue(str(staged).startswith(str(self.work/'private/profiles/test')))
                calls.append(staged)
            if output:
                Path(output).write_bytes(b'synthetic download')
            return b'{"ok":true}'
        with patch.object(chat, 'ROOT', self.work), patch.dict(os.environ, {'GWS_CHAT_PROFILE':'test'}), patch.object(chat, 'run', fake_run):
            chat.gws('chat', 'media', 'upload', '--upload', str(source))
            downloaded=self.work/'received.pgp'
            chat.gws('chat', 'media', 'download', '--output', str(downloaded), output=downloaded)
            self.assertEqual(downloaded.read_bytes(), b'synthetic download')
        self.assertTrue(calls)
        self.assertFalse(calls[0].exists())
        self.assertFalse(list((self.work/'private/profiles/test').glob('.transfer-*')))

    def test_bounded_file_read(self):
        p = self.work/'too-big'; p.write_bytes(b'abc')
        with self.assertRaises(ValueError):
            chat.read(p, 2)

    def test_paths_and_overwrites_rejected(self):
        for value in ('spaces/../accounts', 'https://evil.invalid', 'spaces/test?x=1'):
            with self.assertRaises(ValueError): chat.space_name(value)
        p = self.work/'original'; p.write_bytes(b'original')
        with self.assertRaises(FileExistsError): chat.write_new(p, b'new')
        self.assertEqual(p.read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main(verbosity=2)
