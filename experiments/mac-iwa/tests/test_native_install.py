"""Packaging boundaries: no Java/mail runtime and no enrollment mutation."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('native_installer',Path(__file__).parents[1]/'install_native.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


class NativeInstallation(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        for name in ('backend/native','backend/adapters','source/native','destination/native','destination/runtime','destination/private'):
            (self.root/name).mkdir(parents=True,exist_ok=True)
        for name in ('ykman','public.asc'):(self.root/name).write_text('synthetic public fixture')
        self.config={'serial':'123456','ykman':str(self.root/'ykman'),
                     'app':str(self.root/'backend'),'cert':str(self.root/'public.asc'),
                     'chat_email':'owner@example.test'}

    def test_minimal_hardware_enrollment_needs_no_java_or_standalone_cli(self):
        installer.validate(self.config)
        for name,value in [('runner','/unreviewed/runner'),('java','/unused/java'),
                           ('classpath','/unused/classes'),('command','generate')]:
            with self.subTest(name=name),self.assertRaises(ValueError):
                installer.validate(dict(self.config,**{name:value}))
        for serial in ('0','00123456','2147483648','123456; reset'):
            with self.subTest(serial=serial),self.assertRaises(ValueError):
                installer.validate(dict(self.config,serial=serial))

    def test_allowlisted_copy_excludes_transport_and_preserves_existing_data(self):
        source=self.root/'source';destination=self.root/'destination'
        for name in installer.NATIVE_MODULES:(source/'native'/name).write_text('# active hardware service\n')
        for name in ('gmail_bridge.py','cert_store.py','unexpected_transport.py'):
            (source/'native'/name).write_text('# must not be installed\n')
        binary=self.root/'built-crypto';binary.write_bytes(b'synthetic executable')
        enrollment=destination/'private/config.json';enrollment.write_text(json.dumps(self.config))
        legacy=destination/'runtime/old-result.txt';legacy.write_text('preserve local evidence')
        before=enrollment.read_bytes()
        with patch.object(installer,'ROOT',source):installer.install_code(destination,binary)
        self.assertEqual({p.name for p in (destination/'native').iterdir()},set(installer.NATIVE_MODULES))
        self.assertEqual((destination/'runtime/sequoia-iwa-crypto').read_bytes(),binary.read_bytes())
        self.assertEqual(enrollment.read_bytes(),before)
        self.assertEqual(legacy.read_text(),'preserve local evidence')
        self.assertFalse((destination/'runtime/java').exists())
        self.assertFalse((destination/'runtime/chat').exists())


if __name__=='__main__':unittest.main()
