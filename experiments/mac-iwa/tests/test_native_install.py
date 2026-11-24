"""Packaging boundaries: no Java/mail runtime and no enrollment mutation."""
import importlib.util,json,tempfile,unittest,subprocess
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
        with patch.object(installer,'ROOT',source),patch.object(installer,'validate_crypto_binary') as validate:
            installer.install_code(destination,binary)
            validate.assert_called_once_with(binary)
        self.assertEqual({p.name for p in (destination/'native').iterdir()},set(installer.NATIVE_MODULES))
        self.assertEqual((destination/'runtime/sequoia-iwa-crypto').read_bytes(),binary.read_bytes())
        self.assertEqual(enrollment.read_bytes(),before)
        self.assertEqual(legacy.read_text(),'preserve local evidence')
        self.assertFalse((destination/'runtime/java').exists())
        self.assertFalse((destination/'runtime/chat').exists())

    def test_production_capabilities_reject_oracle_legacy_and_unexpected_routes(self):
        good={'service':'sequoia-iwa-hardware','version':1,'testOracle':False,
              'operations':sorted(installer.PRODUCTION_OPERATIONS)}
        with patch.object(installer.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(good).encode())) as run:
            installer.validate_crypto_binary('/built/worker')
            self.assertEqual(run.call_args.args[0],['/built/worker','--capabilities'])
            self.assertEqual(run.call_args.kwargs['input'],b'')
        for value in ({'service':'sequoia-iwa-test-oracle','version':1,'testOracle':True},
                      dict(good,operations=good['operations']+['seal']),
                      dict(good,operations=good['operations'][:-1]),dict(good,version=True),
                      dict(good,testOracle=True),dict(good,extra='unexpected'),[]):
            with self.subTest(value=value),patch.object(installer.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(value).encode())),self.assertRaises(ValueError):
                installer.validate_crypto_binary('/built/worker')
        with patch.object(installer.subprocess,'run',side_effect=subprocess.TimeoutExpired(['wrong-binary'],10,output=b'private data')),self.assertRaisesRegex(ValueError,'^Expected the production'):
            installer.validate_crypto_binary('/built/worker')

    def test_rejected_binary_does_not_modify_installation(self):
        destination=self.root/'destination'
        with patch.object(installer,'validate_crypto_binary',side_effect=ValueError('test oracle')):
            with self.assertRaises(ValueError):installer.install_code(destination,self.root/'wrong-binary')
        self.assertFalse(list((destination/'native').iterdir()))
        self.assertFalse(list((destination/'runtime').iterdir()))


if __name__=='__main__':unittest.main()
