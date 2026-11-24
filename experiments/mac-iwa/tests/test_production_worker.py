"""Exercise the installed worker's executable boundary without a device.

The test supplies deliberately unusable adapter paths and synthetic PIN text.
Retired message modes must fail at dispatch, before looking at those fields.
The separate oracle is opt-in and can never satisfy the installer's contract.
"""
import importlib.util,json,os,subprocess,unittest
from pathlib import Path

root=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('production_installer',root/'install_native.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


@unittest.skipUnless(os.environ.get('IWA_CRYPTO_TEST_BIN'),'Set IWA_CRYPTO_TEST_BIN to the production worker')
class ProductionWorkerBoundary(unittest.TestCase):
    def setUp(self):
        self.binary=os.environ['IWA_CRYPTO_TEST_BIN']

    def test_capabilities_are_public_and_accepted_by_installer(self):
        # No installed config, backend, certificate or token is supplied.
        installer.validate_crypto_binary(self.binary)

    def test_message_and_fixture_modes_are_rejected_without_private_input(self):
        for operation in ('seal','open','sign-browser','open-browser',
                          'decapsulate-browser','verify-detached','check-ciphertext','generate'):
            with self.subTest(operation=operation):
                request={'op':operation,'pin':'SYNTHETIC-PIN',
                         'config':{'adapters':'/no-such-test-backend'},'payload':'TEST'}
                result=subprocess.run([self.binary],input=json.dumps(request).encode(),
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')
                self.assertEqual(result.stderr,b'IWA_CRYPTO_STATUS=CRYPTO_FAILED\n')

    def test_arbitrary_command_line_arguments_are_not_operations(self):
        result=subprocess.run([self.binary,'--test-oracle'],input=b'',
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')

    @unittest.skipUnless(os.environ.get('IWA_CRYPTO_ORACLE_BIN'),'Build the message_oracle example explicitly')
    def test_test_oracle_cannot_be_installed_as_hardware_worker(self):
        with self.assertRaisesRegex(ValueError,'production hardware worker'):
            installer.validate_crypto_binary(os.environ['IWA_CRYPTO_ORACLE_BIN'])


if __name__=='__main__':unittest.main()
