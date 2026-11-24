#!/usr/bin/env python3
"""Single-PIN, bounded PIV diagnostic suite. No mail, provisioning or vault edits.

A hidden Terminal prompt authorizes this entire run, not subsequent app use.
Every operation uses an explicitly supplied test-only message oracle and a fresh
PKCS#11 process/session. The installed production helper rejects these modes.
The PIN exists only in this process and anonymous child pipes; no argv/env/file
contains it. Python/OS copies cannot be guaranteed wiped, so the runner exits
when finished. FIDO PRF ceremonies and browser UI tests are deliberately excluded.
"""
import argparse,base64,fcntl,getpass,hashlib,importlib.util,json,os,subprocess,time,uuid
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent

def module(path):
    spec=importlib.util.spec_from_file_location('piv_readonly_snapshot',path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def request(command,value,timeout=150):
    # Never expose CalledProcessError/TimeoutExpired objects: they may retain
    # stdin/stdout secrets. Only a closed status code is propagated to reports.
    try:
        p=subprocess.run(command,input=json.dumps(value).encode(),stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,timeout=timeout)
    except subprocess.TimeoutExpired:raise RuntimeError('HELPER_TIMEOUT') from None
    if p.returncode:
        allowed={'MLKEM_FAILED','X25519_FAILED','ADAPTER_TIMEOUT_OR_INPUT',
                 'MLKEM_RESPONSE_SIZE','X25519_RESPONSE_SIZE','CRYPTO_FAILED'}
        code=next((c for c in sorted(allowed) if ('IWA_CRYPTO_STATUS='+c).encode() in p.stderr.splitlines()),'OPERATION_FAILED')
        raise RuntimeError(code)
    if len(p.stdout)>1048576:raise RuntimeError('OUTPUT_LIMIT')
    try:return json.loads(p.stdout)
    except (ValueError,UnicodeError):raise RuntimeError('INVALID_RESPONSE') from None

def no_touch(before):
    # Do not assume the user's key configuration: unattended loops require
    # explicit Never policies on every private component used by this suite.
    for slot in ('9c','84','9d','85'):
        lines=before['slots'][slot].get('metadata','').lower().splitlines()
        if not any('touch policy:' in line and line.split(':',1)[1].strip()=='never' for line in lines):
            raise RuntimeError('Touch policy is not Never in slot '+slot+'; no test started')

def run_rounds(rounds,step,deadline):
    for number in range(1,rounds+1):
        if time.monotonic()>deadline:raise RuntimeError('RUN_AUTHORIZATION_EXPIRED')
        step(number) # A failure propagates immediately; no retry/next round.

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--installed',type=Path,required=True)
    p.add_argument('--oracle',type=Path,required=True,help='Separately built message_oracle test example')
    p.add_argument('--serial',required=True)
    p.add_argument('--node',type=Path,required=True)
    p.add_argument('--rounds',type=int,default=5,choices=range(1,21))
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    # Validate the diagnostic marker before snapshots, PIN entry or operations.
    # The production binary intentionally cannot serve the old message API.
    marker=subprocess.run([str(a.oracle.resolve(strict=True)),'--capabilities'],
                          input=b'',stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    if marker.returncode or len(marker.stdout)>8192 or json.loads(marker.stdout)!={
            'service':'sequoia-iwa-test-oracle','version':1,'testOracle':True}:
        raise RuntimeError('Explicit message_oracle executable required; no test started')
    cfg=json.loads((a.installed/'private/config.json').read_text())
    if cfg['serial']!=a.serial:raise RuntimeError('Configured serial mismatch; no test started')
    a.out.mkdir(parents=True,exist_ok=False,mode=0o700)
    report={'serial':a.serial,'rounds_requested':a.rounds,'operations':[],
            'passed':False,'unchanged':False,'pin_storage':'run memory only'}
    pin=bytearray();before=None
    snapshot=module(Path(cfg['runner'])).snapshot
    # Use the same lock as native Chat/Vault operations. Separate windows must
    # not compete for a smart-card transaction while this diagnostic runs.
    with (a.installed/'private/chat-state/operation.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            before=snapshot(SimpleNamespace(**cfg));no_touch(before)
            (a.out/'before.json').write_text(json.dumps(before,indent=2))
            # The adapter utility exports expected SPKI components without PIN.
            subprocess.run([cfg['binary'],'inspect',cfg['cert'],str(a.out)],check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            for slot in ('9c','84','9d','85'):
                expected=hashlib.sha256((a.out/('expected-'+slot+'.der')).read_bytes()).hexdigest()
                if expected!=before['slots'][slot].get('sha256'):raise RuntimeError('PUBLIC_KEY_MISMATCH')
            cert=base64.b64encode(Path(cfg['cert']).read_bytes()).decode()
            app=Path(cfg['app']);backend={'python':'/usr/bin/python3','adapters':str(app/'adapters'),
                'openssl':str(app/'native/bin/openssl'),'provider':str(app/'native/lib/pkcs11.dylib'),
                'module':str(app/'native/lib/libykcs11.dylib'),'serial':a.serial}
            crypto=[str(a.oracle.resolve(strict=True))]
            wasm=[str(a.node),str(ROOT/'tests/vault-hardware.mjs')]
            print(f'Confirmed {a.serial}, matching public keys and no-touch policies. {a.rounds} rounds; one PIN; stop on any failure.',flush=True)
            # No getpass fallback to visible stdin is allowed.
            if not os.isatty(0):raise RuntimeError('Run in a local Terminal')
            text=getpass.getpass('YubiKey PIN (cached only for this test run): ')
            pin.extend(text.encode('ascii'));del text
            if not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):raise RuntimeError('Invalid local PIN format')
            deadline=time.monotonic()+900
            def invoke(op,payload):
                if time.monotonic()>deadline:raise RuntimeError('RUN_AUTHORIZATION_EXPIRED')
                v={'op':op,'pin':pin.decode('ascii'),'own':cert,'peer':cert,
                   'payload':payload,'config':backend}
                start=time.monotonic()
                try:
                    result=request(crypto,v)
                    report['operations'].append({'op':op,'status':'OK','ms':round((time.monotonic()-start)*1000)})
                    return result
                except RuntimeError as error:
                    report['operations'].append({'op':op,'status':str(error),'ms':round((time.monotonic()-start)*1000)})
                    raise
                finally:v.pop('pin',None)
            def step(number):
                # Synthetic MIME contains both representations and exact binary
                # attachment bytes; compare the whole payload after verification.
                from email.message import EmailMessage
                from email.policy import SMTP
                msg=EmailMessage(policy=SMTP);msg['Subject']='PIV diagnostic '+str(number)
                msg.set_content('Synthetic PIV test');msg.add_alternative('<p>Synthetic <b>PIV</b> test</p>',subtype='html')
                msg.add_attachment(bytes(range(256)),maintype='application',subtype='octet-stream',filename='test.bin')
                raw=msg.as_bytes();encoded=base64.b64encode(raw).decode()
                sealed=invoke('seal',encoded)['data']
                opened=invoke('open',sealed)['data'] # Sequoia requires a valid hybrid signature.
                if base64.b64decode(opened)!=raw:raise RuntimeError('MESSAGE_BYTES_MISMATCH')
                # Fresh WASM envelope and session key per round; no real vault is
                # read or changed. Historical full-message oracle, separate from the IWA component path.
                seed=base64.b64encode(os.urandom(32)).decode();vid=str(uuid.uuid4());wid=str(uuid.uuid4())
                wrapped=request(wasm,{'op':'wrap','certificate':cert,'secret':seed,'vaultId':vid,'wrapperId':wid})
                session=invoke('decapsulate-browser',wrapped['cipher'])
                result=request(wasm,{'op':'unwrap',**wrapped,**session,'sessionKey':session['data'],
                    'vaultId':vid,'wrapperId':wid,'expected':seed})
                if result.get('passed') is not True:raise RuntimeError('VAULT_VALIDATION_FAILED')
                print(f'PASS round {number}: hybrid signing, message decryption/verification, exact MIME/attachment bytes, WASM vault unwrap and negative binding tests',flush=True)
            run_rounds(a.rounds,step,deadline);report['passed']=True
        except BaseException as error:
            # Report only known status messages; never serialize subprocess
            # exceptions, requests, PINs, session keys or native diagnostics.
            report['error']=str(error) if type(error) is RuntimeError else type(error).__name__
            print('STOPPED; no further private operations. See result.json.',flush=True)
        finally:
            pin[:]=b'\0'*len(pin)
            if before is not None:
                try:
                    after=snapshot(SimpleNamespace(**cfg))
                    (a.out/'after.json').write_text(json.dumps(after,indent=2))
                    report['unchanged']=before==after
                except Exception:report['snapshot_error']='After snapshot unavailable; unchanged status unconfirmed'
            (a.out/'result.json').write_text(json.dumps(report,indent=2))
            print('Results: '+str(a.out),flush=True)
    return 0 if report['passed'] and report['unchanged'] else 1

if __name__=='__main__':raise SystemExit(main())
