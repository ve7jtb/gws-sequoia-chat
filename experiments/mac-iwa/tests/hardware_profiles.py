#!/usr/bin/env python3
"""Stage or run read-only-card profile tests through the real IWA worker.

Default mode performs public verification only. --run-hardware explicitly
permits one native-PIN signing and one native-PIN decryption per selected profile.
No provision/write/reset/import/policy API or email transport is available.
The browser owns packet construction/verification; native retains its independent
live-key authorization, single-use grants, PIN prompt and private operations.
"""
import argparse,base64,fcntl,json,os,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'native'))
from chat_bridge import ChatBridge,MESSAGE_STATUS
from identities import preview,companion_preview,run_public,checked_serial
from host import operation_error

ALLOWED={'chat-identity-bundle-read','chat-identity-companion-read','chat-identity-key-snapshot','chat-hardware-audit',
         'chat-selected-signing-material','chat-selected-decryption-material',
         'chat-sign-digest','chat-decapsulate-components'}
ORDINARY_PROFILES=('level3','level3-v4-hybrid','level3-v4-classical','level3-v5-hybrid',
                  'level5-v6-classical','level5-v4-hybrid-p384','level5-v4-classical-p384')

def isolated_configuration(original_config,backend_app=None):
    """Apply one explicit local diagnostic override to an in-memory copy.

    The command-line operator reviews/stages the backend directory separately.
    This is not an IWA/native-message option: no request field can select it,
    and no installed configuration or vault enrollment is written. Backend
    hashes still bind the selected files into each production one-use grant.
    """
    cfg=json.loads(original_config)
    if backend_app is not None:
        directory=Path(backend_app).resolve(strict=True)
        if not directory.is_dir():raise ValueError('Diagnostic backend app must be a directory')
        cfg['app']=str(directory)
    return cfg

def configuration_audit(original_bytes,current_bytes,expected_isolated,current_isolated):
    """Audit installed bytes and the reviewed runtime copy independently."""
    return {'installedConfigurationUnchanged':current_bytes==original_bytes,
            'isolatedConfigurationUnchanged':current_isolated==expected_isolated}

def selected_profiles(value,companion):
    """Keep diagnosis a closed profile choice, never an arbitrary backend."""
    profiles=value.split(',') if value else ['LEVEL5_COMPANION'] if companion else list(ORDINARY_PROFILES[:4])
    allowed=('LEVEL5_COMPANION',) if companion else ORDINARY_PROFILES
    if not profiles or len(set(profiles))!=len(profiles) or any(p not in allowed for p in profiles):
        raise ValueError('Unsupported test profiles')
    return profiles

def authorize_request(op,request,serial,companion):
    """Constrain the test pipe before the production native schema/grant gate.

    The installed default serial belongs to the existing vault enrollment. It
    must not be rewritten to test a different card. Every public read and every
    selected grant names this run's serial; private calls redeem those one-use
    grants using the unchanged production ChatBridge authorization path.
    """
    if op not in ALLOWED or not isinstance(request,dict) or 'op' in request:
        raise ValueError('Unexpected native test request')
    if op in ('chat-identity-bundle-read','chat-identity-key-snapshot','chat-identity-companion-read'):
        if request.get('serial')!=serial:raise ValueError('Wrong selected test serial')
        if (op=='chat-identity-companion-read')!=companion:raise ValueError('Wrong public storage mode')
    if op in ('chat-hardware-audit','chat-selected-signing-material','chat-selected-decryption-material'):
        if not isinstance(request.get('identity'),dict) or request['identity'].get('serial')!=serial:
            raise ValueError('Wrong selected test identity')
    if request.get('service')=='Vault':raise ValueError('Vault access is outside this isolated test')

def public_preflight(bridge,serial,email,profiles,companion,certificate):
    """Verify signed public metadata without PINs, enrollment or account use."""
    checked=companion_preview(bridge,serial,certificate) if companion else preview(bridge,selected_serial=serial,compatibility_certificate=certificate)
    rows=[{'kind':'openpgp','profile':checked['profile'],'certificate':checked['certificate']}] if companion else checked['certificates']
    if not set(profiles)<={c['profile'] for c in rows if c['kind']=='openpgp'}:
        raise ValueError('Requested profiles are not authenticated by current card bundle')
    for item in rows:
        if item['kind']=='openpgp' and item['profile'] in profiles:
            public=run_public(bridge,{'op':'identity-canonical','certificate':item['certificate']})
            if email not in public['emails']:raise ValueError('Selected test email is not certified')
    return checked

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('installed','crypto-bin','node','out'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--backend-app',type=Path,help='Explicitly reviewed backend directory for this isolated diagnostic only; never changes installed configuration')
    parser.add_argument('--pin-prompt',type=Path,help='Reviewed native PIN dialog candidate; frozen into this isolated run, never exposed as a browser option')
    parser.add_argument('--serial',required=True);parser.add_argument('--email',required=True)
    parser.add_argument('--compatibility-certificate',type=Path)
    parser.add_argument('--companion',action='store_true',help='Test the existing Level 5 encrypted companion in disposable WASM')
    parser.add_argument('--companion-certificate',type=Path,help='Optional public certificate cache for ultra-compact storage')
    parser.add_argument('--profiles')
    parser.add_argument('--run-hardware',action='store_true')
    args=parser.parse_args();os.umask(0o077)
    config_path=args.installed/'private/config.json';original_config=config_path.read_bytes()
    cfg=isolated_configuration(original_config,args.backend_app)
    # Snapshot after the sole reviewed override, before any bridge method can
    # run. Compare against this independent value even on failed/cancelled runs.
    expected_cfg=json.loads(json.dumps(cfg))
    checked_serial(args.serial);profiles=selected_profiles(args.profiles,args.companion)
    if args.companion and args.compatibility_certificate or not args.companion and args.companion_certificate:
        raise ValueError('Public certificate cache does not match selected storage mode')
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    for directory in ('runtime','build','private'):(out/directory).mkdir(mode=0o700)
    # Freeze the reviewed executable for the whole run. A concurrent developer
    # build cannot change the bytes bound into an in-flight authorization grant.
    shutil.copy2(args.crypto_bin.resolve(),out/'runtime/sequoia-iwa-crypto')
    # A wording-only prompt candidate can be tested without replacing the
    # installed helper. Freeze its bytes just like the reviewed crypto worker;
    # a concurrent rebuild must not substitute a different credential dialog.
    if args.pin_prompt:
        shutil.copy2(args.pin_prompt.resolve(strict=True),out/'build/pin-prompt')
    else:
        (out/'build/pin-prompt').symlink_to((args.installed/'build/pin-prompt').resolve(strict=True))
    def progress(event):
        if event.get('type')=='progress':
            print(event['message'],flush=True)
            if event.get('stage') in ('PIN_DIALOG_STARTED','PIN_DIALOG_TIMEOUT','PIN_REJECTED_LOCALLY','PIN_RECEIVED_LOCALLY','PRIVATE_WORKER_STARTED'):
                # Fixed status names prove whether the private worker started;
                # no PIN, request, signature or shared secret is recorded.
                report.setdefault('operationStages',[]).append({'stage':event['stage'],'operation':event['operation']})
                if event['stage']=='PRIVATE_WORKER_STARTED':report['cryptoWorkersStarted']+=1
            if event.get('stage')=='PRIVATE_OPERATION_DIAGNOSTIC' and event.get('status') in MESSAGE_STATUS and event.get('operation') in ('sign-digest','decapsulate-components'):
                report.setdefault('nativePhases',[]).append({'operation':event['operation'],'status':event['status']})
    bridge=ChatBridge(out,cfg,progress)
    guard=(args.installed/'private/chat-state/operation.lock').open('rb')
    fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
    cache=args.companion_certificate if args.companion else args.compatibility_certificate
    certificate=base64.b64encode(cache.read_bytes()).decode() if cache else None
    child=None;report={'passed':False,'hardwareWritesRequested':0,'emailsSent':0,'profiles':profiles,'serial':args.serial,'companion':args.companion,'backendAppOverrideUsed':args.backend_app is not None,'privateRequestsStarted':0,'cryptoWorkersStarted':0}
    try:
        checked=public_preflight(bridge,args.serial,args.email,profiles,args.companion,certificate)
        # An encrypted companion remains in memory except for production
        # one-use public grants in this isolated result directory. Persist only
        # public hashes/profile metadata in the diagnostic preflight file.
        saved={k:checked[k] for k in ('format','version','serial','profile','companionHash')} if args.companion else checked
        (out/'public-preview.json').write_text(json.dumps(saved,indent=2))
        if not args.run_hardware:
            report.update(passed=True,preflightOnly=True);print('PASS public profile preflight; no PIN or private operation.',flush=True);return
        print('Hardware run: one PIN for signing and one for decryption per profile. Touch only as required by existing policies.',flush=True)
        child=subprocess.Popen([str(args.node.resolve()),str(ROOT/'tests/hardware-profiles-node.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        start={'type':'start','serial':args.serial,'email':args.email,'profiles':profiles,'companion':args.companion}
        if certificate:start['companionCertificate' if args.companion else 'compatibilityCertificate']=certificate
        child.stdin.write(json.dumps(start)+'\n');child.stdin.flush()
        complete=False;private_failed=False
        for line in child.stdout:
            if len(line)>500000:raise ValueError('Worker protocol limit')
            event=json.loads(line)
            if event.get('type')=='native':
                op=event.get('op');request=event.get('request')
                authorize_request(op,request,args.serial,args.companion)
                if private_failed and op!='chat-hardware-audit':raise ValueError('Only final public audit allowed after private failure')
                if op in ('chat-sign-digest','chat-decapsulate-components'):
                    report['privateRequestsStarted']+=1
                    if report['privateRequestsStarted']>2*len(profiles):raise ValueError('Private operation count exceeded; no retry')
                # The returned shares/signatures go directly to the retained
                # worker state. Neither request nor response is logged to disk.
                try:
                    value=bridge.action({'op':op,**request})
                    response={'type':'native-result','id':event['id'],'value':value}
                except Exception as error:
                    # Return only a fixed failure to let the IWA coordinator
                    # collect its final public unchanged-key audit. Never allow
                    # a second PIN/private attempt after an ambiguous failure.
                    private_failed=True
                    before_pin=isinstance(error,ValueError) and str(error) in ('PIN dialog timed out before submission','PIN cancelled or invalid')
                    report.setdefault('nativeFailures',[]).append({'operation':op,'beforePinSubmission':before_pin,'status':'PIN_DIALOG_TIMEOUT' if str(error)=='PIN dialog timed out before submission' else 'PIN_REJECTED_LOCALLY' if str(error)=='PIN cancelled or invalid' else 'NATIVE_OPERATION_STOPPED'})
                    print(operation_error(op,error),flush=True)
                    response={'type':'native-result','id':event['id'],'error':True}
                child.stdin.write(json.dumps(response)+'\n');child.stdin.flush()
            elif event.get('type')=='progress':
                print(str(event.get('profile',''))+': '+str(event.get('message',''))[:300],flush=True)
            elif event.get('type')=='report':
                report.setdefault('reports',[]).append(event['report'])
                (out/'result.json').write_text(json.dumps(report,indent=2))
            elif event.get('type')=='complete':
                if complete:raise ValueError('Duplicate completion')
                complete=True;report['reports']=event['reports']
            else:raise ValueError('Worker stopped; no automatic retry')
        if child.wait(timeout=15) or not complete:raise ValueError('Worker did not complete')
        reports=report['reports']
        if len(reports)!=len(profiles) or any(r.get('status')!='PASS' or r.get('unchanged') is not True for r in reports):raise ValueError('Hardware profile did not pass')
        report['passed']=True;print('PASS all requested hardware profiles. No mail or hardware writes.',flush=True)
    finally:
        if child is not None and child.poll() is None:child.terminate();child.wait(timeout=10)
        # Testing an alternate serial must not re-enroll the installed vault or
        # edit its configuration. Check bytes even if the crypto test failed.
        report.update(configuration_audit(original_config,config_path.read_bytes(),expected_cfg,bridge.cfg))
        if not report['installedConfigurationUnchanged'] or not report['isolatedConfigurationUnchanged']:report['passed']=False
        guard.close();(out/'result.json').write_text(json.dumps(report,indent=2));print('Results:',out,flush=True)

if __name__=='__main__':main()
