#!/usr/bin/env python3
"""One physical YubiKey signature through the browser WASM signing boundary.

Only public reads and one explicitly authorized composite signature are exposed.
No card provisioning, certificate write, policy operation or mail transport is
implemented. The existing native masked PIN dialog supplies the PIN directly to
the native helper in memory; this harness never reads or logs the PIN itself.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'native'))
from chat_bridge import ChatBridge


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def public_pin_state(cfg):
    """Save only the public retry counter; never provisioning credentials."""
    value=subprocess.check_output([cfg['ykman'],'--device',cfg['serial'],'piv','info'],stderr=subprocess.PIPE,timeout=30).decode()
    match=re.search(r'^PIN tries remaining:\s*(\d+)/(\d+)\s*$',value,re.M)
    if not match:raise RuntimeError('Could not read PIN retry state')
    return {'remaining':int(match[1]),'maximum':int(match[2])}


def backend_hashes(cfg):
    """Identify the unchanged installed PKCS#11 implementation under test."""
    app=Path(cfg['app'])
    paths=[app/'native/bin'/n for n in ('openssl','pqmail-pkcs11-sign','pqmail-pkcs11-kem')]
    paths += [app/'native/lib'/n for n in ('pkcs11.dylib','libykcs11.dylib')]
    paths += [app/'adapters'/n for n in ('pkcs11-mu.py','pkcs11-kem.py','ykman-mu.py')]
    return {str(p.relative_to(app)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('installed','node','crypto-bin','fixture-bin','out'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--serial',required=True)
    parser.add_argument('--preflight-only',action='store_true')
    a=parser.parse_args();os.umask(0o077)
    # This test is bound to the installed identity, not a caller-selected serial
    # substituted into its PKCS#11 configuration or a newly provisioned slot.
    cfg=json.loads((a.installed/'private/config.json').read_text())
    if cfg['serial']!=a.serial or not a.serial.isdecimal():raise RuntimeError('Configured serial differs; stopped before hardware access')
    out=a.out.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    snapshot_module=load_module('iwa_signing_snapshot',Path(cfg['runner']))
    before=None;child=None;guards=[];result={'passed':False,'serial':a.serial,'emailsSent':0,'hardwareWritesRequested':0,
        'scope':'actual browser worker in Node shim + native masked PIN/PKCS#11; not a live Chrome UI test'}
    def save(name,value):(out/name).write_text(json.dumps(value,indent=2))
    try:
        # Share the installed host's existing locks without writing their files.
        # A UI vault/signature/test already in progress must finish before this
        # test starts; do not compete for the card or create another PIN dialog.
        for name in ('private/test.lock','private/chat-state/operation.lock'):
            guard=(a.installed/name).open('rb')
            try:fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except Exception:guard.close();raise
            guards.append(guard)
        print('Reading all 24 PIV slot records before any private operation…',flush=True)
        before=snapshot_module.snapshot(SimpleNamespace(**cfg));save('before.json',before)
        pin_before=public_pin_state(cfg);save('pin-before.json',pin_before)
        hashes=backend_hashes(cfg);save('backend-before.json',hashes)
        if pin_before['remaining']!=pin_before['maximum']:
            raise RuntimeError('PIN retry counter is below its maximum; inspect before starting a private operation')
        # The existing adapter's inspect command is public-only and exports the
        # exact SPKIs expected for each component; compare full hashes to card.
        own=out/'sender-public.pgp';shutil.copyfile(cfg['cert'],own)
        inspect=out/'inspect';inspect.mkdir()
        subprocess.run([cfg['binary'],'inspect',str(own),str(inspect)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True,timeout=60)
        for slot in ('9c','84','9d','85'):
            expected=hashlib.sha256((inspect/('expected-'+slot+'.der')).read_bytes()).hexdigest()
            if before['slots'][slot].get('sha256')!=expected:raise RuntimeError('Public certificate mismatch in slot '+slot)
        print('PASS: installed public certificate matches existing 9c/84/9d/85 keys.',flush=True)
        if a.preflight_only:
            result.update(passed=True,preflightOnly=True);return

        # Make an isolated test host tree. It copies no account credentials or
        # contact store, and links only fixed executables/public parser helpers.
        for directory in ('runtime/chat/bin','private','build'):(out/directory).mkdir(parents=True,exist_ok=True)
        for name in ('chat.py','mail_transport.py'):
            shutil.copy2(a.installed/'runtime/chat'/name,out/'runtime/chat'/name)
        for name in ('sq','chat-software-identity'):
            (out/'runtime/chat/bin'/name).symlink_to((a.installed/'runtime/chat/bin'/name).resolve())
        (out/'runtime/sequoia-iwa-crypto').symlink_to(a.crypto_bin.resolve())
        (out/'build/pin-prompt').symlink_to((a.installed/'build/pin-prompt').resolve())
        fixture=out/'fixture'
        subprocess.run([str(a.fixture_bin.resolve()),'generate',str(fixture)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True,timeout=60)
        # The fixture generator also creates a software sender for its unit
        # tests. This physical test must never use it; remove that secret now.
        (fixture/'sender-secret.pgp').unlink()
        cfg={**cfg,'cert':str(own)}
        def progress(message):
            if message.get('type')=='progress':print(message['message'],flush=True)
        bridge=ChatBridge(out,cfg,progress)
        peer=fixture/'recipient-public.pgp';peer_info=bridge.chat.check_cert(peer,'recipient@example.invalid')
        fingerprint=peer_info['fingerprint'];contact={'id':'synthetic-hardware-recipient','email':'recipient@example.invalid','fingerprint':fingerprint}
        bridge.chat.write_new(bridge.data/(fingerprint+'.pgp'),peer.read_bytes())
        bridge.chat.write_new(bridge.data/'contact-synthetic.json',json.dumps(contact).encode())
        material=bridge.action({'op':'chat-browser-prepare','contact':contact['id'],
            'subject':'Physical YubiKey — WASM signing test','service':'Gmail','space':'Gmail'})
        print('One native PIN dialog follows. Touch only if the existing key policy requires it. No email is sent.',flush=True)
        child=subprocess.Popen([str(a.node.resolve()),str(ROOT/'tests/signing-worker-hardware.mjs')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        child.stdin.write(json.dumps({'type':'start','material':material,'directory':str(out),
            'sq':str((out/'runtime/chat/bin/sq').resolve())})+'\n');child.stdin.flush()
        calls=0;completed=False
        for line in child.stdout:
            if len(line)>16384:raise RuntimeError('Oversized worker response')
            message=json.loads(line)
            if message.get('type')=='sign':
                calls+=1
                if calls!=1:raise RuntimeError('Refusing a second hardware signing request')
                request=message['request']
                if set(request)!={'review','requestId','signingFingerprint','hashAlgorithm','digest'}:
                    raise RuntimeError('Unexpected digest request fields')
                started=time.monotonic()
                response=bridge.action({'op':'chat-sign-digest',**request})
                result['nativeSigningSeconds']=round(time.monotonic()-started,3)
                child.stdin.write(json.dumps({'type':'signature','value':response})+'\n');child.stdin.flush()
            elif message.get('type')=='complete':
                if completed or calls!=1:raise RuntimeError('Unexpected test completion')
                completed=True;result.update(message['result'])
            else:raise RuntimeError('WASM/physical signing test stopped; no retry')
        if child.wait(timeout=15) or not completed:raise RuntimeError('Worker did not complete verification')
        # The successful sign ticket exists only in this isolated test directory.
        # It is never submitted to encryption completion/export/send routes.
        print('PASS: one hardware hybrid signature; independent sq decrypt/verify; text, HTML and attachment bytes.',flush=True)
    except Exception as error:
        result.update(passed=False,errorType=type(error).__name__,error=str(error))
        raise
    finally:
        if child is not None and child.poll() is None:
            child.terminate();child.wait(timeout=15)
        # Disposable software recipient material is no longer needed after the
        # independent verifier. The physical sender's private keys never left
        # the YubiKey and no private-key export command exists in this harness.
        for name in ('sender-secret.pgp','recipient-secret.pgp'):
            (out/'fixture'/name).unlink(missing_ok=True)
        if before is not None:
            try:
                after=snapshot_module.snapshot(SimpleNamespace(**cfg));save('after.json',after)
                pin_after=public_pin_state(cfg);save('pin-after.json',pin_after)
                hashes_after=backend_hashes(cfg);save('backend-after.json',hashes_after)
                result.update(slotRecordsCompared=24,keysAndPoliciesUnchanged=before==after,
                    pinTriesUnchanged=pin_before==pin_after,backendUnchanged=hashes==hashes_after)
                if not all(result[k] for k in ('keysAndPoliciesUnchanged','pinTriesUnchanged','backendUnchanged')):
                    result['passed']=False
                print('Final public snapshot: '+('UNCHANGED' if result.get('keysAndPoliciesUnchanged') else 'DIFFERENT'),flush=True)
            except Exception as error:
                result.update(passed=False,finalSnapshotError=type(error).__name__)
        save('result.json',result)
        print('Results: '+str(out),flush=True)
        for guard in guards:guard.close()
        # A return from the preflight branch still executes this final audit.
        # Do not let that return mask an unavailable/different after snapshot.
        if result.get('preflightOnly') and not result['passed']:
            raise RuntimeError('Final preflight audit failed; inspect saved result')
    if not result['passed']:raise RuntimeError('Final audit failed; inspect result before retrying')


if __name__=='__main__':main()
