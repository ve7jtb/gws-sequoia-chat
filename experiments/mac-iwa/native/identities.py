"""Public-only own-identity review, separate from contact trust and authority.

A browser inventory entry is only a selection request: a fresh, authenticated
on-key bundle supplies its public certificate and supported role mapping. Native
configuration alone supplies executable paths. Existing vault enrollments retain
their configured serial. These routes neither ask for a PIN nor write a card.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess

from certificate_migration import read_public_file

MAX_BUNDLE=65536
MAX_REPLY=400000


def bundle_bytes(text):
    """Reject ambiguous base64 and unsupported containers before card access."""
    if not isinstance(text,str) or not 1<=len(text)<=87384:
        raise ValueError('Certificate bundle size limit')
    try:raw=base64.b64decode(text,validate=True)
    except (ValueError,TypeError):raise ValueError('Invalid certificate bundle encoding') from None
    if base64.b64encode(raw).decode()!=text or not 1<=len(raw)<=MAX_BUNDLE:
        raise ValueError('Invalid certificate bundle encoding')
    if not raw.startswith(b'PQMZIP01'):
        raise ValueError('Current compressed public certificate bundle required')
    return raw


def serial(bridge):
    """Return the fixed enrollment serial used by legacy/vault public review."""
    value=bridge.cfg['serial']
    if not isinstance(value,str) or not re.fullmatch(r'[1-9][0-9]{0,9}',value) or int(value)>2147483647:
        raise ValueError('Invalid configured serial')
    return value


def run_public(bridge,request):
    """Only fixed public crypto requests cross an anonymous pipe.

    stderr is discarded rather than surfaced as a browser error. The helper
    output is bounded and never includes a PIN, secret key, session key or path.
    The outer native operation lock also excludes concurrent signing/decryption.
    """
    result=subprocess.run([str(bridge.root/'runtime/sequoia-iwa-crypto')],
        input=json.dumps(request).encode(),stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=180)
    if result.returncode or len(result.stdout)>MAX_REPLY:
        raise ValueError('Public identity review failed')
    value=json.loads(result.stdout)
    if not isinstance(value,dict):raise ValueError('Invalid public identity response')
    return value


def current(bridge):
    """Read the currently configured public sender without touching a card.

    This is a display of configured authority, not a live presence/key-match
    claim. The browser reparses the certificate before rendering or saving it.
    """
    raw=read_public_file(Path(bridge.cfg['cert']),131072)
    if not raw:raise ValueError('Empty configured certificate')
    result=run_public(bridge,{'op':'identity-current','certificate':base64.b64encode(raw).decode()})
    if set(result)!={'certificate','fingerprint','slots'}:
        raise ValueError('Invalid configured identity response')
    result['serial']=serial(bridge)
    return result


def preview(bridge,encoded=None,selected_serial=None):
    """Verify the signed bundle against the selected or configured live card.

    Import is deliberately not an offline assertion of hardware ownership: a
    file must match the same physical public keys as an on-key restore. The
    browser stores the result only after the user reviews it. Native state,
    contacts, trust, certificates and hardware keys are left unchanged.
    """
    if encoded is not None:bundle_bytes(encoded)
    request={'op':'identity-restore','serial':selected_serial or serial(bridge),
        'objectHelper':str(Path(bridge.cfg['app'])/'native/bin/hybrid-mail-provision')}
    if encoded is not None:request['bundle']=encoded
    bridge.emit({'type':'progress','message':'Reading and verifying public certificate bundle — no PIN or touch required.'})
    result=run_public(bridge,request)
    if result.get('serial')!=request['serial'] or result.get('source')!=('file' if encoded is not None else 'yubikey'):
        raise ValueError('Identity review authority mismatch')
    if result.get('bundleSignatureVerified') is not True or result.get('liveKeysMatched') is not True:
        raise ValueError('Unverified identity review')
    return result


def selection(value):
    """A browser may name a restored identity, never executable paths or slots.

    These bounded public identifiers are a lookup request only. They acquire
    authority only after the live signed bundle and all public keys verify.
    Keeping an exact schema prevents a future caller accidentally interpreting
    display metadata as a request to change the native backend configuration.
    """
    fields={'serial','bundleHash','fingerprint','certificateHash','email'}
    if not isinstance(value,dict) or set(value)!=fields:
        raise ValueError('Invalid selected identity')
    if not isinstance(value['serial'],str) or not re.fullmatch(r'[1-9][0-9]{0,9}',value['serial']) or int(value['serial'])>2147483647:
        raise ValueError('Invalid selected serial')
    for field in ('bundleHash','certificateHash'):
        if not isinstance(value[field],str) or not re.fullmatch('[a-f0-9]{64}',value[field]):
            raise ValueError('Invalid selected identity hash')
    if not isinstance(value['fingerprint'],str) or not re.fullmatch('[A-F0-9]{64}',value['fingerprint']):
        raise ValueError('Selected v6 fingerprint required')
    if not isinstance(value['email'],str) or len(value['email'])>320 or not re.fullmatch(r'[^\s<>@,;\x00-\x1f\x7f]+@[^\s<>@,;\x00-\x1f\x7f]+',value['email']) or value['email']!=value['email'].lower():
        raise ValueError('One normalized selected email required')
    return dict(value)


def selected(bridge,value):
    """Rebuild private-operation authority from the live authenticated bundle.

    The on-key manifest determines the supported roles/slots through the shared
    decoder. No browser certificate, path, algorithm or slot is accepted here.
    Restoring another supported serial does not modify the installed default
    identity (which remains the authority for existing vault enrollments).
    """
    chosen=selection(value)
    connected=subprocess.check_output([bridge.cfg['ykman'],'list','--serials'],
        stderr=subprocess.DEVNULL,timeout=25).decode().split()
    if chosen['serial'] not in connected:raise ValueError('Connect YubiKey '+chosen['serial'])
    snapshot=preview(bridge,selected_serial=chosen['serial'])
    if snapshot['bundleHash']!=chosen['bundleHash']:
        raise ValueError('Selected certificate bundle changed; restore it again')
    candidates=[c for c in snapshot['certificates'] if c.get('kind')=='openpgp' and c.get('label')=='OpenPGP v6']
    if len(candidates)!=1:raise ValueError('One supported v6 identity required')
    # Canonical OpenPGP packet bytes, rather than armor or primary fingerprint
    # alone, bind the exact UID/subkey/certification view reviewed by the IWA.
    public=run_public(bridge,{'op':'identity-canonical','certificate':candidates[0]['certificate']})
    if (public.get('fingerprint')!=chosen['fingerprint'] or
        public.get('certificateHash')!=chosen['certificateHash'] or
        chosen['email'] not in public.get('emails',[])):
        raise ValueError('Selected public certificate or certified email changed')
    context={**chosen,'certificate':public['certificate']}
    context=operation_context(context)
    return context,public


def operation_context(value):
    """Validate a native-created public grant before the PIN dialog.

    The helper's private calls re-check the physical public components against
    this certificate. This check additionally binds the persisted canonical
    packet bytes to the reviewed hash and rejects malformed grant contents.
    """
    if not isinstance(value,dict) or set(value)!={'serial','bundleHash','fingerprint','certificateHash','email','certificate'}:
        raise ValueError('Invalid selected operation context')
    chosen=selection({k:v for k,v in value.items() if k!='certificate'})
    encoded=value['certificate']
    if not isinstance(encoded,str) or len(encoded)>87384:
        raise ValueError('Selected certificate limit')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError):raise ValueError('Invalid selected certificate') from None
    if not 1<=len(raw)<=65536 or base64.b64encode(raw).decode()!=encoded or hashlib.sha256(raw).hexdigest()!=chosen['certificateHash']:
        raise ValueError('Selected certificate hash mismatch')
    return {**chosen,'certificate':encoded}


def revalidate_context(bridge,value):
    """Recheck public-only packets and current certifications before the PIN.

    Grant files contain only public material, but are parsed defensively when
    another native process redeems them. Revocation/expiry and secret packets
    must fail before prompting, not after the user supplies a PIN.
    """
    context=operation_context(value)
    public=run_public(bridge,{'op':'identity-canonical','certificate':context['certificate']})
    if any(public.get(k)!=context[k] for k in ('certificate','certificateHash','fingerprint')) or context['email'] not in public.get('emails',[]):
        raise ValueError('Selected identity no longer valid')
    return context
