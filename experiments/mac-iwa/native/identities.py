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
PUBLIC_SLOTS=('9a','9c','9d','9e',*(f'{slot:02x}' for slot in range(0x82,0x96)))


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


def checked_serial(value):
    """Validate a public device selector without changing vault enrollment."""
    if not isinstance(value,str) or not re.fullmatch(r'[1-9][0-9]{0,9}',value) or int(value)>2147483647:
        raise ValueError('Invalid selected serial')
    return value


def devices(bridge):
    """Enumerate serials only; this discovery route never opens a PIV session."""
    raw=subprocess.check_output([bridge.cfg['ykman'],'list','--serials'],stderr=subprocess.DEVNULL,timeout=25)
    if len(raw)>8192:raise ValueError('Device discovery limit')
    found=[checked_serial(item) for item in raw.decode('ascii').split()]
    return {'devices':[{'serial':item} for item in sorted(set(found))]}


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


def public_snapshot(bridge,include_bundle,selected_serial=None):
    """Read opaque bundle bytes and actual public keys, with no UI decoding.

    Only the installed enrollment selects the physical device and executable.
    The helper reads the fixed current bundle namespace and all 24 public slot
    states twice. It does not parse the compressed bundle or claim signature,
    live-key matching, identity selection or trust. WASM must independently
    inspect the bytes and compare its authenticated mapping to this snapshot.
    A file import can request the keys alone after an entirely offline review.
    """
    request={'op':'identity-bundle-read' if include_bundle else 'identity-key-snapshot',
        'serial':checked_serial(selected_serial) if selected_serial is not None else serial(bridge),
        'objectHelper':str(Path(bridge.cfg['app'])/'native/bin/hybrid-mail-provision')}
    bridge.emit({'type':'progress','message':'Reading public YubiKey data — no PIN or touch required.'})
    result=run_public(bridge,request)
    fields={'format','version','serial','slots','warnings'}|({'bundle','generation'} if include_bundle else set())
    if (set(result)!=fields or result.get('format')!='sequoia-iwa-public-snapshot' or
        type(result.get('version')) is not int or result['version']!=1 or
        result.get('serial')!=request['serial'] or result.get('warnings')!=[]):
        raise ValueError('Invalid public snapshot response')
    slots=result.get('slots')
    if not isinstance(slots,list) or len(slots)!=len(PUBLIC_SLOTS):
        raise ValueError('Invalid public slot snapshot')
    for expected,item in zip(PUBLIC_SLOTS,slots):
        if not isinstance(item,dict) or set(item)!={'slot','publicKeySha256'} or item['slot']!=expected:
            raise ValueError('Invalid public slot snapshot')
        digest=item['publicKeySha256']
        if digest is not None and (not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest)):
            raise ValueError('Invalid public key digest')
    if include_bundle:
        bundle_bytes(result['bundle'])
        if type(result['generation']) is not int or not 1<=result['generation']<=9007199254740991:
            raise ValueError('Invalid public bundle generation')
    return result


def preview(bridge,encoded=None,selected_serial=None,compatibility_certificate=None):
    """Verify the signed bundle against the selected or configured live card.

    This internal authorization path is intentionally distinct from browser
    inventory parsing in WASM. Before selected signing or decryption, native
    code independently validates the full signed bundle and live public keys.
    No browser route accepts a bundle for this decoder. The optional file form
    remains an internal regression/test facility with the same live checks.
    """
    if encoded is not None:bundle_bytes(encoded)
    request={'op':'identity-restore','serial':selected_serial or serial(bridge),
        'objectHelper':str(Path(bridge.cfg['app'])/'native/bin/hybrid-mail-provision')}
    if encoded is not None:request['bundle']=encoded
    if compatibility_certificate is not None:request['compatibilityCertificate']=compatibility_certificate
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
    if not isinstance(value,dict) or set(value) not in (fields,fields|{'certificate'}):
        raise ValueError('Invalid selected identity')
    if not isinstance(value['serial'],str) or not re.fullmatch(r'[1-9][0-9]{0,9}',value['serial']) or int(value['serial'])>2147483647:
        raise ValueError('Invalid selected serial')
    for field in ('bundleHash','certificateHash'):
        if not isinstance(value[field],str) or not re.fullmatch('[a-f0-9]{64}',value[field]):
            raise ValueError('Invalid selected identity hash')
    if not isinstance(value['fingerprint'],str) or not re.fullmatch('(?:[A-F0-9]{40}|[A-F0-9]{64})',value['fingerprint']):
        raise ValueError('Full selected fingerprint required')
    if not isinstance(value['email'],str) or len(value['email'])>320 or not re.fullmatch(r'[^\s<>@,;\x00-\x1f\x7f]+@[^\s<>@,;\x00-\x1f\x7f]+',value['email']) or value['email']!=value['email'].lower():
        raise ValueError('One normalized selected email required')
    if 'certificate' in value:
        encoded=value['certificate']
        if not isinstance(encoded,str) or len(encoded)>87384:raise ValueError('Public certificate cache limit')
        raw=base64.b64decode(encoded,validate=True)
        if base64.b64encode(raw).decode()!=encoded or hashlib.sha256(raw).hexdigest()!=value['certificateHash']:
            raise ValueError('Public certificate cache hash mismatch')
    return dict(value)


def companion_preview(bridge,selected_serial,certificate=None):
    """Read/authenticate encrypted public metadata only; no companion opening."""
    request={'op':'identity-companion-read','serial':checked_serial(selected_serial),
        'objectHelper':str(Path(bridge.cfg['app'])/'native/bin/hybrid-mail-provision')}
    if certificate is not None:request['certificate']=certificate
    bridge.emit({'type':'progress','message':'Reading encrypted on-key companion — no PIN or touch required.'})
    result=run_public(bridge,request)
    if result.get('serial')!=request['serial'] or result.get('format')!='sequoia-iwa-companion':
        raise ValueError('Invalid companion review')
    return result


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
    # The ciphertext hash selects a companion independently from the normal
    # public bundle. A cache may provide an ultra-compact public certificate,
    # but the signed template and live keys must authenticate it first.
    cached=run_public(bridge,{'op':'identity-canonical','certificate':chosen['certificate']}) if 'certificate' in chosen else None
    compatibility=chosen['certificate'] if cached and cached.get('version')==5 else None
    try:snapshot=preview(bridge,selected_serial=chosen['serial'],compatibility_certificate=compatibility)
    except ValueError:snapshot=None
    if snapshot is None or snapshot['bundleHash']!=chosen['bundleHash']:
        companion=companion_preview(bridge,chosen['serial'],chosen.get('certificate'))
        if companion['companionHash']!=chosen['bundleHash']:
            raise ValueError('Selected certificate bundle changed; restore it again')
        public=run_public(bridge,{'op':'identity-canonical','certificate':companion['certificate']})
        if (public.get('fingerprint')!=chosen['fingerprint'] or public.get('certificateHash')!=chosen['certificateHash'] or chosen['email'] not in public.get('emails',[])):
            raise ValueError('Selected companion certificate changed')
        context={**{k:chosen[k] for k in ('serial','bundleHash','fingerprint','certificateHash','email')},
                 'certificate':public['certificate'],'profile':companion['profile'],
                 'components':companion['components'],'companion':{k:companion[k] for k in ('encoded','serial','publicKeys','certificate')}}
        return operation_context(context),public
    candidates=[c for c in snapshot['certificates'] if c.get('kind')=='openpgp']
    matches=[]
    # A full packet hash distinguishes compatibility views sharing a primary
    # fingerprint. Never select by display label or browser-supplied profile.
    for candidate in candidates:
        public=run_public(bridge,{'op':'identity-canonical','certificate':candidate['certificate']})
        if (public.get('fingerprint')==chosen['fingerprint'] and
            public.get('certificateHash')==chosen['certificateHash'] and
            chosen['email'] in public.get('emails',[])):
            matches.append((candidate,public))
    if len(matches)!=1:raise ValueError('Selected certificate is not in the verified live bundle')
    candidate,public=matches[0]
    context={**{k:chosen[k] for k in ('serial','bundleHash','fingerprint','certificateHash','email')},'certificate':public['certificate'],
             'profile':candidate['profile'],'components':candidate['components']}
    return operation_context(context),public


def operation_context(value):
    """Validate a native-created public grant before the PIN dialog.

    The helper's private calls re-check the physical public components against
    this certificate. This check additionally binds the persisted canonical
    packet bytes to the reviewed hash and rejects malformed grant contents.
    """
    if not isinstance(value,dict) or set(value) not in ({'serial','bundleHash','fingerprint','certificateHash','email','certificate','profile','components'},{'serial','bundleHash','fingerprint','certificateHash','email','certificate','profile','components','companion'}):
        raise ValueError('Invalid selected operation context')
    chosen=selection({k:value[k] for k in ('serial','bundleHash','fingerprint','certificateHash','email')})
    encoded=value['certificate']
    if not isinstance(encoded,str) or len(encoded)>87384:
        raise ValueError('Selected certificate limit')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError):raise ValueError('Invalid selected certificate') from None
    if not 1<=len(raw)<=65536 or base64.b64encode(raw).decode()!=encoded or hashlib.sha256(raw).hexdigest()!=chosen['certificateHash']:
        raise ValueError('Selected certificate hash mismatch')
    # These rows were reconstructed by the signed-bundle parser. Rechecking
    # their closed schema on grant redemption prevents accidental broadening
    # of private operations if a future caller adds paths or arbitrary roles.
    profile=value['profile']
    if not isinstance(profile,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',profile):
        raise ValueError('Invalid hardware profile')
    components=value['components']
    if not isinstance(components,list) or not 2<=len(components)<=8:
        raise ValueError('Invalid hardware components')
    roles=set()
    for row in components:
        if not isinstance(row,dict) or set(row)!={'role','algorithm','storage','slot','publicKey'}:
            raise ValueError('Invalid hardware component')
        if row['role'] not in ('signing-pq','signing-classical','decryption-pq','decryption-classical','certification-pq','certification-classical','companion-wrap') or row['role'] in roles:
            raise ValueError('Invalid hardware role')
        roles.add(row['role'])
        if row['storage'] not in ('piv','companion') or (row['storage']=='piv' and row['slot'] not in PUBLIC_SLOTS) or (row['storage']=='companion' and row['slot']!=''):
            raise ValueError('Invalid hardware storage')
        if row['algorithm'] not in ('ML-DSA-65','ML-DSA-87','ML-KEM-768','ML-KEM-1024','Ed25519','Ed448','X25519','X448','P-384','P-521','ECDSA-P384','ECDH-P384'):
            raise ValueError('Invalid hardware algorithm')
        raw_public=base64.b64decode(row['publicKey'],validate=True)
        if not 32<=len(raw_public)<=4096 or base64.b64encode(raw_public).decode()!=row['publicKey']:
            raise ValueError('Invalid component public key')
    result={**chosen,'certificate':encoded,'profile':profile,'components':components}
    if 'companion' in value:
        companion=value['companion']
        if not isinstance(companion,dict) or set(companion)!={'encoded','serial','publicKeys','certificate'} or companion['serial']!=chosen['serial']:
            raise ValueError('Invalid companion grant')
        cached_public=base64.b64decode(companion['certificate'],validate=True)
        if not 1<=len(cached_public)<=65536:raise ValueError('Companion public cache limit')
        ciphertext=base64.b64decode(companion['encoded'],validate=True)
        if not 1<=len(ciphertext)<=65536 or hashlib.sha256(ciphertext).hexdigest()!=chosen['bundleHash']:
            raise ValueError('Companion grant hash mismatch')
        result['companion']=companion
    return result


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
