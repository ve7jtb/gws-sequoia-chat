"""Read-only export of the former native public-certificate and trust store.

This route is an explicit migration source, not a live authority or fallback.
The IWA reviews, validates and atomically imports these records. Nothing here
creates, removes or updates a certificate/trust file or accesses a private key.
"""
import base64
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import subprocess

FP=re.compile(r'(?:[A-F0-9]{40}|[A-F0-9]{64})')


def read_public_file(path,limit):
    """Never follow a legacy-store symlink or read beyond the export budget."""
    # Open without following links, then inspect the opened descriptor. This
    # closes the check/open race if a local record is replaced during migration.
    try:fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    except OSError:raise ValueError('Invalid legacy public record') from None
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise ValueError('Invalid legacy public record')
        data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('Legacy public record limit')
    return data



def validate_public(bridge,fp,raw):
    """Reject secret packets and filename/fingerprint mismatches before export.

    The legacy store should contain only validated public certificates, but the
    read-only boundary must not trust filenames or accidentally send a mistakenly
    imported secret key to Chrome. The fixed native parser independently checks
    public-only packet structure; the IWA repeats validation before persistence.
    """
    request={'op':'inspect-public','certificate':base64.b64encode(raw).decode()}
    check=subprocess.run([str(bridge.root/'runtime/sequoia-iwa-crypto')],
        input=json.dumps(request).encode(),stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=30)
    if check.returncode or len(check.stdout)>32768:
        raise ValueError('Invalid legacy public certificate')
    if json.loads(check.stdout).get('fingerprint')!=fp:
        raise ValueError('Legacy public fingerprint mismatch')

def snapshot(bridge):
    """Export only the fixed public filename patterns, with a stable digest.

    Duplicate native copies of the same certificate must agree. Differing copies
    need explicit user review rather than silently picking whichever glob wins.
    Source fingerprints are hints: the WASM importer independently derives each
    full fingerprint and validates current self-certifications before trust.
    """
    directory=Path(bridge.data);certificates={};budget=200000
    for path in sorted(directory.glob('*.pgp')):
        name=path.stem
        if name.startswith('mail-cert-'):name=name[len('mail-cert-'):]
        if not FP.fullmatch(name):continue
        raw=read_public_file(path,262144)
        if name in certificates:
            if certificates[name]!=raw:raise ValueError('Conflicting legacy certificate copies')
            continue
        if not raw or len(certificates)>=24 or len(raw)>budget:
            raise ValueError('Legacy certificate budget exceeded')
        validate_public(bridge,name,raw)
        budget-=len(raw);certificates[name]=raw
    bindings=set()
    for pattern in ('contact-*.json','mail-trust-*.json'):
        for path in sorted(directory.glob(pattern)):
            value=json.loads(read_public_file(path,16384))
            if not isinstance(value,dict):raise ValueError('Invalid legacy trust record')
            fp=value.get('fingerprint');email=value.get('email')
            if not isinstance(fp,str) or not FP.fullmatch(fp) or fp not in certificates:
                raise ValueError('Legacy trust has no matching certificate')
            if not isinstance(email,str) or not 1<=len(email)<=320 or any(ord(c)<32 or ord(c)==127 for c in email):
                raise ValueError('Invalid legacy trust email')
            bindings.add((email,fp))
            if len(bindings)>256:raise ValueError('Legacy trust budget exceeded')
    result={'version':1,'certificates':[base64.b64encode(certificates[fp]).decode() for fp in sorted(certificates)],
            'saved':sorted(certificates),'bindings':[{'email':email,'fingerprint':fp} for email,fp in sorted(bindings)]}
    # A digest lets the UI identify the exact reviewed export. It is not a trust
    # signature: only explicit local review and WASM policy validation grant trust.
    encoded=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    result['sourceDigest']=hashlib.sha256(encoded).hexdigest()
    # Native Messaging JSON escapes non-ASCII by default. Bound that actual
    # representation too, so many long Unicode bindings cannot overflow the
    # bridge even though the raw certificate and binding counts are valid.
    if len(json.dumps(result).encode())>480000:
        raise ValueError('Legacy migration frame limit')
    return result
