"""Small native authority utilities, independent of the old mail application.

Only public certificate validation and exclusive public grant-file creation
belong here. There is no Google transport, MIME parser, secret store, arbitrary
command, or compatibility fallback to a standalone frontend executable.
"""
import base64
import os
from pathlib import Path
import re

from certificate_migration import read_public_file


def write_new(path, value):
    """Create a one-use public grant without following or replacing a file.

    Callers supply a path constructed from a fixed private directory and a
    random native identifier. O_EXCL also refuses an existing symlink, while
    mode 0600 prevents another user from reading the authorization metadata.
    """
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(value)


def check_certificate(bridge,path,email):
    """Validate a configured public identity and its currently certified email.

    The existing native Rust identity parser rejects private packets, expired
    or revoked certifications, unsupported keys and ambiguous certificate
    streams. Reuse it instead of loading the standalone Chat software signer.
    This is public-only policy validation, never evidence of device presence.
    """
    if not isinstance(email,str) or not 1<=len(email)<=320 or not re.fullmatch(r'[^\s<>@,;\x00-\x1f\x7f]+@[^\s<>@,;\x00-\x1f\x7f]+',email):
        raise ValueError('Invalid configured certified email')
    raw=read_public_file(Path(path),65536)
    if not raw:raise ValueError('Empty configured certificate')
    # Import inside the function to keep the small native modules acyclic.
    from identities import run_public
    value=run_public(bridge,{'op':'identity-canonical','certificate':base64.b64encode(raw).decode()})
    # Treat the parser process as a protocol boundary too: malformed output
    # must fail closed instead of becoming a guessed certificate identity.
    fingerprint=value.get('fingerprint') if isinstance(value,dict) else None
    emails=value.get('emails') if isinstance(value,dict) else None
    if (not isinstance(fingerprint,str) or not re.fullmatch('[A-F0-9]{64}',fingerprint)
            or not isinstance(emails,list) or not 1<=len(emails)<=64
            or any(not isinstance(item,str) or not 1<=len(item)<=320 for item in emails)
            or email.lower() not in emails):
        raise ValueError('Configured email not certified by identity')
    return {'fingerprint':fingerprint,'emails':emails,
            'algorithms':['ML-DSA-65 + Ed25519','ML-KEM-768 + X25519']}
