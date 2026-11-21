#!/usr/bin/env python3
"""Standalone Google Chat transport (gws) and OpenPGP cryptography (Sequoia).

No PQ Mail classes, vault, account tokens, Java runtime or hardware adapters are
used. Google only receives encrypted MIME and a public certificate. The fixed
command boundary also permits a future localhost UI without exposing a shell.
"""
import argparse
import base64
import email.policy
import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid
from email.message import EmailMessage
from email.parser import BytesParser

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 20 * 1024 * 1024
MAX_FILES = 10 * 1024 * 1024
SCOPES = ','.join('https://www.googleapis.com/auth/' + x for x in
                  ('chat.spaces.readonly', 'chat.messages.readonly', 'chat.messages.create'))
SUITES = {'3': ('mldsa65-ed25519', 'mlkem768-x25519'),
          '5': ('mldsa87-ed448', 'mlkem1024-x448')}
ALGORITHMS = {30: 'ML-DSA-65 + Ed25519', 31: 'ML-DSA-87 + Ed448',
              35: 'ML-KEM-768 + X25519', 36: 'ML-KEM-1024 + X448'}


def require(test, reason):
    if not test:
        raise ValueError(reason)


def read(path, limit=MAX_BYTES):
    # Limit the actual read, not just stat(), since a file could grow after stat.
    with Path(path).open('rb') as f:
        value = f.read(limit + 1)
    require(len(value) <= limit, 'File exceeds the permitted size')
    return value


def write_new(path, value):
    # Exclusive creation refuses overwrites and symlink targets.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(value)


def private_dir(path):
    path = Path(path).resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def run(command, *, output=None, cap=MAX_BYTES, interactive=False, timeout=180):
    """Execute an argv list, never a shell; bound subprocess time and output.

    sq can prompt directly on the controlling terminal for an encrypted key's
    password. Neither Python nor gws receives that password. Output remains in
    a private staging file until sq exits successfully and verifies a signature.
    """
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen([str(x) for x in command], stdout=stdout,
                                stderr=None if interactive else stderr)
        start = time.monotonic()
        try:
            while proc.poll() is None:
                if time.monotonic() - start > timeout:
                    raise ValueError('Command timed out; operation was not retried')
                if output and Path(output).exists() and Path(output).stat().st_size > cap:
                    raise ValueError('Downloaded/decompressed content exceeds size limit')
                if os.fstat(stdout.fileno()).st_size > cap or os.fstat(stderr.fileno()).st_size > 1024*1024:
                    raise ValueError('Command output exceeds size limit')
                time.sleep(0.025)
            stdout.seek(0)
            data = stdout.read(cap + 1)
            require(len(data) <= cap, 'Command output exceeds size limit')
            if proc.returncode:
                stderr.seek(0)
                diagnostic = stderr.read(8192).decode('utf-8', 'replace')
                # Do not interpolate command arguments, passwords or credentials.
                raise ValueError('Command failed: ' + diagnostic.strip())
            if output:
                require(Path(output).is_file(), 'Command did not create its output')
                require(Path(output).stat().st_size <= cap, 'Output exceeds size limit')
            return data
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def sq(*args, output=None, interactive=False, batch=False):
    # Disable default stores so this workflow cannot silently import or trust
    # certificates, select an unrelated key, or access PQ Mail state.
    cmd = [ROOT/'bin/sq', '--home=none', '--cert-store=none', '--key-store=none']
    if batch:
        cmd += ['--batch']
    return run(cmd + list(args), output=output, interactive=interactive)


def gws(*args, output=None, cap=MAX_BYTES):
    # gws restricts transfers to its cwd. The wrapper deliberately uses its
    # isolated profile directory, so stage only the explicitly selected files
    # there instead of weakening upstream path checks or changing token stores.
    profile = os.environ.get('GWS_CHAT_PROFILE', 'default')
    require(bool(re.fullmatch(r'[A-Za-z0-9_-]+', profile)), 'Invalid account profile')
    config = ROOT/'private'/('gws' if profile == 'default' else 'profiles/'+profile)
    config.mkdir(mode=0o700, parents=True, exist_ok=True)
    argv = list(args)
    with tempfile.TemporaryDirectory(prefix='.transfer-', dir=config) as directory:
        staging = Path(directory)
        if '--upload' in argv:
            i = argv.index('--upload') + 1
            source = Path(argv[i])
            require(source.name in ('message.pgp', 'pq-mail-sender-key.pgp'), 'Unexpected upload filename')
            target = staging/source.name
            write_new(target, read(source, cap))
            argv[i] = str(target)
        staged_output = None
        if output:
            require('--output' in argv, 'Missing download output option')
            require(not Path(output).exists(), 'Download output already exists')
            staged_output = staging/'download.bin'
            argv[argv.index('--output')+1] = str(staged_output)
        raw = run([ROOT/'gws-chat', *argv], output=staged_output, cap=cap)
        result = json.loads(raw)
        require(not result.get('error'), 'Google API returned an error')
        if staged_output:
            write_new(output, read(staged_output, cap))
        return result


def canonical_email(value):
    require(bool(re.fullmatch(r'[^\s<>@,;\x00-\x1f]+@[^\s<>@,;\x00-\x1f]+\.[^\s<>@,;\x00-\x1f]+', value)),
            'Expected a single plain email address')
    return value.lower()


def public_packets(path):
    """Decode bounded public packets; never accept secret or partial packets."""
    raw = read(path, 1024*1024)
    if raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
        parts = raw.replace(b'\r\n', b'\n').split(b'\n\n', 1)
        require(len(parts) == 2, 'Malformed public certificate armor')
        block, end, trailing = parts[1].partition(b'-----END PGP PUBLIC KEY BLOCK-----')
        require(end and not trailing.strip(), 'Trailing data after public certificate')
        encoded = b''.join(x for x in block.splitlines() if x and not x.startswith(b'='))
        raw = base64.b64decode(encoded, validate=True)
    at, packets = 0, []
    while at < len(raw):
        start = at
        tag = raw[at]; at += 1
        require(tag & 0x80, 'Invalid OpenPGP packet')
        if tag & 0x40:
            kind = tag & 63
            require(at < len(raw), 'Truncated packet length')
            size = raw[at]; at += 1
            if 192 <= size < 224:
                require(at < len(raw), 'Truncated packet length')
                size = (size-192)*256 + raw[at] + 192; at += 1
            elif size == 255:
                require(at+4 <= len(raw), 'Truncated packet length')
                size = int.from_bytes(raw[at:at+4], 'big'); at += 4
            else:
                require(size < 192, 'Partial certificate packets are not accepted')
        else:
            kind = (tag >> 2) & 15
            n = tag & 3
            require(n != 3, 'Indeterminate certificate packets are not accepted')
            n = 1 << n
            require(at+n <= len(raw), 'Truncated packet length')
            size = int.from_bytes(raw[at:at+n], 'big'); at += n
        require(at+size <= len(raw), 'Truncated certificate')
        body = raw[at:at+size]; at += size
        require(kind in (6, 14, 2, 13), 'Expected only public certificate packets')
        packets.append((kind, body, raw[start:at]))
    return packets


def public_info(path):
    """Return public metadata with policy-validated mailbox bindings.

    Mixed certificates are permitted, but encryption and verification operate
    on a filtered public view retaining only hybrid subkeys. No signature or
    primary-key packet is rewritten, so the primary fingerprint is unchanged.
    """
    # Packet parsing bounds the input and enforces the frontend's supported
    # profile. It cannot authenticate UID claims; delegate that to Sequoia below.
    primary, algorithms = None, []
    for kind, body, _ in public_packets(path):
        if kind in (6, 14):
            require(len(body) >= 10 and body[0] == 6, 'Only v6 certificates accepted')
            if kind == 6:
                require(primary is None and body[5] in (30, 31), 'Expected one hybrid primary')
                primary = hashlib.sha256(b'\x9b'+len(body).to_bytes(4, 'big')+body).hexdigest().upper()
            else:
                require(primary is not None, 'Subkey before primary')
            algorithms.append(ALGORITHMS.get(body[5], 'Classical algorithm ' + str(body[5])))
    require(primary and algorithms, 'Missing public primary key')
    # No raw UID is eligible for trust or sender/recipient selection. The helper
    # checks live self-certifications, primary-key validity, and UID/cert
    # revocations on every use (including reloading saved contacts). A matching
    # fingerprint makes the native/Python interpretation explicit. This still
    # requires the user's independent fingerprint verification to grant trust.
    validated = json.loads(run([ROOT/'bin/chat-software-identity', 'inspect-public', path],
                               cap=1024*1024, timeout=30))
    require(validated.get('fingerprint') == primary, 'Certificate fingerprint mismatch')
    emails = sorted({canonical_email(address) for address in validated.get('emails', [])})
    require(emails, 'No current self-certified email address')
    return {'fingerprint': primary, 'algorithms': algorithms, 'emails': emails}


# Preserve signed packet bytes when projecting a hybrid-only certificate view.
# Re-signing or rewriting a key packet would change the identity. This filters
# available algorithms but is not itself certificate-policy validation.
def hybrid_public(path):
    public_info(path)
    result, keep = bytearray(), True
    for kind, body, encoded in public_packets(path):
        if kind == 14:
            keep = body[5] in ALGORITHMS
        elif kind in (6, 13):
            keep = True
        if keep:
            result.extend(encoded)
    return bytes(result)


def check_cert(path, address, fingerprint=None):
    info = public_info(path)
    require(canonical_email(address) in info['emails'], 'Email not present in selected certificate')
    if fingerprint:
        require(bool(re.fullmatch(r'[0-9a-fA-F]{64}', fingerprint)), 'Supply the full v6 primary fingerprint')
        require(info['fingerprint'] == fingerprint.upper(), 'Certificate fingerprint does not match')
    return info


def generate(directory, address, level, test_only=False):
    address = canonical_email(address)
    directory = private_dir(directory)
    signing, encryption = SUITES[level]
    secret, public = directory/'secret.pgp', directory/'public.pgp'
    args = ['key', 'generate', '--own-key', '--email', address, '--profile', 'rfc9580',
            '--cipher-suite', signing, '--encryption-algorithm', encryption,
            '--cannot-authenticate', '--expiration', '1y', '--output', secret,
            '--rev-cert', directory/'revocation.pgp']
    # Only automated disposable fixtures bypass password protection. The public
    # CLI does not expose this switch; normal creation lets sq prompt securely.
    if test_only:
        args += ['--without-password']
    sq(*args, output=secret, interactive=not test_only, batch=test_only)
    sq('key', 'delete', '--cert-file', secret, '--output', public, output=public)
    return public_info(public)


def mime_bytes(sender, recipient, subject, text, html=None, attachments=()):
    require(len(subject) <= 500 and '\n' not in subject and '\r' not in subject, 'Invalid subject')
    msg = EmailMessage(policy=email.policy.SMTP)
    msg['From'], msg['To'] = canonical_email(sender), canonical_email(recipient)
    msg['Subject'], msg['Date'] = subject, email.utils.formatdate(localtime=False, usegmt=True)
    msg['Message-ID'] = email.utils.make_msgid(domain='standalone-chat.invalid')
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype='html')
    require(len(attachments) <= 20, 'Too many attachments')
    total = 0
    for filename in attachments:
        data = read(filename, MAX_FILES-total)
        total += len(data)
        msg.add_attachment(data, maintype='application', subtype='octet-stream', filename=Path(filename).name)
    result = msg.as_bytes()
    require(len(result) <= MAX_BYTES, 'MIME exceeds 20 MiB')
    return result


def pack(identity, recipient_cert, recipient_fingerprint, sender, recipient, subject,
         text, html, attachments, output, compression='zip', batch=False):
    identity = Path(identity).resolve()
    own = check_cert(identity/'public.pgp', sender)
    require(all(x in ALGORITHMS.values() for x in own['algorithms']),
            'Sending identity must contain only hybrid signing keys')
    peer = check_cert(recipient_cert, recipient, recipient_fingerprint)
    require(any(x.startswith('ML-KEM') for x in peer['algorithms']), 'Recipient has no hybrid KEM')
    out = private_dir(output)
    with tempfile.TemporaryDirectory(prefix='.compose-', dir=out) as staging:
        staging = Path(staging)
        mime = staging/'payload.mime'
        write_new(mime, mime_bytes(sender, recipient, subject, text, html, attachments))
        encrypted = staging/'encrypted.pgp'
        filtered = staging/'recipient.pgp'
        write_new(filtered, hybrid_public(recipient_cert))
        sq('encrypt', '--for-file', filtered, '--signer-file', identity/'secret.pgp',
           '--profile', 'rfc9580', '--compression', compression, '--binary', '--output', encrypted,
           mime, output=encrypted, interactive=not batch, batch=batch)
        write_new(out/'message.pgp', read(encrypted))
    # Public certificate packets are validated before copying: never upload a
    # secret-key file accidentally supplied under a public-looking filename.
    write_new(out/'pq-mail-sender-key.pgp', read(identity/'public.pgp', 1024*1024))
    manifest = {'format': 'openpgp-compressed-mime', 'sender': sender, 'recipient': recipient,
                'sender_fingerprint': own['fingerprint'], 'recipient_fingerprint': peer['fingerprint'],
                'ciphertext_sha256': hashlib.sha256(read(out/'message.pgp')).hexdigest()}
    # Local metadata is for review, not an authenticated transport assertion.
    write_new(out/'manifest.json', json.dumps(manifest, indent=2).encode())
    return manifest


def inspect_mime(raw, sender, recipient):
    require(len(raw) <= MAX_BYTES, 'Decompressed MIME exceeds 20 MiB')
    msg = BytesParser(policy=email.policy.default).parsebytes(raw)
    for header, expected in (('From', sender), ('To', recipient)):
        require(len(msg.get_all(header, [])) == 1, 'Expected one signed '+header)
        addresses = email.utils.getaddresses(msg.get_all(header))
        require(len(addresses) == 1 and addresses[0][1].lower() == canonical_email(expected),
                'Signed '+header+' does not match the selected identity')
    files, plain, html, total, count = [], [], [], 0, 0

    def walk(part, depth=0):
        nonlocal total, count
        count += 1
        require(depth <= 12 and count <= 100, 'Excessive MIME nesting or parts')
        if part.is_multipart():
            for child in part.iter_parts():
                walk(child, depth+1)
        elif part.get_content_disposition() == 'attachment' or part.get_filename():
            data = part.get_payload(decode=True) or b''
            total += len(data)
            require(total <= MAX_FILES and len(files) < 20, 'Attachments exceed limit')
            files.append((part.get_filename() or 'attachment.bin', data))
        elif part.get_content_type() in ('text/plain', 'text/html'):
            (html if part.get_content_type() == 'text/html' else plain).append(part.get_content())
    walk(msg)
    return {'subject': str(msg.get('Subject', '')), 'plain': plain, 'html': html, 'files': files}


def unpack(identity, bundle, signer_cert, fingerprint, sender, recipient, output, batch=False):
    check_cert(signer_cert, sender, fingerprint)
    identity = Path(identity).resolve()
    check_cert(identity/'public.pgp', recipient)
    read(bundle)  # Bound the ciphertext before starting Sequoia.
    out = private_dir(output)
    with tempfile.TemporaryDirectory(prefix='.verify-', dir=out) as staging:
        verified = Path(staging)/'verified.mime'
        # Explicit signer file AND threshold enforce verification; decryption
        # success alone is insufficient. Failed output never becomes a result.
        filtered = Path(staging)/'signer.pgp'
        write_new(filtered, hybrid_public(signer_cert))
        sq('decrypt', '--recipient-file', identity/'secret.pgp', '--signer-file', filtered,
           '--signatures', '1', '--output', verified, Path(bundle).resolve(), output=verified,
           interactive=not batch, batch=batch)
        raw = read(verified)
        content = inspect_mime(raw, sender, recipient)
        write_new(out/'verified.mime', raw)
    # HTML is preserved as source but never opened/rendered automatically. Remote
    # content and scripts must not execute as a side effect of reading a message.
    write_new(out/'body.txt', '\n'.join(content['plain']).encode())
    if content['html']:
        write_new(out/'body-html-source.txt', '\n'.join(content['html']).encode())
    files = []
    for i, (name, data) in enumerate(content['files']):
        # Ignore incoming path names, including ../, absolute paths and collisions.
        stored = 'attachment-%02d.bin' % (i+1)
        write_new(out/stored, data)
        files.append({'original_name': name, 'saved_as': stored, 'sha256': hashlib.sha256(data).hexdigest()})
    result = {'signature_valid': True, 'sender_fingerprint': fingerprint.upper(), 'from': sender,
              'to': recipient, 'subject': content['subject'], 'attachments': files,
              'trust': 'Explicitly selected certificate and full fingerprint; no automatic trust changes'}
    write_new(out/'result.json', json.dumps(result, indent=2).encode())
    return result


def space_name(value):
    require(bool(re.fullmatch(r'spaces/[A-Za-z0-9_-]+', value)), 'Invalid Chat space resource name')
    return value


def message_name(value):
    require(bool(re.fullmatch(r'spaces/[A-Za-z0-9_-]+/messages/[A-Za-z0-9_.-]+', value)),
            'Invalid Chat message resource name')
    return value


def send(space, bundle, confirm=False):
    space_name(space)
    bundle = Path(bundle).resolve()
    require(not (bundle/'send-request.json').exists(),
            'This bundle already has a send attempt; inspect its saved request before sending again')
    manifest = json.loads(read(bundle/'manifest.json', 16384))
    cert = public_info(bundle/'pq-mail-sender-key.pgp')
    require(cert['fingerprint'] == manifest['sender_fingerprint'], 'Sender certificate changed')
    require(hashlib.sha256(read(bundle/'message.pgp')).hexdigest() == manifest['ciphertext_sha256'],
            'Bundle changed since preparation')
    print(json.dumps({'space': space, 'sender': cert, 'recipient': manifest['recipient'],
                      'recipient_fingerprint': manifest['recipient_fingerprint']}, indent=2))
    print('Google and all space members can see the public certificate and its email addresses.')
    if not confirm:
        require(input('Type SEND to upload the encrypted bundle and public certificate: ') == 'SEND', 'Cancelled')
    attached = []
    for filename in ('message.pgp', 'pq-mail-sender-key.pgp'):
        uploaded = gws('chat', 'media', 'upload', '--params', json.dumps({'parent': space}),
                       '--json', json.dumps({'filename': filename}), '--upload', str(bundle/filename),
                       '--upload-content-type', 'application/octet-stream')
        ref = uploaded.get('attachmentDataRef', {})
        # Upload returns an opaque attachmentUploadToken; resourceName is the
        # later download handle and need not exist until a message is created.
        require(isinstance(ref, dict) and any(isinstance(ref.get(k), str) and 0 < len(ref[k]) <= 65536
                for k in ('attachmentUploadToken', 'resourceName')), 'Upload returned no attachment reference')
        attached.append({'attachmentDataRef': {k: ref[k] for k in ('attachmentUploadToken', 'resourceName') if k in ref}})
    # A stable, saved request ID lets an uncertain create response be investigated
    # without automatically resending. No failed POST is retried by this wrapper.
    request_id = str(uuid.uuid4())
    write_new(bundle/'send-request.json', json.dumps({'space': space, 'requestId': request_id}).encode())
    # Chat rejects multiple non-media files in one message. Publish the public
    # certificate first, then link it from the encrypted bundle's caption.
    cert_result = gws('chat', 'spaces', 'messages', 'create', '--params', json.dumps({'parent': space, 'requestId': request_id}),
                      '--json', json.dumps({'text': 'PQ Mail public OpenPGP certificate. Verify its fingerprint independently.',
                                            'attachment': [attached[1]]}))
    cert_message = message_name(cert_result.get('name', ''))
    require(cert_message.startswith(space+'/messages/'), 'Unexpected certificate message destination')
    write_new(bundle/'certificate-sent.json', json.dumps(cert_result, indent=2).encode())
    bundle_request = str(uuid.uuid4())
    write_new(bundle/'bundle-send-request.json', json.dumps({'space': space, 'requestId': bundle_request}).encode())
    result = gws('chat', 'spaces', 'messages', 'create', '--params', json.dumps({'parent': space, 'requestId': bundle_request}),
                 '--json', json.dumps({'text': 'PQ Mail signed OpenPGP bundle.\nCertificate message: '+cert_message,
                                       'attachment': [attached[0]]}))
    write_new(bundle/'sent.json', json.dumps(result, indent=2).encode())
    return {'sent': result.get('name'), 'certificate_message': cert_message, 'requestId': bundle_request}


def linked_certificate_message(result):
    links = re.findall(r'(?<!\S)Certificate message:\s*(\S+)', result.get('text', ''), re.MULTILINE)
    require(len(links) == 1, 'Expected one linked certificate message')
    name = message_name(links[0].strip())
    own = message_name(result.get('name', ''))
    require(name.split('/messages/')[0] == own.split('/messages/')[0] and name != own,
            'Certificate link must stay in this conversation')
    cert = gws('chat', 'spaces', 'messages', 'get', '--params', json.dumps({'name': name}))
    sender = result.get('sender', {}).get('name')
    require(sender and cert.get('sender', {}).get('name') == sender, 'Certificate message sender differs')
    return cert


def receive(message, output):
    message_name(message)
    result = gws('chat', 'spaces', 'messages', 'get', '--params', json.dumps({'name': message}))
    certificate_result = result
    if not any(a.get('contentName') == 'pq-mail-sender-key.pgp' for a in result.get('attachment', [])):
        certificate_result = linked_certificate_message(result)
    out = private_dir(output)
    for wanted, cap in (('message.pgp', MAX_BYTES), ('pq-mail-sender-key.pgp', 1024*1024)):
        source = result if wanted == 'message.pgp' else certificate_result
        matches = [a for a in source.get('attachment', []) if a.get('contentName') == wanted]
        require(len(matches) == 1, 'Expected exactly one '+wanted)
        resource = matches[0].get('attachmentDataRef', {}).get('resourceName', '')
        # Only Chat media references are used; never follow arbitrary downloadUri
        # or Drive links supplied by another participant.
        require(resource and len(resource) < 4096 and re.fullmatch(r'[A-Za-z0-9_./=-]+', resource), 'Invalid media resource')
        require(all(x not in ('.', '..') for x in resource.split('/')), 'Unsafe media path')
        target = out/wanted
        try:
            gws('chat', 'media', 'download', '--params', json.dumps({'resourceName': resource, 'alt': 'media'}),
                '--output', str(target), output=target, cap=cap)
        except Exception:
            target.unlink(missing_ok=True)
            raise
    public_info(out/'pq-mail-sender-key.pgp')
    write_new(out/'transport.json', json.dumps({'name': result.get('name'), 'sender': result.get('sender'),
              'createTime': result.get('createTime'), 'trust': 'Transport metadata is not OpenPGP authentication'}, indent=2).encode())
    return {'downloaded': str(out), 'certificate': public_info(out/'pq-mail-sender-key.pgp'),
            'next': 'Use unpack with an independently selected sender fingerprint; no trust was added.'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('login', help='Separate Google Chat OAuth; no Gmail scopes')
    commands.add_parser('status')
    p = commands.add_parser('spaces'); p.add_argument('--page-token')
    p = commands.add_parser('messages'); p.add_argument('space'); p.add_argument('--page-token')
    p = commands.add_parser('identity'); p.add_argument('--email', required=True); p.add_argument('--level', choices=SUITES, default='3'); p.add_argument('--output', required=True)
    p = commands.add_parser('inspect'); p.add_argument('certificate')
    p = commands.add_parser('pack')
    for name in ('identity', 'recipient-cert', 'recipient-fingerprint', 'sender', 'recipient', 'subject', 'text-file', 'output'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--html-file'); p.add_argument('--attachment', action='append', default=[])
    p.add_argument('--compression', choices=('zip', 'zlib'), default='zip')
    p = commands.add_parser('unpack')
    for name in ('identity', 'bundle', 'signer-cert', 'fingerprint', 'sender', 'recipient', 'output'):
        p.add_argument('--'+name, required=True)
    p = commands.add_parser('send'); p.add_argument('--space', required=True); p.add_argument('--bundle', required=True)
    p = commands.add_parser('receive'); p.add_argument('--message', required=True); p.add_argument('--output', required=True)
    a = parser.parse_args()
    if a.command == 'login':
        print('Select all three Chat permissions. Basic identity consent alone cannot access Chat.', flush=True)
        os.execv(ROOT/'gws-chat', [str(ROOT/'gws-chat'), 'auth', 'login', '--scopes', SCOPES])
    elif a.command == 'status':
        result = gws('auth', 'status')
    elif a.command == 'identity':
        result = generate(a.output, a.email, a.level)
    elif a.command == 'inspect':
        result = public_info(a.certificate)
    elif a.command == 'spaces':
        params = {'pageSize': 100}
        if a.page_token: params['pageToken'] = a.page_token
        result = gws('chat', 'spaces', 'list', '--params', json.dumps(params))
    elif a.command == 'messages':
        params = {'parent': space_name(a.space), 'pageSize': 25, 'orderBy': 'createTime desc'}
        if a.page_token: params['pageToken'] = a.page_token
        result = gws('chat', 'spaces', 'messages', 'list', '--params', json.dumps(params))
    elif a.command == 'pack':
        result = pack(a.identity, a.recipient_cert, a.recipient_fingerprint, a.sender, a.recipient,
                      a.subject, read(a.text_file, 1024*1024).decode('utf-8'),
                      read(a.html_file, 1024*1024).decode('utf-8') if a.html_file else None,
                      a.attachment, a.output, a.compression)
    elif a.command == 'unpack':
        result = unpack(a.identity, a.bundle, a.signer_cert, a.fingerprint, a.sender, a.recipient, a.output)
    elif a.command == 'send':
        result = send(a.space, a.bundle)
    elif a.command == 'receive':
        result = receive(a.message, a.output)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Escape control characters in untrusted diagnostics, including terminal
        # escape sequences. Full message content is never printed on failures.
        print('Standalone Chat: '+json.dumps(str(error)), file=sys.stderr)
        sys.exit(1)
