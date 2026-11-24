#!/usr/bin/python3
"""Experimental Chrome Native Messaging host; deliberately no general RPC.

The IWA owns test orchestration, messages and public inventory. This helper
exposes bounded public reads and authorized private components only. Executable
paths are installed configuration; no token write/provisioning API exists.
"""
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'native'))
MAX_FRAME = 524288


def frame_read(stream):
    # Chrome uses a 32-bit native-endian unsigned byte count. Refuse oversized
    # or truncated frames before allocating or interpreting any JSON content.
    header = stream.read(4)
    if not header: return None
    if len(header) != 4: raise ValueError('Truncated header')
    size = struct.unpack('=I', header)[0]
    if not 0 < size <= MAX_FRAME: raise ValueError('Frame too large')
    raw = stream.read(size)
    if len(raw) != size: raise ValueError('Truncated frame')
    value = json.loads(raw)
    if not isinstance(value, dict): raise ValueError('Object required')
    return value


def frame_write(value):
    # Never put subprocess stdout on this stream: that would corrupt framing
    # and might disclose local diagnostic data to the browser.
    raw = json.dumps(value).encode()
    sys.stdout.buffer.write(struct.pack('=I', len(raw)) + raw)
    sys.stdout.buffer.flush()


def validate_request(request):
    if isinstance(request.get('op'),str) and request['op'].startswith('chat-'):
        from chat_bridge import validate
        return validate(request)
    if set(request) != {'op'} or request['op'] != 'status':
        raise ValueError('Unsupported operation')
    return request['op']


def detected(cfg):
    value = subprocess.check_output([cfg['ykman'], 'list', '--serials'], stderr=subprocess.DEVNULL, timeout=25)
    return cfg['serial'] in value.decode().split()


def operation_error(op, error=None):
    """Return fixed, operation-specific guidance without exposing CLI secrets.

    Connection failures happen before the hardware operation. Keep them separate
    from signing/decryption failures so users do not unnecessarily retry a PIN.
    """
    if op and op.startswith('chat-'):
        # Only fixed pre-crypto labels get this explanation. Never expose the
        # exception text/output or turn a private-operation error into a retry.
        if str(error)=='PIN dialog timed out before submission':
            return 'The native PIN dialog timed out before submission. No PIN was sent to the YubiKey. Start the operation again and look for the YubiKey PIN dialog or pin-prompt in the Dock or Command-Tab.'
        if str(error)=='PIN cancelled or invalid':
            return 'PIN entry was cancelled or its format was rejected locally. No PIN was sent to the YubiKey. No automatic retry was performed.'
        # Only a strictly numeric serial from our pre-PIN presence check may
        # enter this guidance. Never surface arbitrary backend exception text.
        missing=re.fullmatch(r'Connect YubiKey ([1-9][0-9]{0,9})',str(error))
        if missing and int(missing.group(1))<=2147483647:
            return 'Connect YubiKey '+missing.group(1)+'. No PIN was submitted. Retry only after connecting that key.'
    if op in ('chat-selected-signing-material','chat-selected-decryption-material'):
        return 'Selected identity review stopped. Connect the selected YubiKey and restore its current bundle if certificates changed. The signed bundle, exact public certificate and live keys must match. No PIN was submitted and no card data was changed.'
    if op in ('chat-identity-bundle-read','chat-identity-key-snapshot','chat-identity-companion-read','chat-identity-devices'):
        return 'Public YubiKey read stopped. Connect the configured YubiKey and retry with its current public bundle. No PIN was submitted and no card or identity data was changed.'
    if op=='chat-hardware-audit':
        return 'Read-only hardware audit stopped. The selected signed bundle, device, public keys or metadata could not be read consistently. No PIN was requested and unchanged status is unconfirmed.'
    if op=='chat-identity-current':
        return 'The configured public identity could not be read. No YubiKey operation was attempted.'
    if op=='chat-certificate-migration':
        return 'Legacy public-certificate export stopped. Check the old store for conflicting, malformed or oversized records. No certificates or trust were changed. No YubiKey operation was attempted.'
    if op=='chat-decryption-material':
        return 'The configured public decryption identity could not be read. No YubiKey operation was attempted.'
    if op in ('chat-sign-digest','chat-decapsulate-components'):
        return 'YubiKey operation stopped. Check the configured key and native PIN dialog. No automatic private-operation retry was performed.'
    if op and op.startswith('chat-vault-'):
        # Reflect only our fixed diagnostics, never arbitrary exceptions, native
        # stderr, PINs or secret output. Cancellation is not a token PIN failure.
        # PIV_UNLOCK_DIAGNOSTICS: these fixed component labels consume the
        # status protocol from chat_bridge.py and crypto/src/main.rs. They may
        # remain when disk history is removed. If removing the protocol too,
        # retain a generic failure response: never expose str(error)/raw stderr
        # or add an automatic private-operation retry.
        reasons={'PIN cancelled or invalid':'PIN dialog cancelled or local PIN format rejected',
                 'Vault crypto MLKEM_FAILED':'ML-KEM-768 PKCS#11 component failed',
                 'Vault crypto X25519_FAILED':'X25519 PKCS#11 component failed',
                 'Vault crypto ADAPTER_TIMEOUT_OR_INPUT':'PKCS#11 adapter timed out or rejected input',
                 'Vault crypto MLKEM_RESPONSE_SIZE':'ML-KEM-768 returned an invalid response length',
                 'Vault crypto X25519_RESPONSE_SIZE':'X25519 returned an invalid response length',
                 'Vault crypto CRYPTO_FAILED':'native cryptographic validation failed (unclassified)',
                 'Vault helper timeout':'native cryptographic helper timed out',
                 'Expected YubiKey not connected':'configured YubiKey not connected',
                 'Cryptographic operation failed; no retry':'PKCS#11 decapsulation failed',
                 'Wrong PIV key':'public-key mismatch',
                 'Required vault YubiKey absent':'configured classical PIV key not connected'}
        reason=reasons.get(str(error),'native vault operation could not complete')
        return 'Vault stopped: '+reason+'. No retry or vault write was performed.'
    if op and op.startswith('chat-'):
        return 'Unsupported or failed hardware operation. No automatic cryptographic retry was performed.'
    return 'Operation stopped. Check the key connection or native dialog. No automatic retry; unchanged status is unconfirmed unless the saved comparison completed.'


def main():
    os.umask(0o077)
    cfg = json.loads((ROOT/'private/config.json').read_text())
    # Chrome authenticates the extension against allowed_origins in the host
    # manifest. Recheck its caller argument here; do not accept arbitrary callers.
    if len(sys.argv) < 2 or sys.argv[1] != 'chrome-extension://'+cfg['extension_id']+'/': return 1
    op = None
    try:
        while True:
            request = frame_read(sys.stdin.buffer)
            if request is None: break
            op = validate_request(request)
            if op == 'status':
                frame_write({'type':'result','connected':detected(cfg),'serial':cfg['serial'],'backend':'Sequoia Level3Signer / Level3Decryptor → existing PKCS#11 helpers'})
            else:
                from chat_bridge import ChatBridge
                frame_write({'type':'result','data':ChatBridge(ROOT,cfg,frame_write).action(request)})
    except Exception as e:
        # Avoid reflecting low-level errors, PINs, or environment data. The IWA
        # owns its bounded public audit result; raw worker diagnostics stay here.
        message = operation_error(op, e)
        frame_write({'type':'error','message':message})
        return 1
    return 0

if __name__ == '__main__': sys.exit(main())
