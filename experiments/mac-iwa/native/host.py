#!/usr/bin/python3
"""Experimental Chrome Native Messaging host; deliberately no general RPC.

A closed Chat API and fixed synthetic Level 3 test are exposed. Paths, serial,
certificate and executable are administrator/user-installed local configuration,
never supplied by the browser. No token write/provisioning API is implemented.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

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
    if set(request) != {'op'} or request['op'] not in ('status', 'test'):
        raise ValueError('Unsupported operation')
    return request['op']


def detected(cfg):
    value = subprocess.check_output([cfg['ykman'], 'list', '--serials'], stderr=subprocess.DEVNULL, timeout=25)
    return cfg['serial'] in value.decode().split()


def run_test(cfg, emit=frame_write):
    # A process-wide flock prevents parallel browser windows from consuming
    # several PIN attempts or starting competing smart-card transactions.
    with (ROOT/'private/test.lock').open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('Test already running')
        if not detected(cfg): raise ValueError('Expected key is not connected')
        out = ROOT/'private'/('hardware-'+time.strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(3).hex())
        command = ['/usr/bin/python3', '-I', '-B', cfg['runner']]
        for key in ('app','java','ykman','binary','cert','serial','classpath'):
            command += ['--'+key, cfg[key]]
        command += ['--out', str(out)]
        emit({'type':'progress','message':'Reading all 24 PIV slot states and comparing public keys…'})
        # The unchanged adapter utility reads /dev/tty. A private PTY supplies
        # that controlling terminal; only this host can write to it. We require
        # echo to be disabled before delivering the native dialog's PIN.
        pid, fd = pty.fork()
        if pid == 0:
            env = {k:v for k,v in os.environ.items() if k in ('HOME','PATH','TMPDIR','LANG')}
            os.execve(command[0], command, env)
        pending = b''
        prompts = 0
        labels = ('Hybrid signing: ML-DSA-65 (9c) + Ed25519 (84)',
                  'Hybrid decryption: ML-KEM-768 (9d) + X25519 (85)',
                  'Independent PQ Mail ciphertext: ML-KEM-768 (9d) + X25519 (85)')
        deadline = time.monotonic()+900
        exited = False
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([fd], [], [], .25)
                if readable:
                    try: chunk = os.read(fd, 4096)
                    except OSError: chunk = b''
                    if not chunk: break
                    pending = (pending + chunk)[-16384:]
                    marker = b'YubiKey PIN (not saved): '
                    if marker in pending:
                        pending = pending.split(marker,1)[1]
                        if prompts >= len(labels): raise ValueError('Unexpected additional PIN prompt')
                        # rpassword writes its prompt immediately before disabling
                        # terminal echo; allow that transition without sending data.
                        for _ in range(100):
                            if not termios.tcgetattr(fd)[3] & termios.ECHO: break
                            time.sleep(.01)
                        else: raise ValueError('Refusing PIN entry into an echoing terminal')
                        emit({'type':'progress','message':labels[prompts]+' — authorize in the Mac dialog, then touch if requested.'})
                        ui = subprocess.run([str(ROOT/'build/pin-prompt'),labels[prompts],cfg['serial']],
                                            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=180)
                        pin = bytearray(ui.stdout)
                        try:
                            if ui.returncode or not 6 <= len(pin) <= 8 or any(c < 32 or c > 126 for c in pin):
                                raise ValueError('PIN entry cancelled or invalid; no automatic retry')
                            if termios.tcgetattr(fd)[3] & termios.ECHO: raise ValueError('Terminal echo changed')
                            os.write(fd, pin + b'\n')
                        finally:
                            pin[:] = b'\0'*len(pin)
                            del ui
                        prompts += 1
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    exited = True
                    break
            else: raise ValueError('Hardware test timed out')
            if not exited:
                _, status = os.waitpid(pid,0); exited = True
            passed = os.waitstatus_to_exitcode(status) == 0 and (out/'result.txt').is_file()
            unchanged = (out/'unchanged.txt').is_file()
            result = {'type':'result','passed':passed,'unchanged':unchanged,'pinOperations':prompts,'resultDirectory':str(out)}
            # The result has only fixed test status and public metadata. No raw
            # CLI output or arbitrary files can be fetched through this host.
            (out/'iwa-result.json').write_text(json.dumps(result,indent=2)) if out.is_dir() else None
            return result
        finally:
            os.close(fd)
            if not exited:
                with contextlib.suppress(ProcessLookupError): os.killpg(pid,signal.SIGTERM)
                os.waitpid(pid,0)


def operation_error(op):
    """Return fixed, operation-specific guidance without exposing CLI secrets.

    Connection failures happen before the hardware operation. Keep them separate
    from signing/decryption failures so users do not unnecessarily retry a PIN.
    """
    if op in ('chat-mail-login','chat-mail-connect','chat-mail-list','chat-mail-read'):
        return 'Gmail connection failed. Complete Google sign-in with Gmail read and send permissions, then reconnect Gmail. No YubiKey operation was attempted.'
    if op in ('chat-login','chat-spaces','chat-messages'):
        return 'Google Chat connection failed. Complete Google sign-in and all three Chat permissions, then reconnect. No YubiKey operation was attempted.'
    if op and op.startswith('chat-mail-'):
        return 'Gmail operation stopped. Check the Gmail connection, selected trusted certificate and any native PIN dialog. No automatic send or cryptographic retry was performed.'
    if op and op.startswith('chat-'):
        return 'Chat operation stopped. Check the selected trusted certificate and any native PIN dialog. No automatic send or cryptographic retry was performed.'
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
            elif op == 'test': frame_write(run_test(cfg))
            else:
                from chat_bridge import ChatBridge
                frame_write({'type':'result','data':ChatBridge(ROOT,cfg,frame_write).action(request)})
    except Exception:
        # Avoid reflecting low-level errors, PINs, or environment data. Full
        # public test diagnostics remain only in the local hardware result folder.
        message = operation_error(op)
        frame_write({'type':'error','message':message})
        return 1
    return 0

if __name__ == '__main__': sys.exit(main())
