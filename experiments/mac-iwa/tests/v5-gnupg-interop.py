#!/usr/bin/env python3
"""Independent, software-only v5 interoperability with unmodified GnuPG 2.5.

Run the opt-in Rust exporter first using a NEW private temporary directory:
  IWA_V5_FIXTURE_DIR=/tmp/new-fixture cargo test --lib \
    libre::tests::export_disposable_v5_fixture -- --exact
Then run this script with --fixture, --gpg, --agent and --libgcrypt paths.
Finally run Rust's import test with IWA_V5_IMPORT_FIXTURE_DIR set to the same
fixture. These test artifacts include plaintext SYNTHETIC secrets: never use
real keys, install the artifacts, or publish them. No hardware tool is called.
"""
import argparse, base64, ctypes as c, json, os, subprocess, tempfile
from pathlib import Path
os.umask(0o077)
parser=argparse.ArgumentParser(description=__doc__)
for name in ('fixture','gpg','agent','libgcrypt'):
    parser.add_argument('--'+name,required=True)
args=parser.parse_args();f=Path(args.fixture).resolve()
assert (f/'seeds-test-only.json').is_file(), 'Disposable Rust fixture required'
# An independent keyring prevents accidental access to the user's agent, keys,
# trust records, or configuration; smartcard operations are explicitly disabled.
home=Path(tempfile.mkdtemp(prefix='iwa-v5-gpg-'))
lib=c.CDLL(args.libgcrypt);lib.gcry_check_version.restype=c.c_char_p
assert lib.gcry_check_version(None), 'libgcrypt initialization failed'
s={k:base64.b64decode(v) for k,v in json.loads((f/'seeds-test-only.json').read_text()).items()}
b=(f/'public.pgp').read_bytes();a=0
while a<len(b):
 n=int.from_bytes(b[a+2:a+6],'big');body=b[a+6:a+6+n]
 if b[a]&63==14: material=body[10:];xp=material[7:39];mp=material[43:];assert len(xp)==32 and len(mp)==1184
 a+=6+n
lib.gcry_sexp_new.argtypes=[c.POINTER(c.c_void_p),c.c_void_p,c.c_size_t,c.c_int];lib.gcry_sexp_new.restype=c.c_uint
lib.gcry_pk_genkey.argtypes=[c.POINTER(c.c_void_p),c.c_void_p];lib.gcry_pk_genkey.restype=c.c_uint
lib.gcry_sexp_find_token.argtypes=[c.c_void_p,c.c_char_p,c.c_size_t];lib.gcry_sexp_find_token.restype=c.c_void_p
lib.gcry_sexp_sprint.argtypes=[c.c_void_p,c.c_int,c.c_void_p,c.c_size_t];lib.gcry_sexp_sprint.restype=c.c_size_t
lib.gcry_pk_get_keygrip.argtypes=[c.c_void_p,c.c_void_p];lib.gcry_pk_get_keygrip.restype=c.c_void_p
lib.gcry_sexp_release.argtypes=[c.c_void_p]
def parse(text):
 obj=c.c_void_p();assert lib.gcry_sexp_new(c.byref(obj),text,len(text),1)==0;return obj
# GnuPG normalizes algorithm-8 X25519 to its legacy cv25519 component.
# Its private scalar is clamped and encoded big-endian; the wire point
# remains little-endian. This affects only the disposable agent fixture.
scalar=bytearray(s['x25519']);scalar[0]&=248;scalar[31]&=127;scalar[31]|=64;scalar.reverse()
x=parse(('(private-key(ecc(curve Curve25519)(flags djb-tweak)(q #40'+xp.hex()+'#)(d #'+scalar.hex()+'#)))').encode())
p=parse(('(genkey(kyber768(derive-parms(seed #'+s['mlkem768'].hex()+'#))))').encode());full=c.c_void_p();assert lib.gcry_pk_genkey(c.byref(full),p)==0
ml=lib.gcry_sexp_find_token(full,b'private-key',0);assert ml
for obj in (x,ml):
 grip=c.create_string_buffer(20);assert lib.gcry_pk_get_keygrip(obj,grip);size=lib.gcry_sexp_sprint(obj,1,None,0);buf=c.create_string_buffer(size);length=lib.gcry_sexp_sprint(obj,1,buf,size)
 file=home/'private-keys-v1.d'/(grip.raw.hex().upper()+'.key');file.parent.mkdir(exist_ok=True);file.write_bytes(buf.raw[:length]);file.chmod(0o600);print('Installed synthetic component',grip.raw.hex().upper())

# Stock GnuPG imports the signing key, but algorithm-8 secret-subkey packet
# import is unsupported. Supply only its public subkey in the import file;
# the two synthetic component files above supply decryption to its normal agent.
wire=(f/'secret-test-only.pgp').read_bytes();pos=0;signing=bytearray()
while pos<len(wire):
    assert wire[pos+1]==255
    length=int.from_bytes(wire[pos+2:pos+6],'big');body=wire[pos+6:pos+6+length]
    if wire[pos]&63==7:
        public=body[:10+int.from_bytes(body[6:10],'big')]
        signing+=bytes([0xce,255])+len(public).to_bytes(4,'big')+public
    else:
        signing+=wire[pos:pos+6+length]
    pos+=6+length
(f/'signing-test-only.pgp').write_bytes(signing)
command=[args.gpg,'--homedir',str(home),'--agent-program',args.agent,'--batch','--yes',
         '--no-tty','--pinentry-mode','loopback','--passphrase','','--status-fd','1']
# The temporary agent must never discover a connected smartcard. If fixture
# installation is wrong the test fails with a missing key, not a card prompt.
(home/'gpg-agent.conf').write_text('disable-scdaemon\n')
results=[]
def run(label,arguments,required=()):
    result=subprocess.run(command+arguments,capture_output=True,timeout=90)
    status=result.stdout+result.stderr
    (f/('gnupg-'+label+'.log')).write_bytes(status)
    assert result.returncode==0, label+' failed; inspect test-only log'
    assert all(token in status for token in required), label+' lacked required status'
    results.append(label)
run('import',['--import',str(f/'signing-test-only.pgp')])
run('verify',['--verify',str(f/'signature.pgp'),str(f/'payload.bin')],(b'[GNUPG:] VALIDSIG',))
run('decrypt',['--output',str(home/'clear.bin'),'--decrypt',str(f/'encrypted.pgp')],
    (b'[GNUPG:] DECRYPTION_OKAY',b'[GNUPG:] GOODMDC',b'[GNUPG:] VALIDSIG'))
assert (home/'clear.bin').read_bytes()==(f/'payload.bin').read_bytes()
for mode,flags in [('return',[]),('return-ocb',['--force-ocb'])]:
    run(mode,flags+['--trust-model','always','--compress-algo','none',
       '-r','fixture@example.invalid','-u','fixture@example.invalid','--output',
       str(f/('gpg-'+mode+'.pgp')),'--sign','--encrypt',str(f/'payload.bin')])
(f/'gnupg-result.json').write_text(json.dumps({'status':'PASS','checks':results,
    'hardwareOperations':0,'syntheticSecrets':True},indent=2)+'\n')
print('PASS stock GnuPG verification/decryption; MDC and OCB replies ready for Rust import test.')
