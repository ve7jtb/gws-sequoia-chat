"""Make public-only test vectors using the native OpenSSL verifier as oracle.

MIME extraction remains native Python. No mail API, account token or YubiKey is
used. User-supplied Proton files are never embedded in the distributable IWA.
"""
import argparse,base64,json,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--proton',type=Path);p.add_argument('--tampered',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
cases=[]
def add(name,request,wanted):
    run=subprocess.run([str(a.native)],input=json.dumps({'op':'verify-detached',**request}).encode(),stdout=subprocess.PIPE,check=True)
    expected=json.loads(run.stdout)['signatures']
    assert expected and all(s['status']==wanted for s in expected),(name,expected)
    cases.append({'name':name,'request':request,'expected':expected})
for kind in ('v4','v6'):
    request=json.loads((a.fixtures/(kind+'.json')).read_text())
    add(kind+' valid',request,'valid')
    add(kind+' altered body',{**request,'payload':base64.b64encode(b'altered body').decode()},'invalid')
    add(kind+' missing certificate',{**request,'certificates':[]},'unknown-key')
if a.proton:
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'native'))
    import gmail_bridge as g
    for name,path,wanted in [('Proton original',a.proton,'valid'),('Proton altered body',a.tampered,'invalid')]:
        raw=path.read_bytes();msg=g.BytesParser(policy=g.policy.default).parsebytes(raw)
        payload,signature,_=g.signed_parts(raw,msg)
        certs=[base64.b64encode(part.get_payload(decode=True)).decode() for part in msg.walk() if part.get_content_type()=='application/pgp-keys']
        assert certs,'Proton fixture must contain its public certificate'
        add(name,{'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(signature).decode(),'certificates':certs},wanted)
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps({'version':1,'cases':cases}))
print(f'Prepared {len(cases)} public verification cases; no private keys or trust records.')
