"""Local public-certificate inventory. Never reads account tokens or private keys.

Trust removal preserves public material; deletion removes both active copies and
all email bindings for the exact full fingerprint. Calls run under the bridge's
operation lock, and destructive routes require explicit UI confirmation.
"""
import base64,json,re,subprocess

FP=re.compile(r'(?:[A-F0-9]{40}|[A-F0-9]{64})')
FIELDS={'chat-cert-list':set(),'chat-cert-untrust':{'fingerprint','email','confirmed'},'chat-cert-delete':{'fingerprint','confirmed'}}

def paths(data,fp):
    if not FP.fullmatch(fp):raise ValueError('Full primary fingerprint required')
    return [data/(fp+'.pgp'),data/('mail-cert-'+fp+'.pgp')]

def certificates(data):
    result={}
    for path in sorted(data.glob('*.pgp')):
        fp=path.stem.removeprefix('mail-cert-') if hasattr(str,'removeprefix') else path.stem.replace('mail-cert-','',1)
        if FP.fullmatch(fp):result.setdefault(fp,[]).append(path)
    return result

def bindings(data):
    for pattern in ('contact-*.json','mail-trust-*.json'):
        for path in sorted(data.glob(pattern)):
            record=json.loads(path.read_text())
            if FP.fullmatch(record.get('fingerprint','')) and isinstance(record.get('email'),str):yield path,record

def inventory(b):
    records=list(bindings(b.data));rows=[]
    for fp,copies in certificates(b.data).items():
        size=copies[0].stat().st_size
        info={'version':'unknown','algorithms':[],'emails':[]}
        if size<=262144:
            request={'op':'inspect-public','certificate':base64.b64encode(copies[0].read_bytes()).decode()}
            worker=subprocess.run([str(b.root/'runtime/sequoia-iwa-crypto')],input=json.dumps(request).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            if worker.returncode==0 and len(worker.stdout)<=32768:
                value=json.loads(worker.stdout)
                if value.get('fingerprint')==fp:info=value
        rows.append({'fingerprint':fp,'version':info['version'],'algorithms':info['algorithms'],
            'trustedEmails':sorted({r['email'] for _,r in records if r['fingerprint']==fp}),
            'emails':info['emails'],'hybridContact':any(p.name.startswith('contact-') and r['fingerprint']==fp for p,r in records)})
    return rows

def action(b,r):
    if r['op']=='chat-cert-list':return {'certificates':inventory(b),'contacts':b.contacts()}
    if r['op'] not in ('chat-cert-untrust','chat-cert-delete'):raise ValueError('Unsupported certificate operation')
    if r.get('confirmed') is not True:raise ValueError('Confirmation required')
    fp=r['fingerprint'];copies=paths(b.data,fp)
    if not any(p.exists() for p in copies):raise ValueError('Saved certificate no longer exists')
    # Delete only the exact selected email binding, or every binding when the
    # user confirms deleting this public certificate. Other keys remain intact.
    for path,record in list(bindings(b.data)):
        if record['fingerprint']==fp and (r['op']=='chat-cert-delete' or record['email']==r['email']):path.unlink()
    if r['op']=='chat-cert-delete':
        for path in copies:
            if path.exists():path.unlink()
    elif r['op']!='chat-cert-untrust':raise ValueError('Unsupported certificate operation')
    return {'certificates':inventory(b),'contacts':b.contacts()}
