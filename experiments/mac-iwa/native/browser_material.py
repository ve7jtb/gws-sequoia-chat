"""Read-only, bounded public verification material; no tokens or private keys."""
import base64
from cert_store import certificates,bindings

def material(b):
    certs=[];saved=[];budget=200000
    for fp,paths in sorted(certificates(b.data).items()):
        raw=paths[0].read_bytes()
        if len(certs)>=24 or len(raw)>budget:raise ValueError('Public certificate budget exceeded')
        budget-=len(raw);certs.append(base64.b64encode(raw).decode());saved.append(fp)
    trust=[{'email':c['email'],'fingerprint':c['fingerprint']} for _,c in bindings(b.data)]
    if len(trust)>256:raise ValueError('Too many trust bindings')
    return {'certificates':certs,'saved':saved,'bindings':trust}
