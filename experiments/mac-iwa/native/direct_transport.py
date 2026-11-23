"""Offline native boundary for browser-owned Google transport.

No OAuth tokens, Google URLs or gws calls enter these operations. The browser
supplies bounded public message bytes for re-verification before saving trust.
Send tickets are consumed before releasing ciphertext, so no uncertain send can
be silently repeated using the same review ticket.
"""
import base64,json,re,time
from email import policy
from email.parser import BytesParser
from chat_bridge import LIMIT

def action(b,r):
    op=r['op']
    if op=='chat-browser-prepare':
        if r['service'] not in ('Gmail','Chat'):raise ValueError('Unknown service')
        space=b.chat.space_name(r['space']) if r['service']=='Chat' else 'Gmail'
        contact,peer=b.peer(r['contact'])
        return b.prepare_browser_signature(r,contact,peer,r['service'],space)
    if op in ('chat-browser-cert-save','chat-browser-cert-trust'):
        from gmail_bridge import signed_message,save_signer
        raw=base64.b64decode(r['raw'],validate=True)
        if len(raw)>LIMIT:raise ValueError('Message limit')
        result=signed_message(b,raw,BytesParser(policy=policy.default).parsebytes(raw))
        request={**r,'op':'chat-mail-cert-trust' if op.endswith('trust') else 'chat-mail-cert-save'}
        return save_signer(b,result,request)
    if op=='chat-browser-export':
        if r['service'] not in ('Gmail','Chat') or r['confirmed'] is not True:raise ValueError('Confirmation required')
        rid=r['review']
        if not re.fullmatch('[a-f0-9]{48}',rid):raise ValueError('Bad review')
        prefix='mail-' if r['service']=='Gmail' else ''
        draft=b.data/(prefix+'draft-'+rid)
        review=json.loads((draft/'review.json').read_text())
        if time.time()-review['created']>600:raise ValueError('Review expired')
        contact,_=b.peer(review['contact'])
        if contact['email']!=review['recipient'] or contact['fingerprint']!=review['fingerprint']:raise ValueError('Recipient trust changed')
        # Recheck the trusted recipient binding before releasing a send ticket.
        if prefix:
            from email.utils import getaddresses
            raw=(draft/'message.eml').read_bytes()
            addresses=getaddresses(BytesParser(policy=policy.default).parsebytes(raw).get_all('To',[]))
            if len(addresses)!=1 or not any(c['email']==addresses[0][1] for c in b.contacts()):raise ValueError('Recipient trust changed')
            result={'raw':base64.b64encode(raw).decode()}
        else:
            manifest=json.loads((draft/'manifest.json').read_text())
            if not any(c['email']==manifest['recipient'] and c['fingerprint']==manifest['recipient_fingerprint'] for c in b.contacts()):raise ValueError('Recipient trust changed')
            result={'space':b.chat.space_name(review['space']),'cipher':base64.b64encode((draft/'message.pgp').read_bytes()).decode(),'certificate':base64.b64encode((draft/'pq-mail-sender-key.pgp').read_bytes()).decode()}
        # This records an export attempt, not proof of Google delivery.
        draft.rename(b.data/(prefix+'exported-'+rid))
        return result
    raise ValueError('Unsupported offline operation')
