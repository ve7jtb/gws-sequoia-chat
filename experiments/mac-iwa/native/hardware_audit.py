"""Read-only, bounded before/after evidence for IWA-owned hardware tests.

The browser names a previously restored identity using public identifiers. The
native helper authenticates it afresh, then inspects every ordinary PIV slot
through its installed ykman executable. No PIN, reset, generation, import,
policy setter, management-key operation or browser-selected command exists.
"""
import hashlib
import re
import subprocess

from identities import PUBLIC_SLOTS,selected,selection
from signing import backend_hash

MAX_OUTPUT=16384
FIELDS={'Algorithm':'algorithm','Origin':'origin','PIN policy':'pinPolicy','Touch policy':'touchPolicy'}
EMPTY_SLOT_ERRORS={
    'APDU error: SW=0x6A88',
    'Error: APDU error: SW=0x6A88',
    'Error: Failed to get slot metadata: Connection error: APDU error: SW=0x6A88',
}


def command(bridge,arguments,limit=MAX_OUTPUT):
    """Invoke one fixed read command, discarding raw diagnostics at the boundary.

    Metadata/SPKI output contains only public material. stdin is closed so even
    an unexpected tool prompt cannot acquire a PIN. The process is not retried:
    a transport failure must never be interpreted as an unoccupied key slot.
    """
    result=subprocess.run([bridge.cfg['ykman'],*arguments],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
    if len(result.stdout)>limit or len(result.stderr)>MAX_OUTPUT:
        raise ValueError('Hardware audit output limit')
    return result


def presence(bridge,serial):
    result=command(bridge,['list','--serials'])
    if result.returncode or serial not in result.stdout.decode('ascii').split():
        raise ValueError('Selected hardware audit key absent')


def retries(bridge,serial):
    result=command(bridge,['--device',serial,'piv','info'])
    if result.returncode:raise ValueError('Could not read PIN retry metadata')
    matches=re.findall(rb'^PIN tries remaining:\s*(\d+)/(\d+)\s*$',result.stdout,re.MULTILINE)
    if len(matches)!=1:raise ValueError('Ambiguous PIN retry metadata')
    remaining,maximum=map(int,matches[0])
    if not 0<=remaining<=maximum<=255 or maximum<1:
        raise ValueError('Invalid PIN retry metadata')
    return {'remaining':remaining,'maximum':maximum}


def slots(bridge,serial):
    result=[]
    for slot in PUBLIC_SLOTS:
        prefix=['--device',serial,'piv','keys']
        metadata=command(bridge,[*prefix,'info',slot])
        if metadata.returncode:
            # Only an explicit absent-object status may represent an empty
            # slot. Other APDU/PCSC/USB failures abort the whole audit.
            error=metadata.stderr.decode('ascii','strict').strip()
            # Current ykman wraps the absent-object APDU in its metadata and
            # transport labels. Accept only these observed complete messages;
            # a substring match could hide an additional USB/PCSC failure.
            if error not in EMPTY_SLOT_ERRORS:
                raise ValueError('Incomplete hardware slot audit')
            result.append({'slot':slot,'publicKeySha256':None,**{field:None for field in FIELDS.values()}})
            continue
        values={}
        for line in metadata.stdout.decode('ascii','strict').splitlines():
            label,sep,value=line.partition(':')
            if label.strip() not in FIELDS:continue
            field=FIELDS[label.strip()];value=value.strip()
            if field in values or not re.fullmatch(r'[A-Za-z0-9 _().+-]{1,80}',value):
                raise ValueError('Ambiguous public key policy metadata')
            values[field]=value
        if set(values)!=set(FIELDS.values()):raise ValueError('Incomplete public key policy metadata')
        public=command(bridge,[*prefix,'export','--format','der',slot,'-'],8192)
        if public.returncode or not public.stdout:raise ValueError('Incomplete public key read')
        result.append({'slot':slot,'publicKeySha256':hashlib.sha256(public.stdout).hexdigest(),**values})
    return result


def snapshot(bridge,identity):
    """Produce stable public evidence, not a private-operation authorization.

    Validate the signed bundle and selected public certificate before reading
    policy metadata. Read all 24 slots twice and bracket them with presence and
    PIN-retry reads; an external card/key/policy change invalidates this result.
    Browser comparisons never replace the independent checks in signing and
    decapsulation. An incomplete after-read reports unchanged status unknown.
    """
    choice=selection(identity)
    context,_=selected(bridge,choice)
    if any(context.get(k)!=v for k,v in choice.items()):raise ValueError('Audit identity mismatch')
    serial=choice['serial'];before_backend=backend_hash(bridge)
    bridge.emit({'type':'progress','message':'Reading all 24 PIV slot keys and policies twice — no PIN or touch required.'})
    presence(bridge,serial);pin=retries(bridge,serial)
    first=slots(bridge,serial);second=slots(bridge,serial)
    after_pin=retries(bridge,serial);presence(bridge,serial)
    after_backend=backend_hash(bridge)
    if first!=second or pin!=after_pin or before_backend!=after_backend:
        raise ValueError('Hardware changed during audit')
    return {'format':'sequoia-iwa-hardware-audit','version':1,'identity':choice,
            'slots':first,'pinRetries':pin,'backendHash':before_backend}
