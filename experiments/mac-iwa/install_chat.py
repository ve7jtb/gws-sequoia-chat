#!/usr/bin/env python3
"""Add Chat to an existing experimental native-helper installation.

Does not install gws or OAuth client secrets. Does not log in, send messages, trust contacts or access a YubiKey.
"""
import argparse,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('installed','transport-root','sq-bin','crypto-bin'):p.add_argument('--'+name,required=True,type=Path)
 p.add_argument('--email',required=True);a=p.parse_args();os.umask(0o077)
 if '@' not in a.email or any(c.isspace() or c in '<>' for c in a.email):raise ValueError('Explicit email required')
 dest=a.installed.resolve();cfg=json.loads((dest/'private/config.json').read_text())
 target=dest/'runtime/chat';(target/'bin').mkdir(parents=True,exist_ok=True);
 for name in ('chat.py','mail_transport.py'):shutil.copy2(a.transport_root/name,target/name)
 for source,name in ((a.sq_bin,'sq'),(a.transport_root/'bin/chat-software-identity','chat-software-identity')):shutil.copy2(source,target/'bin'/name)
 shutil.copy2(a.crypto_bin,dest/'runtime/sequoia-iwa-crypto')
 for name in ('host.py','chat_bridge.py','certificate_migration.py','signing.py','vault_piv.py'):shutil.copy2(ROOT/'native'/name,dest/'native'/name)
 subprocess.run(['/usr/bin/swiftc',str(ROOT/'native/PinPrompt.swift'),'-o',str(dest/'build/pin-prompt')],check=True)
 cfg['chat_email']=a.email;(dest/'private/config.json').write_text(json.dumps(cfg,indent=2))
 print('Chat helper installed. Authorize Google through the browser extension; gws is not required.')
if __name__=='__main__':main()
