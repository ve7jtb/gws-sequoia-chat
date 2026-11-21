#!/usr/bin/env python3
"""Add Chat to an existing experimental native-helper installation.

Copies only OAuth client registration metadata, never an existing Google refresh
credential. Does not log in, send messages, trust contacts or access a YubiKey.
"""
import argparse,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('installed','transport-root','gws-bin','sq-bin','oauth-client','crypto-bin'):p.add_argument('--'+name,required=True,type=Path)
 p.add_argument('--email',required=True);a=p.parse_args();os.umask(0o077)
 if '@' not in a.email or any(c.isspace() or c in '<>' for c in a.email):raise ValueError('Explicit email required')
 dest=a.installed.resolve();cfg=json.loads((dest/'private/config.json').read_text())
 target=dest/'runtime/chat';(target/'bin').mkdir(parents=True,exist_ok=True);(target/'private/gws').mkdir(parents=True,exist_ok=True,mode=0o700)
 for name in ('chat.py','gws-chat','mail_transport.py'):shutil.copy2(a.transport_root/name,target/name)
 # Native login originally omitted USER/USERNAME, selecting gws's fixed
 # unknown-user Keychain account. Preserve that account for every IWA command
 # so browser launches and Terminal diagnostics decrypt the same saved session.
 # This changes only this installation's wrapper, never other gws profiles.
 wrapper=target/'gws-chat'
 wrapper.write_text(wrapper.read_text().replace('set -eu', 'set -eu\n# Keep the native-login Keychain account stable.\nexport USER=unknown-user\nunset USERNAME',1))
 for source,name in ((a.gws_bin,'gws'),(a.sq_bin,'sq'),(a.transport_root/'bin/chat-software-identity','chat-software-identity')):shutil.copy2(source,target/'bin'/name)
 client=target/'private/gws/client_secret.json'
 if not client.exists():shutil.copy2(a.oauth_client,client);client.chmod(0o600)
 shutil.copy2(a.crypto_bin,dest/'runtime/sequoia-iwa-crypto')
 for name in ('host.py','chat_bridge.py','gmail_bridge.py'):shutil.copy2(ROOT/'native'/name,dest/'native'/name)
 subprocess.run(['/usr/bin/swiftc',str(ROOT/'native/PinPrompt.swift'),'-o',str(dest/'build/pin-prompt')],check=True)
 cfg['chat_email']=a.email;(dest/'private/config.json').write_text(json.dumps(cfg,indent=2))
 print('Chat helper installed. Authorize its separate Google session in the IWA.')
if __name__=='__main__':main()
