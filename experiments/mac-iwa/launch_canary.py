#!/usr/bin/env python3
"""Launch the experiment in its own Canary profile; no token operation starts."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parent
if __name__=='__main__':
    bundle=ROOT/'build/sequoia-lab.swbn'
    if not bundle.is_file():raise SystemExit('Build the signed IWA first')
    subprocess.Popen(['/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
        '--user-data-dir='+str(ROOT/'private/chrome-profile'),
        '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode',
        '--install-isolated-web-app-from-file='+str(bundle),
        '--no-first-run','--no-default-browser-check','chrome://iwa-dev'],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
