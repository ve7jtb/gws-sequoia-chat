#!/usr/bin/env python3
"""Launch the experiment in its own browser profile; no token operation starts."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
DEFAULT_CANARY = '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary'

if __name__ == '__main__':
    bundle = ROOT / 'build/sequoia-lab.swbn'
    if not bundle.is_file():
        raise SystemExit('Build the signed IWA first')
    browser = os.environ.get('CHROMIUM_BIN', DEFAULT_CANARY)
    extra = sys.argv[1:]
    subprocess.Popen([
        browser,
        '--user-data-dir=' + str(ROOT / 'private/chrome-profile'),
        '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,SmartCard',
        '--install-isolated-web-app-from-file=' + str(bundle),
        '--no-first-run', '--no-default-browser-check', *extra, 'chrome://iwa-dev',
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
