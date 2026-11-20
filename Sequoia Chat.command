#!/bin/zsh
# Run outside the Codex sandbox so gws can access its macOS Keychain item.
set -eu
umask 077
cd -- "${0:A:h}"
exec /usr/bin/env python3 -B webapp.py
