#!/usr/bin/env python3
"""Update an existing experimental hardware helper; Google transport is IWA-owned.

The historical filename is retained for local upgrade scripts. This command
does not install gws, sq, Java, an OAuth client, or the standalone mail runtime.
It does not access a YubiKey, perform private operations or change vault state.
"""
import argparse,json,os
from pathlib import Path
from install_native import install_code


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed',required=True,type=Path)
    parser.add_argument('--crypto-bin',required=True,type=Path)
    parser.add_argument('--email',help='Optional explicit update to the fixed enrollment mailbox')
    args=parser.parse_args();os.umask(0o077)
    destination=args.installed.resolve(strict=True)
    binary=args.crypto_bin.resolve(strict=True)
    if not binary.is_file() or not os.access(binary,os.X_OK):
        raise ValueError('Built executable required')
    config_path=destination/'private/config.json'
    config=json.loads(config_path.read_text())
    # Preserve existing enrollment, vault credentials and unused historical
    # configuration fields by default. Public Account settings live in the IWA.
    if args.email is not None:
        from install_native import validate
        candidate={key:config[key] for key in ('serial','ykman','app','cert')}
        candidate['chat_email']=args.email;validate(candidate)
    if not (destination/'build/pin-prompt').is_file():
        raise ValueError('Install the native PIN prompt before upgrading')
    install_code(destination,binary)
    if args.email is not None:
        config['chat_email']=args.email
        temporary=config_path.with_suffix('.update')
        # Exclusive creation avoids following a pre-existing temporary symlink.
        with temporary.open('x') as stream:json.dump(config,stream,indent=2)
        temporary.replace(config_path)
    print('Hardware helper updated. No YubiKey operation performed; OAuth remains in the browser.')


if __name__=='__main__':main()
