"""Expose RFC 8308 server-sig-algs in a disposable copy of pinned x/crypto."""
from pathlib import Path
import sys


source = Path(sys.argv[1]) / "ssh"
replacements = {
    "client.go": (
        "\tAllowedMethods []string\n",
        "\tAllowedMethods []string\n"
        "\n\t// ServerSignatureAlgorithms is the raw server-sig-algs name-list.\n"
        "\tServerSignatureAlgorithms string\n",
    ),
    "client_auth.go": (
        "\t\t\t\tAllowedMethods:        slices.Clone(methods),\n",
        "\t\t\t\tAllowedMethods:        slices.Clone(methods),\n"
        '\t\t\t\tServerSignatureAlgorithms: string(extensions["server-sig-algs"]),\n',
    ),
}
for name, (old, new) in replacements.items():
    original = source / name
    text = original.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"Review the pinned x/crypto SSH overlay for {name}")
    original.chmod(0o600)
    original.write_text(text.replace(old, new))
