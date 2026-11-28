package sshengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The POSIX shell command contains no interpolated client input. The reviewed
// public key arrives on stdin. Recognize the same blob even on lines with key
// options or comments so reauthorization does not bypass existing restrictions.
const authorizationReceipt = "sequoia-ssh-key-authorized\n"
const authorizeCommand = `set -eu
umask 077
: "${HOME:?}"
directory="$HOME/.ssh"
file="$directory/authorized_keys"
[ ! -L "$directory" ] && [ ! -L "$file" ] || exit 1
mkdir -p "$directory"
[ ! -e "$file" ] || [ -f "$file" ] || exit 1
pending=
while IFS=' ' read -r algorithm blob; do
    found=
    if [ -f "$file" ]; then
        found=$(awk -v algorithm="$algorithm" -v key="$blob" '!/^[[:space:]]*#/ { for (i=2; i<=NF; i++) if ($(i-1)==algorithm && $i==key) found=1 } END { if (found) print "yes" }' "$file")
    fi
    if [ "$found" != yes ]; then
        pending="$pending
$algorithm $blob"
    fi
done
[ -z "$pending" ] || printf '%s\n' "$pending" >> "$file"
printf '%s' '` + authorizationReceipt + `'
`

// Match the fixed receipt without retaining unbounded remote stdout. An
// unrelated forced command can otherwise exit zero without installing the key.
type authorizationOutput struct {
	matched int
	invalid bool
}

func (out *authorizationOutput) Write(p []byte) (int, error) {
	if !out.invalid {
		next := out.matched + len(p)
		if next > len(authorizationReceipt) || string(p) != authorizationReceipt[out.matched:next] {
			out.invalid = true
		} else {
			out.matched = next
		}
	}
	return len(p), nil
}

func authorizationKeys(keys []ssh.PublicKey, advertised string) []ssh.PublicKey {
	algorithms := strings.Split(advertised, ",")
	var selected []ssh.PublicKey
	for _, key := range keys {
		if slices.Contains(algorithms, key.Type()) {
			selected = append(selected, key)
		}
	}
	return selected
}

// AuthorizePublicKeys reviews matching keys before requesting the one-time
// password on the same verified SSH connection. It never invokes a signer.
func AuthorizePublicKeys(ctx context.Context, conn net.Conn, address, user string, keys []ssh.PublicKey, verify ssh.HostKeyCallback, password func([]string) (string, error)) ([]string, error) {
	defer conn.Close()
	if user == "" || len(user) > 256 || len(keys) < 1 || len(keys) > 2 || verify == nil || password == nil {
		return nil, errors.New("invalid SSH key authorization configuration")
	}
	for i, key := range keys {
		if key == nil || (key.Type() != CompositeAlgorithm && key.Type() != ssh.KeyAlgoED25519) || (i > 0 && key.Type() == keys[0].Type()) {
			return nil, errors.New("invalid SSH key authorization candidates")
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	attempted := false
	var selected []ssh.PublicKey
	var algorithms []string
	config := &ssh.ClientConfig{User: user, HostKeyCallback: verify, ClientVersion: "SSH-2.0-SequoiaIWA"}
	config.AuthCallback = func(auth *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
		if attempted {
			return nil, errors.New("SSH password authentication was rejected or requires another method")
		}
		if !slices.Contains(auth.AllowedMethods, "password") {
			return nil, errors.New("the server did not offer SSH password authentication")
		}
		if auth.ServerSignatureAlgorithms == "" {
			return nil, errors.New("the server did not advertise public-key authentication algorithms")
		}
		selected = authorizationKeys(keys, auth.ServerSignatureAlgorithms)
		if len(selected) == 0 {
			return nil, errors.New("the server does not advertise support for the selected keys; choose an imported Ed25519 key if supported")
		}
		for _, key := range selected {
			algorithms = append(algorithms, key.Type())
		}
		attempted = true
		return ssh.PasswordCallback(func() (string, error) { return password(algorithms) }), nil
	}
	c, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if !attempted {
		return nil, errors.New("the server did not request SSH password authentication")
	}
	client := ssh.NewClient(c, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var publicKeys bytes.Buffer
	for _, key := range selected {
		publicKeys.Write(ssh.MarshalAuthorizedKey(key))
	}
	session.Stdin = &publicKeys
	var receipt authorizationOutput
	session.Stdout = &receipt
	if err = session.Run(authorizeCommand); err != nil {
		return nil, fmt.Errorf("could not update ~/.ssh/authorized_keys: %w", err)
	}
	if receipt.invalid || receipt.matched != len(authorizationReceipt) {
		return nil, errors.New("the server did not confirm the authorized_keys update")
	}
	return algorithms, nil
}
