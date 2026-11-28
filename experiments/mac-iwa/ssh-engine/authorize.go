package sshengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

// The POSIX shell command contains no interpolated client input. The reviewed
// public key arrives on stdin. Recognize the same blob even on lines with key
// options or comments so reauthorization does not bypass existing restrictions.
const authorizationReceipt = "sequoia-ssh-key-authorized\n"
const authorizeCommand = `set -eu
umask 077
IFS=' ' read -r algorithm blob
: "${HOME:?}"
directory="$HOME/.ssh"
file="$directory/authorized_keys"
[ ! -L "$directory" ] && [ ! -L "$file" ] || exit 1
mkdir -p "$directory"
if [ -e "$file" ]; then
    [ -f "$file" ] || exit 1
    found=$(awk -v algorithm="$algorithm" -v key="$blob" '!/^[[:space:]]*#/ { for (i=2; i<=NF; i++) if ($(i-1)==algorithm && $i==key) found=1 } END { if (found) print "yes" }' "$file")
else
    found=
fi
if [ "$found" != yes ]; then
    printf '\n%s %s\n' "$algorithm" "$blob" >> "$file"
fi
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

// AuthorizePublicKey uses a single verified, password-authenticated exec
// session. It never requests a PTY or invokes the selected private key.
func AuthorizePublicKey(ctx context.Context, conn net.Conn, address, user string, key ssh.PublicKey, verify ssh.HostKeyCallback, password func() (string, error)) error {
	defer conn.Close()
	if user == "" || len(user) > 256 || key == nil || key.Type() != CompositeAlgorithm || verify == nil || password == nil {
		return errors.New("invalid SSH key authorization configuration")
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	attempted := false
	auth := ssh.PasswordCallback(func() (string, error) {
		if attempted {
			return "", errors.New("SSH password was already attempted")
		}
		attempted = true
		return password()
	})
	config := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: verify, ClientVersion: "SSH-2.0-SequoiaIWA"}
	c, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return err
	}
	defer c.Close()
	if !attempted {
		return errors.New("the server did not request SSH password authentication")
	}
	client := ssh.NewClient(c, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(ssh.MarshalAuthorizedKey(key))
	var receipt authorizationOutput
	session.Stdout = &receipt
	if err = session.Run(authorizeCommand); err != nil {
		return fmt.Errorf("could not update ~/.ssh/authorized_keys: %w", err)
	}
	if receipt.invalid || receipt.matched != len(authorizationReceipt) {
		return errors.New("the server did not confirm the authorized_keys update")
	}
	return nil
}
