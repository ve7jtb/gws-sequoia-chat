// Package sshengine owns the SSH protocol, never card provisioning or vault storage.
package sshengine

import (
	"context"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

// Terminal owns exactly one authenticated PTY. Closing the connection also
// interrupts authentication, reads and writes when the vault locks.
type Terminal struct {
	Client  *ssh.Client
	Session *ssh.Session
	Input   io.WriteCloser
	once    sync.Once
}

func (t *Terminal) Close() { t.once.Do(func() { t.Session.Close(); t.Client.Close() }) }
func (t *Terminal) Resize(rows, cols int) error {
	if rows < 1 || rows > 1000 || cols < 1 || cols > 1000 {
		return errors.New("invalid terminal dimensions")
	}
	return t.Session.WindowChange(rows, cols)
}

// Connect accepts only a scoped signer and a mandatory host verifier. The SSH
// library verifies the server's handshake signature before user authentication;
// the caller's trust callback must reject unknown, changed or revoked keys.
func Connect(ctx context.Context, conn net.Conn, address, user string, signer ssh.Signer, verify ssh.HostKeyCallback, output io.Writer, rows, cols int) (*Terminal, error) {
	if user == "" || len(user) > 256 || signer == nil || verify == nil || rows < 1 || cols < 1 || rows > 1000 || cols > 1000 {
		conn.Close()
		return nil, errors.New("invalid SSH configuration")
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	success := false
	defer func() {
		if !success {
			stop()
			conn.Close()
		}
	}()
	config := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: verify, ClientVersion: "SSH-2.0-SequoiaIWA"}
	c, ch, req, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(c, ch, req)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	t := &Terminal{Client: client, Session: session}
	session.Stdout = output
	session.Stderr = output
	t.Input, err = session.StdinPipe()
	if err != nil {
		t.Close()
		return nil, err
	}
	// Disable terminal echo on the local side: the remote PTY controls echo. No
	// agent/X11 forwarding, local port forwarding or environment forwarding exists.
	if err = session.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{}); err != nil {
		t.Close()
		return nil, err
	}
	if err = session.Shell(); err != nil {
		t.Close()
		return nil, err
	}
	success = true
	go func() { session.Wait(); stop(); t.Close() }()
	return t, nil
}
