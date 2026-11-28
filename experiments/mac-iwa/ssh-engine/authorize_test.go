package sshengine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestAuthorizePublicKey(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		trust, validPassword bool
	}{
		{"trusted account", true, true},
		{"wrong password", true, false},
		{"untrusted host", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			host := key(t)
			signer, err := NewCompositeSigner(make([]byte, 32), bytes.Repeat([]byte{1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			pub := signer.PublicKey()
			verified := false
			prompts := 0
			const password = "disposable fixture password"
			config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, received []byte) (*ssh.Permissions, error) {
				if !bytes.Equal(received, []byte(password)) {
					return nil, errors.New("invalid password")
				}
				return nil, nil
			}}
			config.AddHostKey(host)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go serveAuthorization(listener, config, home)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			err = AuthorizePublicKey(ctx, conn, listener.Addr().String(), "test", pub, func(_ string, _ net.Addr, k ssh.PublicKey) error {
				if !tc.trust || !bytes.Equal(k.Marshal(), host.PublicKey().Marshal()) {
					return errors.New("host not trusted")
				}
				verified = true
				return nil
			}, func() (string, error) {
				if !verified {
					t.Error("password requested before host verification")
				}
				prompts++
				if !tc.validPassword {
					return "deliberately incorrect", nil
				}
				return password, nil
			})
			path := filepath.Join(home, ".ssh", "authorized_keys")
			if tc.trust && tc.validPassword {
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub))) {
					t.Fatalf("incorrect authorized_keys: %v", err)
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("authorized_keys must be private: %v", err)
				}
			} else if _, statErr := os.Stat(path); err == nil || !os.IsNotExist(statErr) {
				t.Fatal("a failed verification or password attempt reached the authorized_keys file")
			}
			if tc.trust && prompts != 1 || !tc.trust && prompts != 0 {
				t.Fatalf("unexpected password prompt count: %d", prompts)
			}
		})
	}
}

func serveAuthorization(listener net.Listener, config *ssh.ServerConfig, home string) {
	transport, err := listener.Accept()
	if err != nil {
		return
	}
	defer transport.Close()
	conn, channels, requests, err := ssh.NewServerConn(transport, config)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		ch, requests, err := channel.Accept()
		if err != nil {
			return
		}
		defer ch.Close()
		for request := range requests {
			var command struct{ Command string }
			if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || command.Command != authorizeCommand {
				request.Reply(false, nil)
				continue
			}
			request.Reply(true, nil)
			cmd := exec.Command("/bin/sh", "-c", command.Command)
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			cmd.Stdin, cmd.Stdout = ch, ch
			var status uint32
			if cmd.Run() != nil {
				status = 1
			}
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			return
		}
	}
}

func TestAuthorizationPreservesExistingKeyOptions(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	key := []byte("ssh-mldsa44-ed25519 c3ludGhldGlj\n")
	original := append([]byte("restrict,command=\"echo test\" "), key...)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", authorizeCommand)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(key)
	receipt, err := cmd.Output()
	if err != nil || string(receipt) != authorizationReceipt {
		t.Fatalf("failed to recognize existing key: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("changed existing restrictions: %v", err)
	}
}
