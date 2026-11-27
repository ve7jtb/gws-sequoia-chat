package sshengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countSigner establishes that failed host trust cannot reach a private-key operation.
type countSigner struct {
	ssh.Signer
	n atomic.Int32
}

func (s *countSigner) Sign(r io.Reader, b []byte) (*ssh.Signature, error) {
	s.n.Add(1)
	return s.Signer.Sign(r, b)
}
func key(t *testing.T) ssh.Signer {
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := ssh.NewSignerFromKey(k)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestTerminalAndHostTrust(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted", false: "changed"}[trusted], func(t *testing.T) {
			host, user := key(t), &countSigner{Signer: key(t)}
			cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				if !bytes.Equal(k.Marshal(), user.PublicKey().Marshal()) {
					return nil, errors.New("wrong user")
				}
				return nil, nil
			}}
			cfg.AddHostKey(host)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			go func() {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				sc, channels, requests, e := ssh.NewServerConn(c, cfg)
				if e != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					channel, requests, e := ch.Accept()
					if e != nil {
						return
					}
					go func() {
						defer channel.Close()
						for r := range requests {
							r.Reply(r.Type == "pty-req" || r.Type == "shell" || r.Type == "window-change", nil)
							if r.Type == "shell" {
								b := make([]byte, 4)
								if _, e := io.ReadFull(channel, b); e == nil {
									channel.Write(b)
								}
								return
							}
						}
					}()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, e := net.Dial("tcp", listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			terminal, e := Connect(ctx, conn, listener.Addr().String(), "test", user, func(_ string, _ net.Addr, k ssh.PublicKey) error {
				if !trusted || !bytes.Equal(host.PublicKey().Marshal(), k.Marshal()) {
					return errors.New("host trust rejected")
				}
				return nil
			}, w, 24, 80)
			if !trusted {
				if e == nil || user.n.Load() != 0 {
					t.Fatal("untrusted host reached signer")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer terminal.Close()
			if _, e = terminal.Input.Write([]byte("test")); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, 4)
			if _, e = io.ReadFull(r, got); e != nil || string(got) != "test" {
				t.Fatalf("terminal round trip: %q %v", got, e)
			}
			if user.n.Load() != 1 {
				t.Fatal("unexpected signing count")
			}
		})
	}
}
