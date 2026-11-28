// Disposable loopback-only integration server. Never packaged in the IWA.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"

	"github.com/pkg/sftp"
	"net"
	"os"
	"time"
)

func main() {
	_, host, _ := ed25519.GenerateKey(rand.Reader)
	pub, user, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(host)
	us, _ := ssh.NewPublicKey(pub)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(us.Marshal()) {
			return nil, fmt.Errorf("wrong key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(hs)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		panic(e)
	}
	defer l.Close()
	time.AfterFunc(30*time.Second, func() { os.Exit(2) })
	json.NewEncoder(os.Stdout).Encode(map[string]any{"address": l.Addr().String(), "hostKey": base64.StdEncoding.EncodeToString(hs.PublicKey().Marshal()), "userKey": base64.StdEncoding.EncodeToString(us.Marshal()), "userSeed": base64.StdEncoding.EncodeToString(user.Seed())})
	c, e := l.Accept()
	if e != nil {
		panic(e)
	}
	defer c.Close()
	sc, channels, requests, e := ssh.NewServerConn(c, cfg)
	if e != nil {
		panic(e)
	}
	defer sc.Close()
	go ssh.DiscardRequests(requests)
	// All SFTP channels share a disposable in-memory filesystem. The test
	// server has no route to the Mac's files.
	files := sftp.InMemHandler()
	for ch := range channels {
		channel, requests, e := ch.Accept()
		if e != nil {
			panic(e)
		}
		go func() {
			defer channel.Close()
			for r := range requests {
				switch r.Type {
				case "pty-req":
					r.Reply(true, nil)
				case "shell":
					r.Reply(true, nil)
					_, _ = io.Copy(channel, channel)
					return
				case "subsystem":
					r.Reply(true, nil)
					server := sftp.NewRequestServer(channel, files)
					defer server.Close()
					_ = server.Serve()
					return
				default:
					r.Reply(false, nil)
				}
			}
		}()
	}
}
