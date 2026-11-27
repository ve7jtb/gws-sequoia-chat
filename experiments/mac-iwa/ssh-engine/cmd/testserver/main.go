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
	for ch := range channels {
		channel, requests, e := ch.Accept()
		if e != nil {
			panic(e)
		}
		for r := range requests {
			r.Reply(r.Type == "pty-req" || r.Type == "shell", nil)
			if r.Type == "shell" {
				b := make([]byte, 4)
				io.ReadFull(channel, b)
				channel.Write(b)
				time.Sleep(time.Second)
				channel.Close()
				return
			}
		}
	}
}
