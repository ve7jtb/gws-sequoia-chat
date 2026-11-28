package sshengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSFTPOnTerminalConnection(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "folder"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("folder", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	host, user := key(t), &countSigner{Signer: key(t)}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, supplied ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(supplied.Marshal(), user.PublicKey().Marshal()) {
			return nil, errors.New("Unexpected user key")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		connection, channels, requests, err := ssh.NewServerConn(peer, config)
		if err != nil {
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for request := range requests {
					switch request.Type {
					case "pty-req":
						request.Reply(true, nil)
					case "shell":
						request.Reply(true, nil)
						_, _ = io.Copy(channel, channel)
						return
					case "subsystem":
						request.Reply(true, nil)
						server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(root))
						if err == nil {
							defer server.Close()
							_ = server.Serve()
						}
						return
					default:
						request.Reply(false, nil)
					}
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	terminal, err := Connect(ctx, peer, listener.Addr().String(), "fixture", user, ssh.FixedHostKey(host.PublicKey()), write, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()

	payload := []byte{0, 1, 128, 255, 10}
	err = WithSFTP(ctx, terminal.Client, func(client *sftp.Client) error {
		dir, entries, err := BrowseRemote(ctx, client, ".")
		if err != nil {
			return err
		}
		if dir != root || len(entries) != 1 || !entries[0].Directory || entries[0].Name != "folder" {
			return errors.New("Unexpected picker listing")
		}
		if err := UploadRemote(client, dir, "transfer.bin", payload); err != nil {
			return err
		}
		if err := UploadRemote(client, dir, "transfer.bin", []byte("overwrite")); err == nil {
			return errors.New("Overwrote existing file")
		}
		if _, err := DownloadRemote(client, dir, "link"); err == nil {
			return errors.New("Followed symlink")
		}
		if _, err := DownloadRemote(client, dir, "../transfer.bin"); err == nil {
			return errors.New("Accepted nested name")
		}
		got, err := DownloadRemote(client, dir, "transfer.bin")
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return errors.New("File byte mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "transfer.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("File permissions: %v", info.Mode().Perm())
	}
	if _, err = terminal.Input.Write([]byte("open")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err = io.ReadFull(read, data); err != nil || string(data) != "open" {
		t.Fatalf("Terminal round trip: %q %v", data, err)
	}
	if count := user.n.Load(); count != 1 {
		t.Fatalf("Expected one SSH authentication, got %d", count)
	}
}
