package sshengine

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestImportOpenSSHEd25519(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	password := []byte("synthetic file passphrase")
	for _, protected := range []bool{false, true} {
		var file *pem.Block
		var err error
		if protected {
			file, err = ssh.MarshalPrivateKeyWithPassphrase(key, "synthetic", password)
		} else {
			file, err = ssh.MarshalPrivateKey(key, "synthetic")
		}
		if err != nil {
			t.Fatal(err)
		}
		encoded := pem.EncodeToMemory(file)
		if protected {
			if _, _, err := ImportEd25519(encoded, []byte("wrong")); err == nil {
				t.Fatal("accepted the wrong passphrase")
			}
		}
		got, public, err := ImportEd25519(encoded, password)
		if err != nil || !bytes.Equal(got, seed) || !bytes.Equal(public, key.Public().(ed25519.PublicKey)) {
			t.Fatalf("Ed25519 import failed: %v", err)
		}
		clear(got)
	}
}
