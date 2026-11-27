package sshengine

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestCompositeSSH(t *testing.T) {
	a, b := make([]byte, 32), make([]byte, 32)
	rand.Read(a)
	rand.Read(b)
	s, e := NewCompositeSigner(a, b)
	if e != nil {
		t.Fatal(e)
	}
	p, e := ParsePublic(s.PublicKey().Marshal())
	if e != nil {
		t.Fatal(e)
	}
	m := []byte("SSH authentication transcript")
	sig, e := s.Sign(rand.Reader, m)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Verify(m, sig); e != nil {
		t.Fatal(e)
	}
	for _, offset := range []int{0, 2420} {
		bad := &ssh.Signature{Format: sig.Format, Blob: bytes.Clone(sig.Blob)}
		bad.Blob[offset] ^= 1
		if p.Verify(m, bad) == nil {
			t.Fatal("accepted corrupt component")
		}
	}
	if p.Verify([]byte("different"), sig) == nil {
		t.Fatal("accepted changed transcript")
	}
	external := &ExternalSigner{Key: p, Callback: func([]byte) ([]byte, error) { return make([]byte, 2484), nil }}
	if _, e = external.Sign(rand.Reader, m); e == nil {
		t.Fatal("accepted invalid external signature")
	}
}
