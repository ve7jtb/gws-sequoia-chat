package sshengine

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
)

const CompositeAlgorithm = "ssh-mldsa44-ed25519"
const compositeLabel = "COMPSIG-MLDSA44-Ed25519-SHA512"

// representative implements draft-ietf-sshm-composite-sigs-01, section 4.2.
// The SSH context is empty; ML-DSA itself uses the algorithm label as context.
func representative(message []byte) []byte {
	h := sha512.Sum512(message)
	b := []byte("CompositeAlgorithmSignatures2025" + compositeLabel)
	b = append(b, 0)
	return append(b, h[:]...)
}

type compositePublic struct {
	ml *mldsa.PublicKey
	ed ed25519.PublicKey
}

func (p *compositePublic) Type() string { return CompositeAlgorithm }
func (p *compositePublic) Marshal() []byte {
	return ssh.Marshal(struct {
		Algorithm string
		Key       []byte
	}{CompositeAlgorithm, append(p.ml.Bytes(), p.ed...)})
}
func (p *compositePublic) Verify(message []byte, s *ssh.Signature) error {
	if s.Format != CompositeAlgorithm || len(s.Blob) != 2484 {
		return errors.New("invalid composite SSH signature")
	}
	m := representative(message)
	if err := mldsa.Verify(p.ml, m, s.Blob[:2420], &mldsa.Options{Context: compositeLabel}); err != nil {
		return err
	}
	if !ed25519.Verify(p.ed, m, s.Blob[2420:]) {
		return errors.New("invalid Ed25519 component")
	}
	return nil
}

// ParsePublic also accepts the draft composite key absent from x/crypto's parser.
// The component keys remain dedicated to this composite, never classical fallback.
func ParsePublic(blob []byte) (ssh.PublicKey, error) {
	var wire struct {
		Algorithm string
		Key       []byte
	}
	if ssh.Unmarshal(blob, &wire) == nil && wire.Algorithm == CompositeAlgorithm {
		if len(wire.Key) != 1344 {
			return nil, errors.New("invalid composite public key length")
		}
		ml, e := mldsa.NewPublicKey(mldsa.MLDSA44(), wire.Key[:1312])
		if e != nil {
			return nil, e
		}
		return &compositePublic{ml, append(ed25519.PublicKey(nil), wire.Key[1312:]...)}, nil
	}
	return ssh.ParsePublicKey(blob)
}

type compositeSigner struct {
	ml  *mldsa.PrivateKey
	ed  ed25519.PrivateKey
	pub *compositePublic
}

func NewCompositeSigner(mlSeed, edSeed []byte) (ssh.Signer, error) {
	if len(mlSeed) != 32 || len(edSeed) != 32 {
		return nil, errors.New("invalid SSH seed length")
	}
	ml, e := mldsa.NewPrivateKey(mldsa.MLDSA44(), mlSeed)
	if e != nil {
		return nil, e
	}
	ed := ed25519.NewKeyFromSeed(edSeed)
	return &compositeSigner{ml, ed, &compositePublic{ml.PublicKey(), ed.Public().(ed25519.PublicKey)}}, nil
}
func (s *compositeSigner) PublicKey() ssh.PublicKey { return s.pub }
func (s *compositeSigner) Sign(r io.Reader, message []byte) (*ssh.Signature, error) {
	m := representative(message)
	sig, e := s.ml.Sign(r, m, &mldsa.Options{Context: compositeLabel})
	if e != nil {
		return nil, e
	}
	sig = append(sig, ed25519.Sign(s.ed, m)...)
	return &ssh.Signature{Format: CompositeAlgorithm, Blob: sig}, nil
}

// ExternalSigner verifies every returned signature against the pinned public key
// before the SSH library sends it. A bad card response cannot authenticate.
type ExternalSigner struct {
	Key      ssh.PublicKey
	Callback func([]byte) ([]byte, error)
}

func (s *ExternalSigner) PublicKey() ssh.PublicKey { return s.Key }
func (s *ExternalSigner) Sign(_ io.Reader, m []byte) (*ssh.Signature, error) {
	b, e := s.Callback(m)
	if e != nil {
		return nil, e
	}
	sig := &ssh.Signature{Format: s.Key.Type(), Blob: b}
	if e = s.Key.Verify(m, sig); e != nil {
		return nil, e
	}
	return sig, nil
}
