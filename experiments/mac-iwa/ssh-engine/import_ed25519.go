package sshengine

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

// ImportEd25519 deliberately accepts only standalone software keys in the
// OpenSSH private-key container. Keep the original file and passphrase out of
// the vault and reconstruct the public key from the imported seed.
func ImportEd25519(file, passphrase []byte) (seed, public []byte, err error) {
	if len(file) < 1 || len(file) > 32768 || len(passphrase) > 1024 {
		return nil, nil, errors.New("invalid OpenSSH file or passphrase size")
	}
	block, rest := pem.Decode(file)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("choose a single OpenSSH private-key file")
	}
	defer clear(block.Bytes)
	var raw any
	raw, err = ssh.ParseRawPrivateKey(file)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if len(passphrase) == 0 {
			return nil, nil, errors.New("enter the OpenSSH key passphrase")
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(file, passphrase)
	}
	if err != nil {
		return nil, nil, errors.New("could not open the OpenSSH key file with the supplied passphrase")
	}
	key, ok := raw.(*ed25519.PrivateKey)
	if !ok || len(*key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("choose a standalone Ed25519 software private key")
	}
	defer clear(*key)
	seed = (*key).Seed()
	derived := ed25519.NewKeyFromSeed(seed)
	defer clear(derived)
	if !bytes.Equal(derived, *key) {
		clear(seed)
		return nil, nil, errors.New("Ed25519 public and private key material do not match")
	}
	return seed, bytes.Clone(derived.Public().(ed25519.PublicKey)), nil
}
