//go:build js && wasm

package main

import (
	"golang.org/x/crypto/ssh"
	"net"
	"syscall/js"
)

func hostCheck(_ string, _ net.Addr, key ssh.PublicKey) error {
	_, e := await(js.Global().Call("sshVerifyHost", key.Type(), array(key.Marshal())))
	return e
}
