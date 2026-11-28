//go:build js && wasm

// The worker boundary adapts asynchronous Direct Sockets to Go's net.Conn.
// Each worker owns one connection and is destroyed on vault lock/disconnect.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	engine "github.com/ve7jtb/gws-sequoia-chat/sshengine"
	"io"
	"net"
	"syscall/js"
	"time"
)

type result struct {
	v   js.Value
	err error
}

func await(p js.Value) (js.Value, error) {
	ch := make(chan result, 1)
	ok := js.FuncOf(func(_ js.Value, a []js.Value) any { ch <- result{v: a[0]}; return nil })
	fail := js.FuncOf(func(_ js.Value, a []js.Value) any {
		ch <- result{err: errors.New("SSH bridge operation failed")}
		return nil
	})
	p.Call("then", ok, fail)
	r := <-ch
	ok.Release()
	fail.Release()
	return r.v, r.err
}
func octets(v js.Value) []byte {
	b := make([]byte, v.Get("byteLength").Int())
	js.CopyBytesToGo(b, v)
	return b
}
func array(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(v, b)
	return v
}

type address string

func (a address) Network() string { return "tcp" }
func (a address) String() string  { return string(a) }

type connection struct{ pending []byte }

func (c *connection) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		v, e := await(js.Global().Call("sshRead"))
		if e != nil {
			return 0, e
		}
		if v.IsNull() {
			return 0, io.EOF
		}
		c.pending = octets(v)
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *connection) Write(p []byte) (int, error) {
	_, e := await(js.Global().Call("sshWrite", array(p)))
	if e != nil {
		return 0, e
	}
	return len(p), nil
}
func (c *connection) Close() error         { js.Global().Call("sshClose"); return nil }
func (c *connection) LocalAddr() net.Addr  { return address("iwa") }
func (c *connection) RemoteAddr() net.Addr { return address("remote") }

// Deadlines are owned by the worker's handshake timer. Worker termination also
// interrupts every pending promise, including a blocked PIN operation callback.
func (c *connection) SetDeadline(time.Time) error      { return nil }
func (c *connection) SetReadDeadline(time.Time) error  { return nil }
func (c *connection) SetWriteDeadline(time.Time) error { return nil }

type output struct{}

func (output) Write(p []byte) (int, error) {
	js.Global().Call("sshOutput", array(p))
	return len(p), nil
}
func main() {
	// Software signing stays in this disposable worker; callers receive only
	// the signature, never expanded ML-DSA or Ed25519 private keys.
	js.Global().Set("sshSignSeeds", js.FuncOf(func(_ js.Value, a []js.Value) any {
		ml, ed := octets(a[0]), octets(a[1])
		defer clear(ml)
		defer clear(ed)
		signer, e := engine.NewCompositeSigner(ml, ed)
		if e != nil {
			return js.Null()
		}
		if string(signer.PublicKey().Marshal()) != string(octets(a[2])) {
			return js.Null()
		}
		sig, e := signer.Sign(rand.Reader, octets(a[3]))
		if e != nil {
			return js.Null()
		}
		return array(sig.Blob)
	}))
	var terminal *engine.Terminal
	js.Global().Set("sshStart", js.FuncOf(func(_ js.Value, a []js.Value) any {
		go func() {
			options := a[0]
			pub, e := engine.ParsePublic(octets(options.Get("publicKey")))
			if e != nil {
				js.Global().Call("sshFailure", e.Error())
				return
			}
			signer := &engine.ExternalSigner{Key: pub, Callback: func(m []byte) ([]byte, error) {
				v, e := await(js.Global().Call("sshSign", array(m)))
				if e != nil {
					return nil, e
				}
				return octets(v), nil
			}}
			address, user := options.Get("address").String(), options.Get("username").String()
			if options.Get("authorizeKey").Truthy() {
				if e := engine.AuthorizePublicKey(context.Background(), &connection{}, address, user, pub, hostCheck, requestPassword); e != nil {
					js.Global().Call("sshFailure", e.Error())
					return
				}
				js.Global().Call("sshAuthorized")
				return
			}
			terminal, e = engine.Connect(context.Background(), &connection{}, address, user, signer, hostCheck, output{}, 24, 80)
			if e != nil {
				js.Global().Call("sshFailure", e.Error())
				return
			}
			js.Global().Call("sshReady")
		}()
		return nil
	}))
	// Preserve keystroke order: a goroutine per write can reorder concurrent
	// terminal input. Bound the queue rather than retaining unlimited plaintext.
	inputQueue := make(chan []byte, 128)
	go func() {
		for b := range inputQueue {
			if terminal != nil {
				if _, e := terminal.Input.Write(b); e != nil {
					js.Global().Call("sshFailure", "SSH terminal write failed")
					return
				}
			}
		}
	}()
	js.Global().Set("sshInput", js.FuncOf(func(_ js.Value, a []js.Value) any {
		b := octets(a[0])
		if len(b) > 65536 {
			js.Global().Call("sshFailure", "SSH input too large")
			return nil
		}
		select {
		case inputQueue <- b:
		default:
			js.Global().Call("sshFailure", "SSH input queue full")
		}
		return nil
	}))
	js.Global().Set("sshResize", js.FuncOf(func(_ js.Value, a []js.Value) any {
		r, c := a[0].Int(), a[1].Int()
		go func() {
			if terminal != nil {
				terminal.Resize(r, c)
			}
		}()
		return nil
	}))
	select {}
}

// The SSH library needs a password string for its encrypted auth packet.
// Clear both byte buffers after conversion and keep the string in this worker.
func requestPassword() (string, error) {
	v, err := await(js.Global().Call("sshPassword"))
	if err != nil {
		return "", err
	}
	defer v.Call("fill", 0)
	if n := v.Get("byteLength").Int(); n < 1 || n > 1024 {
		return "", errors.New("invalid SSH password length")
	}
	secret := octets(v)
	defer clear(secret)
	return string(secret), nil
}
