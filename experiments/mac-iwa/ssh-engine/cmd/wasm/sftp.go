//go:build js && wasm

package main

import (
	"context"
	"syscall/js"
	"time"

	"github.com/pkg/sftp"
	engine "github.com/ve7jtb/gws-sequoia-chat/sshengine"
)

// Each worker services one file operation at a time. SSH terminal input and
// output continue through their own channel while the SFTP goroutine waits.
func installSFTP(current func() *engine.Terminal) {
	var running context.CancelFunc
	var active int
	js.Global().Set("sshSFTP", js.FuncOf(func(_ js.Value, args []js.Value) any {
		request := args[0]
		id := request.Get("id").Int()
		terminal := current()
		if terminal == nil || running != nil {
			js.Global().Call("sshTransferResult", id, "SFTP channel unavailable", js.Null())
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		running, active = cancel, id
		go func() {
			defer cancel()
			var reply any
			var downloaded []byte
			defer func() { clear(downloaded) }()
			err := engine.WithSFTP(ctx, terminal.Client, func(client *sftp.Client) error {
				directory := request.Get("directory").String()
				switch request.Get("op").String() {
				case "browse":
					resolved, entries, err := engine.BrowseRemote(ctx, client, directory)
					if err != nil {
						return err
					}
					rows := make([]any, 0, len(entries))
					for _, entry := range entries {
						rows = append(rows, map[string]any{"name": entry.Name, "directory": entry.Directory, "size": float64(entry.Size)})
					}
					reply = map[string]any{"directory": resolved, "entries": rows}
				case "get":
					var err error
					downloaded, err = engine.DownloadRemote(client, directory, request.Get("name").String())
					if err != nil {
						return err
					}
					reply = array(downloaded)
				case "put":
					data := octets(request.Get("bytes"))
					defer clear(data)
					return engine.UploadRemote(client, directory, request.Get("name").String(), data)
				}
				return nil
			})
			running = nil
			message := ""
			if ctx.Err() != nil {
				message = "SFTP operation cancelled or timed out"
			} else if err != nil {
				message = err.Error()
			}
			js.Global().Call("sshTransferResult", id, message, reply)
		}()
		return nil
	}))
	js.Global().Set("sshCancelSFTP", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if running != nil && active == args[0].Int() {
			running()
		}
		return nil
	}))
}
