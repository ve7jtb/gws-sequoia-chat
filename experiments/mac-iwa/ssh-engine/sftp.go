package sshengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const MaxTransfer = 16 * 1024 * 1024
const maxPickerEntries = 512

type RemoteEntry struct {
	Name      string
	Directory bool
	Size      int64
}

func validRemotePath(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validRemoteName(value string) bool {
	return validRemotePath(value) && value != "." && value != ".." &&
		len(value) <= 255 && !strings.ContainsAny(value, "/\\")
}

// Each operation gets a distinct SFTP channel on the authenticated SSH
// transport. Cancellation closes that channel and leaves the terminal alive.
func WithSFTP(ctx context.Context, sshClient *ssh.Client, use func(*sftp.Client) error) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}
	go io.Copy(io.Discard, stderr)
	if err := session.RequestSubsystem("sftp"); err != nil {
		return errors.New("The SSH server refused the SFTP subsystem")
	}
	// Bound bytes consumed from the remote server even for a directory with a
	// huge number of entries. Each operation has its own quota and deadline.
	client, err := sftp.NewClientPipe(io.LimitReader(stdout, 2*MaxTransfer), stdin)
	if err != nil {
		return err
	}
	defer client.Close()
	return use(client)
}

func BrowseRemote(ctx context.Context, client *sftp.Client, directory string) (string, []RemoteEntry, error) {
	if !validRemotePath(directory) {
		return "", nil, errors.New("Invalid remote directory")
	}
	resolved, err := client.RealPath(directory)
	if err != nil {
		return "", nil, err
	}
	if !validRemotePath(resolved) || !path.IsAbs(resolved) {
		return "", nil, errors.New("Invalid directory returned by SSH server")
	}
	files, err := client.ReadDirContext(ctx, resolved)
	if err != nil {
		return "", nil, err
	}
	if len(files) > maxPickerEntries {
		return "", nil, errors.New("Directory has more than 512 entries. Enter a smaller directory path")
	}
	entries := make([]RemoteEntry, 0, len(files))
	for _, info := range files {
		regular := info.Mode().IsRegular()
		if !validRemoteName(info.Name()) || (!regular && !info.IsDir()) {
			continue
		}
		entries = append(entries, RemoteEntry{info.Name(), info.IsDir(), info.Size()})
	}
	slices.SortFunc(entries, func(a, b RemoteEntry) int {
		if a.Directory != b.Directory {
			if a.Directory {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return resolved, entries, nil
}

func remoteFile(directory, name string) (string, error) {
	if !validRemotePath(directory) || !path.IsAbs(directory) || !validRemoteName(name) {
		return "", errors.New("Invalid remote file location")
	}
	return path.Join(directory, name), nil
}

func DownloadRemote(client *sftp.Client, directory, name string) ([]byte, error) {
	filename, err := remoteFile(directory, name)
	if err != nil {
		return nil, err
	}
	info, err := client.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Select a regular file")
	}
	if info.Size() < 0 || info.Size() > MaxTransfer {
		return nil, errors.New("Remote file exceeds 16 MiB")
	}
	file, err := client.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxTransfer+1))
	if err != nil || len(data) > MaxTransfer {
		clear(data)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("Remote file exceeds 16 MiB")
	}
	return data, nil
}

func UploadRemote(client *sftp.Client, directory, name string, data []byte) error {
	filename, err := remoteFile(directory, name)
	if err != nil {
		return err
	}
	if len(data) > MaxTransfer {
		return errors.New("Local file exceeds 16 MiB")
	}
	// Exclusive creation protects existing files even if another process
	// creates one after the user picks the directory.
	file, err := client.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		if _, existing := client.Lstat(filename); existing == nil {
			return errors.New("A file with that name already exists on the server")
		}
		return err
	}
	// Create with the server's umask, then restrict access before sending bytes.
	if err = file.Chmod(0600); err == nil {
		_, err = io.Copy(file, bytes.NewReader(data))
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("Upload failed. A partial remote file may remain")
	}
	return err
}
