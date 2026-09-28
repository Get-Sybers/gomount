// ntfsbind is the single adapter that binds the userspace verbs (which speak the
// volumeFS / fileEntry contract) to the concrete ntfsfs backend. Keeping the
// ntfsfs coupling in one file means the operator/tool logic and its stub tests
// do not move when the ntfsfs.Entry struct or method set changes — only the thin
// conversion here does. The shared open pipeline lives in volumes.go
// (resolveVolumes/openVolumeFS): it peels image -> partitions -> LVM ->
// filesystem and hands NTFS volumes to this adapter, all O_RDONLY.
package main

import (
	"errors"
	"io"
	"strconv"

	"github.com/get-sybers/gomount/ntfsfs"
)

// ntfsFS adapts *ntfsfs.FS to the userspace volumeFS contract.
type ntfsFS struct {
	fs *ntfsfs.FS
}

// entryToFile maps a concrete ntfsfs.Entry onto the CLI's fileEntry. This is the
// only place the two representations meet; the MFT id is rendered to a string so
// the CLI stays agnostic to whether the backend keys entries by record number or
// by a composite inode.
func entryToFile(e ntfsfs.Entry) fileEntry {
	return fileEntry{
		Name:    e.Name,
		Path:    e.Path,
		IsDir:   e.IsDir,
		Size:    e.Size,
		MFTID:   strconv.FormatInt(e.MFTID, 10),
		Deleted: e.Deleted,
		Streams: e.Streams,
		Btime:   e.Btime,
		Mtime:   e.Mtime,
		Ctime:   e.Ctime,
		Atime:   e.Atime,
	}
}

func (a ntfsFS) ReadDir(dir string) ([]fileEntry, error) {
	entries, err := a.fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]fileEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToFile(e))
	}
	return out, nil
}

func (a ntfsFS) Stat(p string) (fileEntry, error) {
	e, err := a.fs.Stat(p)
	if err != nil {
		return fileEntry{}, err
	}
	return entryToFile(e), nil
}

func (a ntfsFS) Open(p string) (io.ReadCloser, error) { return a.fs.Open(p) }

// Walk bridges ntfsfs.FS.Walk (which delivers ntfsfs.Entry and returns a
// *ntfsfs.WalkErrors for skipped records) to the volumeFS callback and the
// CLI-local walkPartial the stream verb understands.
func (a ntfsFS) Walk(fn func(e fileEntry, open func() (io.ReadCloser, error)) error) error {
	err := a.fs.Walk(func(e ntfsfs.Entry, open func() (io.ReadCloser, error)) error {
		return fn(entryToFile(e), open)
	})
	var we *ntfsfs.WalkErrors
	if errors.As(err, &we) {
		return &walkPartial{count: we.Count, msg: we.Error()}
	}
	return err
}
