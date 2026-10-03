// fsxbind adapts the fsx backends (ext2/3/4, XFS, vfat — docs/linux §5.1)
// to the userspace volumeFS contract, the mirror of ntfsbind for the
// NTFS side: one thin conversion, so the verbs and their stub tests never
// learn which backend served them. volumeFS.Walk streams regular files
// (the stream/materialise contract); directories and symlinks reach the
// timeline verb through fsx directly.
package main

import (
	"io"
	"strconv"

	"github.com/Get-Sybers/gomount/fsx"
)

// fsxFS adapts an fsx.FS to volumeFS.
type fsxFS struct {
	fs fsx.FS
}

// fsxEntryToFile maps the fsx entry onto the CLI's fileEntry. The inode
// doubles as the MFTID column so provenance-carrying consumers (the
// manifest, stream JSONL) read one identity field whatever the backend.
func fsxEntryToFile(e fsx.Entry) fileEntry {
	return fileEntry{
		Name:       e.Name,
		Path:       e.Path,
		IsDir:      e.IsDir,
		Size:       e.Size,
		MFTID:      strconv.FormatUint(e.Inode, 10),
		Deleted:    !e.Allocated,
		Btime:      e.Btime,
		Mtime:      e.Mtime,
		Ctime:      e.Ctime,
		Atime:      e.Atime,
		UID:        e.UID,
		GID:        e.GID,
		Mode:       e.Mode,
		Inode:      e.Inode,
		Nlink:      e.Nlink,
		LinkTarget: e.LinkTarget,
	}
}

func (a fsxFS) ReadDir(dir string) ([]fileEntry, error) {
	entries, err := a.fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]fileEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, fsxEntryToFile(e))
	}
	return out, nil
}

func (a fsxFS) Stat(p string) (fileEntry, error) {
	e, err := a.fs.Stat(p)
	if err != nil {
		return fileEntry{}, err
	}
	return fsxEntryToFile(e), nil
}

func (a fsxFS) Open(p string) (io.ReadCloser, error) { return a.fs.Open(p) }

func (a fsxFS) Walk(fn func(e fileEntry, open func() (io.ReadCloser, error)) error) error {
	return a.fs.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		if open == nil {
			return nil // directories and symlinks: not stream/materialise material
		}
		return fn(fsxEntryToFile(e), open)
	})
}
