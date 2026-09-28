package hfsplus

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/get-sybers/gomount/fsx"
	"github.com/get-sybers/gomount/fsx/decmpfs"
)

// The fsx view: paths resolve component by component through the catalog;
// a file's content is its data fork, its decmpfs attribute (with the
// resource fork for the chunked types), or — for a hard link — the
// indirect node file's; a symlink's target is its data fork.

// lookup resolves a volume path to its record.
func (f *FS) lookup(p string) (*catRec, string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	cur, err := f.record(rootFolderID)
	if err != nil {
		return nil, "", err
	}
	if clean == "/" {
		return cur, "/", nil
	}
	for _, comp := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		dir := f.dirID(cur)
		if dir == 0 {
			return nil, "", fmt.Errorf("%s: not a directory", clean)
		}
		var next *catRec
		err := f.scanDir(dir, func(r *catRec) bool {
			if f.nameMatch(r.name, comp) {
				next = r
				return false
			}
			return true
		})
		if err != nil {
			return nil, "", err
		}
		if next == nil {
			return nil, "", fmt.Errorf("%s: no such file or directory", clean)
		}
		cur = next
	}
	return cur, clean, nil
}

// dirID is the directory a record lists: its own id for a folder, the
// target's for a directory hard link, 0 for anything else.
func (f *FS) dirID(r *catRec) uint32 {
	if r.isDir() {
		return r.id
	}
	if t := r.dirLinkTarget(); t != 0 && f.privDirDir != 0 {
		return f.childID(f.privDirDir, fmt.Sprintf("dir_%d", t))
	}
	return 0
}

// target follows a file hard link to its indirect node record; any other
// record is its own target.
func (f *FS) target(r *catRec) (*catRec, error) {
	t := r.hardLinkTarget()
	if t == 0 {
		return r, nil
	}
	if f.privFileDir == 0 {
		return nil, fmt.Errorf("hfsplus: hard link %q to iNode%d without a private metadata directory", r.name, t)
	}
	var found *catRec
	want := fmt.Sprintf("iNode%d", t)
	err := f.scanDir(f.privFileDir, func(c *catRec) bool {
		if c.name == want {
			found = c
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("hfsplus: hard link %q: %s is missing", r.name, want)
	}
	return found, nil
}

// entry shapes a record into the fsx view.
func (f *FS) entry(r *catRec, name, fullPath string) fsx.Entry {
	e := fsx.Entry{
		Name: name, Path: fullPath,
		IsDir: r.isDir(),
		Mode:  uint32(r.mode),
		UID:   r.uid, GID: r.gid,
		Inode: uint64(r.id), Nlink: 1,
		Allocated: true,
		Btime:     r.created, Mtime: r.modified, Atime: r.accessed, Ctime: r.changed,
	}
	if r.isDir() {
		return e
	}
	if r.dirLinkTarget() != 0 {
		e.IsDir = true
		e.Mode = e.Mode&^sIFMT | sIFDIR
		return e
	}
	t, err := f.target(r)
	if err != nil {
		t = r
	} else if t != r {
		// every link to one indirect node shares its identity: the node's
		// id is the inode, its special field the link count
		e.Inode = uint64(t.id)
		e.Nlink = t.special
		if e.Nlink == 0 {
			e.Nlink = 1
		}
	}
	if size, _, _, err := parseForkDesc(t.dataFork); err == nil {
		e.Size = size
	}
	if t.ownFlags&ufCompressed != 0 {
		if size, ok := f.compressedSize(t); ok {
			e.Size = size
		}
	}
	if t.isLink() {
		if tgt, err := f.readlink(t); err == nil {
			e.LinkTarget = tgt
		}
	}
	return e
}

func (f *FS) readlink(r *catRec) (string, error) {
	fr, err := f.forkReaderRaw(r.id, forkData, r.dataFork, f.extents)
	if err != nil {
		return "", err
	}
	b, err := fr.readAll(1 << 16)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// compressedSize reads the uncompressed size off the decmpfs header.
func (f *FS) compressedSize(r *catRec) (int64, bool) {
	x, err := f.xattr(r.id, decmpfs.AttrName)
	if err != nil || x == nil {
		return 0, false
	}
	b, err := x.bytes()
	if err != nil {
		return 0, false
	}
	h, ok := decmpfs.Parse(b)
	if !ok {
		return 0, false
	}
	return h.Size, true
}

// contentReader returns a file's bytes: decmpfs when flagged, else the
// data fork.
func (f *FS) contentReader(r *catRec) (io.ReaderAt, int64, error) {
	if r.ownFlags&ufCompressed != 0 {
		x, err := f.xattr(r.id, decmpfs.AttrName)
		if err != nil {
			return nil, 0, err
		}
		if x != nil {
			b, err := x.bytes()
			if err != nil {
				return nil, 0, err
			}
			h, ok := decmpfs.Parse(b)
			if !ok {
				return nil, 0, fmt.Errorf("hfsplus: cnid %d: decmpfs attribute without the cmpf header", r.id)
			}
			fork := func() (io.ReaderAt, int64, error) {
				fr, err := f.forkReaderRaw(r.id, forkRsrc, r.rsrcFork, f.extents)
				if err != nil {
					return nil, 0, err
				}
				return fr, fr.size, nil
			}
			ra, size, err := h.Reader(fork)
			if err != nil {
				return nil, 0, fmt.Errorf("hfsplus: cnid %d: %w", r.id, err)
			}
			return ra, size, nil
		}
		// the flag without the attribute: fall through to the data fork
	}
	fr, err := f.forkReaderRaw(r.id, forkData, r.dataFork, f.extents)
	if err != nil {
		return nil, 0, err
	}
	return fr, fr.size, nil
}

func (f *FS) openRecord(r *catRec) (io.ReadCloser, error) {
	t, err := f.target(r)
	if err != nil {
		return nil, err
	}
	if t.isLink() {
		s, err := f.readlink(t)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(s)), nil
	}
	ra, size, err := f.contentReader(t)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(ra, 0, size)), nil
}

// ReadDir implements fsx.FS.
func (f *FS) ReadDir(dir string) ([]fsx.Entry, error) {
	r, clean, err := f.lookup(dir)
	if err != nil {
		return nil, err
	}
	id := f.dirID(r)
	if id == 0 {
		return nil, fmt.Errorf("%s: not a directory", clean)
	}
	var out []fsx.Entry
	err = f.scanDir(id, func(c *catRec) bool {
		out = append(out, f.entry(c, c.name, path.Join(clean, c.name)))
		return true
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Stat implements fsx.FS.
func (f *FS) Stat(p string) (fsx.Entry, error) {
	r, clean, err := f.lookup(p)
	if err != nil {
		return fsx.Entry{}, err
	}
	name := path.Base(clean)
	if clean == "/" {
		name = "/"
	}
	return f.entry(r, name, clean), nil
}

// Open implements fsx.FS.
func (f *FS) Open(p string) (io.ReadCloser, error) {
	r, clean, err := f.lookup(p)
	if err != nil {
		return nil, err
	}
	if f.dirID(r) != 0 {
		return nil, fmt.Errorf("%s: is a directory", clean)
	}
	return f.openRecord(r)
}

// Walk implements fsx.FS: depth-first from the root. A directory hard
// link is reported but not descended (its target is walked in place).
func (f *FS) Walk(fn func(e fsx.Entry, open func() (io.ReadCloser, error)) error) error {
	var walk func(dir uint32, p string, depth int) error
	walk = func(dir uint32, p string, depth int) error {
		if depth > maxWalkDepth {
			return fmt.Errorf("hfsplus: directory tree too deep at %s", p)
		}
		var recs []*catRec
		if err := f.scanDir(dir, func(r *catRec) bool { recs = append(recs, r); return true }); err != nil {
			return err
		}
		sort.Slice(recs, func(i, j int) bool { return recs[i].name < recs[j].name })
		for _, r := range recs {
			e := f.entry(r, r.name, path.Join(p, r.name))
			var open func() (io.ReadCloser, error)
			if !e.IsDir && e.Mode&sIFMT == sIFREG {
				rr := r
				open = func() (io.ReadCloser, error) { return f.openRecord(rr) }
			}
			if err := fn(e, open); err != nil {
				return err
			}
			if r.isDir() {
				if err := walk(r.id, e.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(rootFolderID, "/", 0)
}
