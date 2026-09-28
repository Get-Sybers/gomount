package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/gomount/fsx"
	"github.com/get-sybers/gomount/fsx/decmpfs"
)

// A volume: its superblock (apfs_superblock_t, "APSB") names the volume
// object map (physical) and the file-system tree root (virtual, resolved
// through that map at the superblock's transaction). Every file-system
// record is a key in that one tree — inode, directory record, extended
// attribute, data-stream id, file extent — ordered by (object id, type).
const (
	fsTypeInode      = 0x3
	fsTypeXattr      = 0x4
	fsTypeSibling    = 0x5
	fsTypeDstreamID  = 0x6
	fsTypeFileExtent = 0x8
	fsTypeDirRec     = 0x9

	rootDirID    = 2
	privateDirID = 3

	inodeFixedSize = 92
	drecFixedSize  = 18

	xfInoName    = 4
	xfInoDstream = 8
	xfInoSparse  = 13

	xattrDataStream   = 0x1
	xattrDataEmbedded = 0x2

	sIFMT  = 0xf000
	sIFDIR = 0x4000
	sIFREG = 0x8000
	sIFLNK = 0xa000

	ufCompressed = 0x20 // bsd_flags: the content is decmpfs-compressed

	xattrDecmpfs = decmpfs.AttrName
	xattrRsrc    = decmpfs.RsrcName
	xattrSymlink = "com.apple.fs.symlink"

	maxWalkDepth = 128
)

// Volume is one opened APFS volume; it implements fsx.FS.
type Volume struct {
	c        *Container
	info     VolumeInfo
	xid      uint64
	omap     *tree
	fs       *tree
	fext     *tree // the file-extent tree, when the volume keeps extents there (nil otherwise)
	caseFold bool
}

func openVolume(c *Container, info VolumeInfo, sb []byte) (*Volume, error) {
	le := binary.LittleEndian
	v := &Volume{c: c, info: info, xid: info.Xid, caseFold: info.CaseInsensitive}
	if incompat := le.Uint64(sb[56:]); incompat&(fsIncompatPFK) != 0 {
		return nil, fmt.Errorf("apfs: volume %q: per-file keys (unsupported)", info.Name)
	}
	omapRoot, err := c.omapRoot(le.Uint64(sb[128:]))
	if err != nil {
		return nil, fmt.Errorf("apfs: volume %q object map: %w", info.Name, err)
	}
	v.omap = &tree{br: &c.br, rootAddr: omapRoot, resolve: identity}
	if err := v.omap.open(); err != nil {
		return nil, fmt.Errorf("apfs: volume %q object map tree: %w", info.Name, err)
	}
	rootOID := le.Uint64(sb[136:])
	rootAddr, err := v.omap.omapLookup(rootOID, v.xid)
	if err != nil {
		return nil, fmt.Errorf("apfs: volume %q root tree: %w", info.Name, err)
	}
	v.fs = &tree{br: &c.br, rootAddr: rootAddr, rootOID: rootOID, resolve: func(oid uint64) (uint64, error) {
		return v.omap.omapLookup(oid, v.xid)
	}}
	if err := v.fs.open(); err != nil {
		return nil, fmt.Errorf("apfs: volume %q file-system tree: %w", info.Name, err)
	}
	// a volume with a file-extent tree (apfs_fext_tree_oid, sealed system
	// volumes and newer formats) keeps extents there, not in the fs tree
	if len(sb) >= 1040 {
		if fextOID := le.Uint64(sb[1032:]); fextOID != 0 {
			addr, err := v.omap.omapLookup(fextOID, v.xid)
			if err != nil {
				addr = fextOID // a physical root
			}
			ft := &tree{br: &c.br, rootAddr: addr, rootOID: fextOID, resolve: func(oid uint64) (uint64, error) {
				if p, err := v.omap.omapLookup(oid, v.xid); err == nil {
					return p, nil
				}
				return oid, nil
			}}
			if err := ft.open(); err == nil {
				v.fext = ft
			}
		}
	}
	if _, err := v.inode(rootDirID); err != nil {
		return nil, fmt.Errorf("apfs: volume %q root directory: %w", info.Name, err)
	}
	return v, nil
}

// VolumeInfo is what the container reported for this volume.
func (v *Volume) VolumeInfo() VolumeInfo { return v.info }

// Info implements fsx.FS.
func (v *Volume) Info() fsx.Info {
	return fsx.Info{Type: "apfs", UUID: v.info.UUID, Label: v.info.Name, BlockSize: v.c.blockSize}
}

// ---- record access -------------------------------------------------------------

// rangeFS visits every record with the given (object id, type), in key
// order, until fn returns false.
func (v *Volume) rangeFS(objID uint64, typ uint8, fn func(key, val []byte) (bool, error)) error {
	cmp := func(k []byte) int {
		if len(k) < 8 {
			return 1
		}
		hdr := binary.LittleEndian.Uint64(k)
		ko, kt := hdr&0x0fffffffffffffff, uint8(hdr>>60)
		switch {
		case objID < ko:
			return -1
		case objID > ko:
			return 1
		case typ < kt:
			return -1
		case typ > kt:
			return 1
		}
		return -1 // the target is the smallest key of its (id, type)
	}
	it, err := v.fs.seek(cmp)
	if err != nil {
		return err
	}
	for it.valid() {
		k, val, err := it.current()
		if err != nil {
			return err
		}
		if len(k) < 8 {
			return fmt.Errorf("apfs: file-system key too short")
		}
		hdr := binary.LittleEndian.Uint64(k)
		if hdr&0x0fffffffffffffff != objID || uint8(hdr>>60) != typ {
			return nil
		}
		cont, err := fn(k[8:], val)
		if err != nil || !cont {
			return err
		}
		if err := it.next(); err != nil {
			return err
		}
	}
	return nil
}

// inode is a parsed j_inode_val_t with the extended fields it carries.
type inode struct {
	id, parent, privateID      uint64
	btime, mtime, ctime, atime time.Time
	flags                      uint64
	nlink                      uint32
	bsdFlags                   uint32
	uid, gid                   uint32
	mode                       uint16
	name                       string
	size, allocSize            int64
	hasDstream                 bool
}

func apfsTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns)).UTC()
}

func (v *Volume) inode(id uint64) (*inode, error) {
	var found *inode
	err := v.rangeFS(id, fsTypeInode, func(_, val []byte) (bool, error) {
		in, err := parseInode(id, val)
		if err != nil {
			return false, err
		}
		found = in
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("apfs: inode %d not found", id)
	}
	return found, nil
}

func parseInode(id uint64, val []byte) (*inode, error) {
	if len(val) < inodeFixedSize {
		return nil, fmt.Errorf("apfs: inode %d value too short (%d bytes)", id, len(val))
	}
	le := binary.LittleEndian
	in := &inode{
		id: id, parent: le.Uint64(val[0:]), privateID: le.Uint64(val[8:]),
		btime: apfsTime(le.Uint64(val[16:])), mtime: apfsTime(le.Uint64(val[24:])),
		ctime: apfsTime(le.Uint64(val[32:])), atime: apfsTime(le.Uint64(val[40:])),
		flags: le.Uint64(val[48:]), nlink: le.Uint32(val[56:]),
		bsdFlags: le.Uint32(val[68:]), uid: le.Uint32(val[72:]), gid: le.Uint32(val[76:]),
		mode: le.Uint16(val[80:]),
	}
	// extended fields: descriptors, then 8-byte aligned values in order
	xf := val[inodeFixedSize:]
	if len(xf) >= 4 {
		n := int(le.Uint16(xf))
		if 4+4*n <= len(xf) {
			data := 4 + 4*n
			for i := 0; i < n; i++ {
				d := xf[4+4*i:]
				typ, size := d[0], int(le.Uint16(d[2:]))
				if data+size > len(xf) {
					break
				}
				field := xf[data : data+size]
				switch typ {
				case xfInoName:
					in.name = strings.TrimRight(string(field), "\x00")
				case xfInoDstream:
					if len(field) >= 16 {
						in.size = int64(le.Uint64(field))
						in.allocSize = int64(le.Uint64(field[8:]))
						in.hasDstream = true
					}
				}
				data += (size + 7) &^ 7
			}
		}
	}
	return in, nil
}

// dirent is a parsed directory record.
type dirent struct {
	name      string
	fileID    uint64
	dateAdded time.Time
	typ       uint16
}

// readDir lists a directory's records. The key carries the name either
// with a hash (j_drec_hashed_key_t: 10-bit length + 22-bit hash) or plain
// (j_drec_key_t: 16-bit length); the stored key size tells them apart.
func (v *Volume) readDir(dirID uint64) ([]dirent, error) {
	var out []dirent
	err := v.rangeFS(dirID, fsTypeDirRec, func(rest, val []byte) (bool, error) {
		if d, ok := parseDrec(rest, val); ok {
			out = append(out, d)
		}
		return true, nil // an unrecognised record never hides its siblings
	})
	return out, err
}

// parseDrec decodes one directory record from the key bytes past the
// header and the value.
func parseDrec(rest, val []byte) (dirent, bool) {
	le := binary.LittleEndian
	var name string
	switch {
	case len(rest) >= 4 && 4+int(le.Uint32(rest)&0x3ff) == len(rest):
		n := int(le.Uint32(rest) & 0x3ff)
		name = strings.TrimRight(string(rest[4:4+n]), "\x00")
	case len(rest) >= 2 && 2+int(le.Uint16(rest)) == len(rest):
		n := int(le.Uint16(rest))
		name = strings.TrimRight(string(rest[2:2+n]), "\x00")
	default:
		return dirent{}, false
	}
	if len(val) < drecFixedSize {
		return dirent{}, false
	}
	return dirent{
		name: name, fileID: le.Uint64(val), dateAdded: apfsTime(le.Uint64(val[8:])),
		typ: le.Uint16(val[16:]) & 0xf,
	}, true
}

// xattr is one extended attribute: embedded bytes, or a data stream.
type xattr struct {
	name     string
	flags    uint16
	data     []byte // embedded
	streamID uint64 // XATTR_DATA_STREAM
	size     int64
}

func (v *Volume) xattrs(id uint64) ([]xattr, error) {
	var out []xattr
	err := v.rangeFS(id, fsTypeXattr, func(rest, val []byte) (bool, error) {
		le := binary.LittleEndian
		if len(rest) < 2 || len(val) < 4 {
			return true, nil
		}
		n := int(le.Uint16(rest))
		if 2+n > len(rest) {
			return true, nil
		}
		x := xattr{name: strings.TrimRight(string(rest[2:2+n]), "\x00"), flags: le.Uint16(val)}
		dlen := int(le.Uint16(val[2:]))
		if 4+dlen > len(val) {
			dlen = len(val) - 4
		}
		data := val[4 : 4+dlen]
		if x.flags&xattrDataStream != 0 {
			if len(data) >= 16 {
				x.streamID = le.Uint64(data)
				x.size = int64(le.Uint64(data[8:]))
			}
		} else {
			x.data = data
			x.size = int64(len(data))
		}
		out = append(out, x)
		return true, nil
	})
	return out, err
}

func (v *Volume) xattr(id uint64, name string) (*xattr, error) {
	xs, err := v.xattrs(id)
	if err != nil {
		return nil, err
	}
	for i := range xs {
		if xs[i].name == name {
			return &xs[i], nil
		}
	}
	return nil, nil
}

// extent is one file extent: a run of blocks holding [logical, logical+length).
type extent struct {
	logical uint64
	length  uint64
	paddr   uint64 // 0: a hole (sparse), reads as zeros
}

func (v *Volume) extents(streamID uint64) ([]extent, error) {
	if v.fext != nil {
		if out, err := v.fextExtents(streamID); err == nil && len(out) > 0 {
			return out, nil
		}
	}
	var out []extent
	err := v.rangeFS(streamID, fsTypeFileExtent, func(rest, val []byte) (bool, error) {
		le := binary.LittleEndian
		if len(rest) < 8 || len(val) < 24 {
			return true, nil
		}
		out = append(out, extent{
			logical: le.Uint64(rest),
			length:  le.Uint64(val) & 0x00ffffffffffffff,
			paddr:   le.Uint64(val[8:]),
		})
		return true, nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].logical < out[j].logical })
	return out, err
}

// fextExtents reads a stream's extents off the file-extent tree: 16-byte
// keys (private id, logical address), 16-byte values (length and flags,
// physical block).
func (v *Volume) fextExtents(streamID uint64) ([]extent, error) {
	le := binary.LittleEndian
	cmp := func(k []byte) int {
		if len(k) < 16 {
			return 1
		}
		ko := le.Uint64(k)
		switch {
		case streamID < ko:
			return -1
		case streamID > ko:
			return 1
		}
		return -1
	}
	it, err := v.fext.seek(cmp)
	if err != nil {
		return nil, err
	}
	var out []extent
	for it.valid() {
		k, val, err := it.current()
		if err != nil {
			return nil, err
		}
		if len(k) < 16 || le.Uint64(k) != streamID {
			break
		}
		if len(val) >= 16 {
			out = append(out, extent{
				logical: le.Uint64(k[8:]),
				length:  le.Uint64(val) & 0x00ffffffffffffff,
				paddr:   le.Uint64(val[8:]),
			})
		}
		if err := it.next(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].logical < out[j].logical })
	return out, nil
}

// ---- paths and the fsx.FS view ----------------------------------------------

func (v *Volume) nameMatch(a, b string) bool {
	if v.caseFold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// lookup resolves a volume path to its inode.
func (v *Volume) lookup(p string) (*inode, string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	cur, err := v.inode(rootDirID)
	if err != nil {
		return nil, "", err
	}
	if clean == "/" {
		return cur, "/", nil
	}
	for _, comp := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if cur.mode&sIFMT != sIFDIR {
			return nil, "", fmt.Errorf("%s: not a directory", clean)
		}
		ents, err := v.readDir(cur.id)
		if err != nil {
			return nil, "", err
		}
		var next uint64
		for _, d := range ents {
			if v.nameMatch(d.name, comp) {
				next = d.fileID
				break
			}
		}
		if next == 0 {
			return nil, "", fmt.Errorf("%s: no such file or directory", clean)
		}
		if cur, err = v.inode(next); err != nil {
			return nil, "", err
		}
	}
	return cur, clean, nil
}

// entry shapes an inode into the fsx view.
func (v *Volume) entry(in *inode, name, fullPath string) fsx.Entry {
	e := fsx.Entry{
		Name: name, Path: fullPath,
		IsDir: in.mode&sIFMT == sIFDIR,
		Mode:  uint32(in.mode),
		UID:   in.uid, GID: in.gid,
		Inode: in.id, Nlink: in.nlink,
		Size:      in.size,
		Allocated: true,
		Btime:     in.btime, Mtime: in.mtime, Atime: in.atime, Ctime: in.ctime,
	}
	if in.bsdFlags&ufCompressed != 0 {
		if size, ok := v.compressedSize(in); ok {
			e.Size = size
		}
	}
	if in.mode&sIFMT == sIFLNK {
		if t, err := v.readlink(in); err == nil {
			e.LinkTarget = t
		}
	}
	return e
}

func (v *Volume) readlink(in *inode) (string, error) {
	x, err := v.xattr(in.id, xattrSymlink)
	if err != nil {
		return "", err
	}
	if x == nil {
		return "", fmt.Errorf("apfs: symlink %d without a target attribute", in.id)
	}
	if x.data != nil {
		return strings.TrimRight(string(x.data), "\x00"), nil
	}
	b, err := v.readStream(x.streamID, x.size, 1<<16)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\x00"), nil
}

// ReadDir implements fsx.FS.
func (v *Volume) ReadDir(dir string) ([]fsx.Entry, error) {
	in, clean, err := v.lookup(dir)
	if err != nil {
		return nil, err
	}
	if in.mode&sIFMT != sIFDIR {
		return nil, fmt.Errorf("%s: not a directory", clean)
	}
	ents, err := v.readDir(in.id)
	if err != nil {
		return nil, err
	}
	var out []fsx.Entry
	for _, d := range ents {
		ci, err := v.inode(d.fileID)
		if err != nil {
			continue // an unreadable child never hides its siblings
		}
		out = append(out, v.entry(ci, d.name, path.Join(clean, d.name)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Stat implements fsx.FS.
func (v *Volume) Stat(p string) (fsx.Entry, error) {
	in, clean, err := v.lookup(p)
	if err != nil {
		return fsx.Entry{}, err
	}
	name := path.Base(clean)
	if clean == "/" {
		name = "/"
	}
	return v.entry(in, name, clean), nil
}

// Open implements fsx.FS.
func (v *Volume) Open(p string) (io.ReadCloser, error) {
	in, clean, err := v.lookup(p)
	if err != nil {
		return nil, err
	}
	if in.mode&sIFMT == sIFDIR {
		return nil, fmt.Errorf("%s: is a directory", clean)
	}
	return v.openInode(in)
}

func (v *Volume) openInode(in *inode) (io.ReadCloser, error) {
	if in.mode&sIFMT == sIFLNK {
		t, err := v.readlink(in)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(t)), nil
	}
	ra, size, err := v.contentReader(in)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(ra, 0, size)), nil
}

// Walk implements fsx.FS: depth-first from the volume root.
func (v *Volume) Walk(fn func(e fsx.Entry, open func() (io.ReadCloser, error)) error) error {
	var walk func(in *inode, dir string, depth int) error
	walk = func(in *inode, dir string, depth int) error {
		if depth > maxWalkDepth {
			return fmt.Errorf("apfs: directory tree too deep at %s", dir)
		}
		ents, err := v.readDir(in.id)
		if err != nil {
			return err
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].name < ents[j].name })
		for _, d := range ents {
			ci, err := v.inode(d.fileID)
			if err != nil {
				continue
			}
			e := v.entry(ci, d.name, path.Join(dir, d.name))
			var open func() (io.ReadCloser, error)
			if ci.mode&sIFMT == sIFREG {
				ciCopy := ci
				open = func() (io.ReadCloser, error) { return v.openInode(ciCopy) }
			}
			if err := fn(e, open); err != nil {
				return err
			}
			if e.IsDir {
				if err := walk(ci, e.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	root, err := v.inode(rootDirID)
	if err != nil {
		return err
	}
	return walk(root, "/", 0)
}
