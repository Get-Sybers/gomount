package hfsplus

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// The catalog B-tree: keys are (parent id, name as UTF-16BE); records
// are folders, files, and the thread records that map an id back to its
// (parent, name). Listing a directory is a scan from the (parent, "")
// thread record while the parent matches — no name comparison against
// Apple's case-folding table is ever needed to walk the tree; name
// matching for a lookup happens in Go over the listed names.
const (
	recFolder       = 1
	recFile         = 2
	recFolderThread = 3
	recFileThread   = 4

	folderRecSize = 88
	fileRecSize   = 248

	// file record flags
	flagHasLinkChain = 0x0020

	// bsd owner flags
	ufCompressed = 0x20

	sIFMT  = 0xf000
	sIFDIR = 0x4000
	sIFREG = 0x8000
	sIFLNK = 0xa000

	// finder info file type / creator of the link records
	typeHardLink = 0x686c6e6b // 'hlnk'
	typeDirLink  = 0x66647270 // 'fdrp'
	creatorHFS   = 0x6866732b // 'hfs+'

	maxNameChars = 255
)

// catRec is a folder or file record.
type catRec struct {
	typ      uint16
	flags    uint16
	id       uint32
	parent   uint32
	name     string
	valence  uint32 // folders: entries
	created  time.Time
	modified time.Time
	changed  time.Time // attribute modification
	accessed time.Time
	backup   time.Time
	uid      uint32
	gid      uint32
	admFlags uint8
	ownFlags uint8
	mode     uint16
	special  uint32 // link reference, link count, or device number
	fdType   uint32
	fdCreat  uint32
	dataFork []byte // the 80-byte descriptors (files)
	rsrcFork []byte
}

func (r *catRec) isDir() bool  { return r.typ == recFolder }
func (r *catRec) isLink() bool { return r.mode&sIFMT == sIFLNK }

// hardLinkTarget is the link reference of a file hard link (0 when the
// record is not one).
func (r *catRec) hardLinkTarget() uint32 {
	if r.typ == recFile && r.flags&flagHasLinkChain != 0 && r.fdType == typeHardLink && r.fdCreat == creatorHFS {
		return r.special
	}
	return 0
}

// dirLinkTarget is the directory reference of a directory hard link.
func (r *catRec) dirLinkTarget() uint32 {
	if r.typ == recFile && r.fdType == typeDirLink && r.fdCreat == creatorHFS {
		return r.special
	}
	return 0
}

// parseCatKey reads (parent, name) off a catalog key.
func parseCatKey(key []byte) (parent uint32, name string, ok bool) {
	if len(key) < 4 {
		return 0, "", false
	}
	be := binary.BigEndian
	parent = be.Uint32(key)
	if len(key) < 6 {
		return parent, "", true
	}
	n := int(be.Uint16(key[4:]))
	if n > maxNameChars || 6+2*n > len(key) {
		return 0, "", false
	}
	return parent, decodeName(key[6 : 6+2*n]), true
}

// decodeName turns UTF-16BE into a Go string; a NUL code unit (the private
// metadata directory's name starts with four) is shown as U+2400.
func decodeName(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(b[2*i:])
		if units[i] == 0 {
			units[i] = 0x2400
		}
	}
	return string(utf16.Decode(units))
}

// parseCatRec reads a folder or file record.
func parseCatRec(parent uint32, name string, data []byte) (*catRec, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("hfsplus: catalog record of %d bytes", len(data))
	}
	be := binary.BigEndian
	r := &catRec{typ: be.Uint16(data), parent: parent, name: name}
	switch r.typ {
	case recFolder:
		if len(data) < folderRecSize {
			return nil, fmt.Errorf("hfsplus: folder record of %d bytes", len(data))
		}
		r.valence = be.Uint32(data[4:])
	case recFile:
		if len(data) < fileRecSize {
			return nil, fmt.Errorf("hfsplus: file record of %d bytes", len(data))
		}
		r.dataFork = data[88:168]
		r.rsrcFork = data[168:248]
	default:
		return nil, fmt.Errorf("hfsplus: catalog record type %d where a folder or file was expected", r.typ)
	}
	r.flags = be.Uint16(data[2:])
	r.id = be.Uint32(data[8:])
	r.created = hfsTime(be.Uint32(data[12:]))
	r.modified = hfsTime(be.Uint32(data[16:]))
	r.changed = hfsTime(be.Uint32(data[20:]))
	r.accessed = hfsTime(be.Uint32(data[24:]))
	r.backup = hfsTime(be.Uint32(data[28:]))
	r.uid = be.Uint32(data[32:])
	r.gid = be.Uint32(data[36:])
	r.admFlags = data[40]
	r.ownFlags = data[41]
	r.mode = be.Uint16(data[42:])
	r.special = be.Uint32(data[44:])
	r.fdType = be.Uint32(data[48:])
	r.fdCreat = be.Uint32(data[52:])
	if r.mode&sIFMT == 0 { // uninitialised permissions: the type comes from the record kind
		if r.typ == recFolder {
			r.mode |= sIFDIR
		} else {
			r.mode |= sIFREG
		}
	}
	return r, nil
}

// catCmp is the search comparator for (parent, "") — the first record of a
// parent, which is its thread record.
func catCmp(parent uint32) func(key []byte) int {
	return func(key []byte) int {
		p, name, ok := parseCatKey(key)
		if !ok {
			return 1
		}
		if parent != p {
			if parent < p {
				return -1
			}
			return 1
		}
		if name == "" {
			return 0
		}
		return -1
	}
}

// threadOf resolves an id to its (parent, name) through the thread record.
func (f *FS) threadOf(id uint32) (parent uint32, name string, err error) {
	c, err := f.catalog.seek(catCmp(id))
	if err != nil {
		return 0, "", err
	}
	if c == nil || !c.valid() {
		return 0, "", fmt.Errorf("hfsplus: cnid %d has no thread record", id)
	}
	key, data, err := c.current()
	if err != nil {
		return 0, "", err
	}
	p, n, ok := parseCatKey(key)
	if !ok || p != id || n != "" {
		return 0, "", fmt.Errorf("hfsplus: cnid %d has no thread record", id)
	}
	be := binary.BigEndian
	if len(data) < 10 {
		return 0, "", fmt.Errorf("hfsplus: thread record of %d bytes", len(data))
	}
	if t := be.Uint16(data); t != recFolderThread && t != recFileThread {
		return 0, "", fmt.Errorf("hfsplus: cnid %d: record type %d where a thread was expected", id, t)
	}
	parent = be.Uint32(data[4:])
	nl := int(be.Uint16(data[8:]))
	if nl > maxNameChars || 10+2*nl > len(data) {
		return 0, "", fmt.Errorf("hfsplus: thread record name of %d chars", nl)
	}
	return parent, decodeName(data[10 : 10+2*nl]), nil
}

// record finds the folder or file record of an id: thread first, then the
// (parent, name) record.
func (f *FS) record(id uint32) (*catRec, error) {
	parent, name, err := f.threadOf(id)
	if err != nil {
		return nil, err
	}
	var found *catRec
	err = f.scanDir(parent, func(r *catRec) bool {
		if r.id == id && r.name == name {
			found = r
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("hfsplus: cnid %d: thread names %q under %d but no such record", id, name, parent)
	}
	return found, nil
}

// scanDir calls fn for every folder and file record whose parent is dir,
// in key order, until fn returns false.
func (f *FS) scanDir(dir uint32, fn func(r *catRec) bool) error {
	c, err := f.catalog.seek(catCmp(dir))
	if err != nil {
		return err
	}
	for ; c.valid(); err = c.next() {
		if err != nil {
			return err
		}
		key, data, err := c.current()
		if err != nil {
			return err
		}
		parent, name, ok := parseCatKey(key)
		if !ok {
			return fmt.Errorf("hfsplus: malformed catalog key under %d", dir)
		}
		if parent != dir {
			return nil
		}
		if name == "" {
			continue // the thread record
		}
		if len(data) < 2 {
			continue
		}
		if t := binary.BigEndian.Uint16(data); t != recFolder && t != recFile {
			continue
		}
		r, err := parseCatRec(parent, name, data)
		if err != nil {
			return err
		}
		if !fn(r) {
			return nil
		}
	}
	return err
}

// nameMatch compares a listed name with a looked-up component: binary on
// HFSX, case-insensitive on HFS+ (Go's Unicode simple folding stands in
// for Apple's table; names are stored decomposed, so a precomposed
// lookup of an accented name will not match).
func (f *FS) nameMatch(listed, want string) bool {
	if listed == want {
		return true
	}
	return f.caseFold && strings.EqualFold(listed, want)
}

// childID returns the id of the child of dir named exactly name, 0 when absent.
func (f *FS) childID(dir uint32, name string) uint32 {
	var id uint32
	shown := decodeName(encodeName(name))
	_ = f.scanDir(dir, func(r *catRec) bool {
		if r.name == shown {
			id = r.id
			return false
		}
		return true
	})
	return id
}

// encodeName is the UTF-16BE form of a Go string (the inverse of decodeName
// for names without U+2400).
func encodeName(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(b[2*i:], u)
	}
	return b
}
