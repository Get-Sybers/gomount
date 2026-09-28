package hfsplus

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The attributes B-tree: keys are (file id, start block, name as
// UTF-16BE), ordered by id, then name (binary), then start block. A record
// is inline data (0x10), a fork descriptor (0x20) for large values, or an
// overflow extents record (0x30) continuing a fork at a start block.
const (
	attrInline  = 0x10
	attrFork    = 0x20
	attrExtents = 0x30

	maxAttrValue = 64 << 20
)

type xattr struct {
	name string
	data []byte      // inline value
	fork *forkReader // or a fork-backed value
}

func (x *xattr) size() int64 {
	if x.fork != nil {
		return x.fork.size
	}
	return int64(len(x.data))
}

// bytes reads the value whole (bounded).
func (x *xattr) bytes() ([]byte, error) {
	if x.fork != nil {
		return x.fork.readAll(maxAttrValue)
	}
	return x.data, nil
}

// readerAt serves the value.
func (x *xattr) readerAt() (io.ReaderAt, int64) {
	if x.fork != nil {
		return x.fork, x.fork.size
	}
	return bytesReaderAt(x.data), int64(len(x.data))
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// parseAttrKey reads (id, startBlock, name) off an attributes key.
func parseAttrKey(key []byte) (id, startBlock uint32, name string, ok bool) {
	if len(key) < 12 {
		return 0, 0, "", false
	}
	be := binary.BigEndian
	id = be.Uint32(key[2:])
	startBlock = be.Uint32(key[6:])
	n := int(be.Uint16(key[10:]))
	if 12+2*n > len(key) {
		return 0, 0, "", false
	}
	return id, startBlock, decodeName(key[12 : 12+2*n]), true
}

// xattrs lists a file's extended attributes.
func (f *FS) xattrs(id uint32) ([]xattr, error) {
	if f.attributes == nil {
		return nil, nil
	}
	be := binary.BigEndian
	c, err := f.attributes.seek(func(key []byte) int {
		kid, _, _, ok := parseAttrKey(key)
		if !ok {
			return 1
		}
		if id != kid {
			if id < kid {
				return -1
			}
			return 1
		}
		return -1 // the empty search name sorts before every attribute
	})
	if err != nil {
		return nil, err
	}
	var out []xattr
	for ; c.valid(); err = c.next() {
		if err != nil {
			return nil, err
		}
		key, data, err := c.current()
		if err != nil {
			return nil, err
		}
		kid, startBlock, name, ok := parseAttrKey(key)
		if !ok {
			return nil, fmt.Errorf("hfsplus: malformed attribute key on cnid %d", id)
		}
		if kid != id {
			break
		}
		if len(data) < 4 {
			continue
		}
		switch be.Uint32(data) {
		case attrInline:
			if len(data) < 16 {
				continue
			}
			n := int(be.Uint32(data[12:]))
			if n < 0 || 16+n > len(data) {
				return nil, fmt.Errorf("hfsplus: cnid %d attribute %q: %d bytes inline in a %d-byte record", id, name, n, len(data))
			}
			out = append(out, xattr{name: name, data: data[16 : 16+n]})
		case attrFork:
			if len(data) < 8+forkDescSize || startBlock != 0 {
				continue
			}
			fr, err := f.attrFork(id, name, data[8:8+forkDescSize])
			if err != nil {
				return nil, err
			}
			out = append(out, xattr{name: name, fork: fr})
		case attrExtents:
			// continuation of the previous fork-backed value: consumed by attrFork
		}
	}
	return out, err
}

// attrFork opens a fork-backed attribute value: the descriptor's extents,
// then any 0x30 records keyed by the blocks so far.
func (f *FS) attrFork(id uint32, name string, desc []byte) (*forkReader, error) {
	size, blocks, exts, err := parseForkDesc(desc)
	if err != nil {
		return nil, err
	}
	have := uint32(0)
	for _, e := range exts {
		have += e.count
	}
	be := binary.BigEndian
	want := encodeName(name)
	for have < blocks {
		start := have
		c, err := f.attributes.seek(func(key []byte) int {
			kid, sb, kname, ok := parseAttrKey(key)
			if !ok {
				return 1
			}
			if id != kid {
				if id < kid {
					return -1
				}
				return 1
			}
			if kn := encodeName(kname); string(want) != string(kn) {
				if string(want) < string(kn) {
					return -1
				}
				return 1
			}
			if start != sb {
				if start < sb {
					return -1
				}
				return 1
			}
			return 0
		})
		if err != nil {
			return nil, err
		}
		if c == nil || !c.valid() {
			break
		}
		key, data, err := c.current()
		if err != nil {
			return nil, err
		}
		kid, sb, kname, ok := parseAttrKey(key)
		if !ok || kid != id || kname != name || sb != start || len(data) < 8+8*extentsPerRec || be.Uint32(data) != attrExtents {
			break
		}
		more := parseExtents(data[8 : 8+8*extentsPerRec])
		if len(more) == 0 {
			break
		}
		for _, e := range more {
			have += e.count
		}
		exts = append(exts, more...)
	}
	return &forkReader{f: f, exts: exts, size: size}, nil
}

// xattr returns one named attribute, nil when absent.
func (f *FS) xattr(id uint32, name string) (*xattr, error) {
	xs, err := f.xattrs(id)
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
