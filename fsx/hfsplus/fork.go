package hfsplus

import (
	"encoding/binary"
	"fmt"
	"io"
)

// A fork (a file's data or resource fork, a B-tree file, an attribute's
// data) is a logical size and up to eight extents in its descriptor; the
// rest live in the extents overflow B-tree, keyed by (fork type, file id,
// first logical block), eight per record.
const (
	forkDescSize  = 80
	extentsPerRec = 8
)

type extent struct {
	start uint32 // allocation block
	count uint32
}

type forkReader struct {
	f    *FS
	exts []extent
	size int64 // logical size
}

// parseForkDesc reads an HFSPlusForkData: logical size, clump, block
// count, eight extents.
func parseForkDesc(b []byte) (size int64, blocks uint32, exts []extent, err error) {
	if len(b) < forkDescSize {
		return 0, 0, nil, fmt.Errorf("hfsplus: fork descriptor of %d bytes", len(b))
	}
	be := binary.BigEndian
	size = int64(be.Uint64(b))
	blocks = be.Uint32(b[12:])
	exts = parseExtents(b[16:80])
	return size, blocks, exts, nil
}

// parseExtents reads an HFSPlusExtentRecord, dropping the unused (0,0) tail.
func parseExtents(b []byte) []extent {
	be := binary.BigEndian
	var out []extent
	for i := 0; i+8 <= len(b) && i < 8*extentsPerRec; i += 8 {
		e := extent{start: be.Uint32(b[i:]), count: be.Uint32(b[i+4:])}
		if e.count == 0 {
			break
		}
		out = append(out, e)
	}
	return out
}

// forkReaderRaw opens a fork from its descriptor bytes, completing the
// extents from the overflow tree (ovf nil while the overflow tree itself
// is being opened).
func (f *FS) forkReaderRaw(cnid uint32, forkType byte, desc []byte, ovf *btree) (*forkReader, error) {
	size, blocks, exts, err := parseForkDesc(desc)
	if err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("hfsplus: fork of cnid %d: negative size", cnid)
	}
	have := uint32(0)
	for _, e := range exts {
		have += e.count
	}
	for ovf != nil && have < blocks {
		more, err := f.overflowExtents(ovf, cnid, forkType, have)
		if err != nil {
			return nil, err
		}
		if len(more) == 0 {
			break // the descriptor over-counted: serve what is addressable
		}
		for _, e := range more {
			have += e.count
		}
		exts = append(exts, more...)
		if len(exts) > 1<<20 {
			return nil, fmt.Errorf("hfsplus: fork of cnid %d: more than a million extents", cnid)
		}
	}
	return &forkReader{f: f, exts: exts, size: size}, nil
}

// overflowExtents looks up the overflow record for (forkType, cnid,
// startBlock): the eight extents from that logical block on.
func (f *FS) overflowExtents(ovf *btree, cnid uint32, forkType byte, startBlock uint32) ([]extent, error) {
	be := binary.BigEndian
	c, err := ovf.seek(func(key []byte) int {
		if len(key) < 10 {
			return 1
		}
		if forkType != key[0] {
			if forkType < key[0] {
				return -1
			}
			return 1
		}
		if id := be.Uint32(key[2:]); id != cnid {
			if cnid < id {
				return -1
			}
			return 1
		}
		if sb := be.Uint32(key[6:]); sb != startBlock {
			if startBlock < sb {
				return -1
			}
			return 1
		}
		return 0
	})
	if err != nil || c == nil || !c.valid() {
		return nil, err
	}
	key, data, err := c.current()
	if err != nil {
		return nil, err
	}
	if len(key) < 10 || key[0] != forkType || be.Uint32(key[2:]) != cnid || be.Uint32(key[6:]) != startBlock {
		return nil, nil // no record for this position
	}
	return parseExtents(data), nil
}

// ReadAt serves the fork's logical bytes from its extents.
func (r *forkReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("hfsplus: negative offset")
	}
	bs := r.f.blockSize
	total := 0
	for len(p) > 0 {
		if off >= r.size {
			return total, io.EOF
		}
		n := int64(len(p))
		if off+n > r.size {
			n = r.size - off
		}
		// the extent covering off
		var logical int64
		found := false
		for _, e := range r.exts {
			length := int64(e.count) * bs
			if off < logical+length {
				within := off - logical
				if length-within < n {
					n = length - within
				}
				vol := int64(e.start)*bs + within
				got, err := r.f.ra.ReadAt(p[:n], vol)
				if err != nil && int64(got) < n {
					return total + got, fmt.Errorf("hfsplus: read block %d: %w", e.start, err)
				}
				found = true
				break
			}
			logical += length
		}
		if !found {
			// past the last extent but within the logical size: the
			// descriptor promised blocks the tree does not hold
			return total, fmt.Errorf("hfsplus: fork offset %d beyond its %d extents", off, len(r.exts))
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}

// readAll reads a whole bounded fork into memory.
func (r *forkReader) readAll(limit int64) ([]byte, error) {
	if r.size > limit {
		return nil, fmt.Errorf("hfsplus: fork of %d bytes exceeds the %d-byte limit", r.size, limit)
	}
	b := make([]byte, r.size)
	if _, err := r.ReadAt(b, 0); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}
