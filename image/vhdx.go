// VHDX (Virtual Hard Disk v2, "vhdxfile") containers, read-only: the
// region table, the metadata items that size the disk, the block
// allocation table with its interleaved sector-bitmap entries, and a
// differencing chain through the parent locator (relative_path first). The
// log is not replayed. All fields little-endian. Ported from VMkatz's
// vhdx.rs (github.com/nikaiw/VMkatz, MIT, Nicolas Devillers).
package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

var (
	sigVhdxfile    = []byte("vhdxfile")
	sigVhdxHead    = []byte("head")
	sigVhdxRegi    = []byte("regi")
	sigVhdxMeta    = []byte("metadata")
	vhdxGUIDBat    = [16]byte{0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08}
	vhdxGUIDMeta   = [16]byte{0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e}
	vhdxMetaParams = [16]byte{0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b}
	vhdxMetaSize   = [16]byte{0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8}
	vhdxMetaSector = [16]byte{0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f}
	vhdxMetaParent = [16]byte{0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c}
)

const (
	vhdxBlockNotPresent       = 0
	vhdxBlockFullyPresent     = 6
	vhdxBlockPartiallyPresent = 7
	vhdxOffsetMask            = 0xfffffffffff00000
)

type vhdxDisk struct {
	f           *os.File
	size        int64
	blockSize   int64
	sectorSize  int64
	chunkRatio  int64
	bat         []uint64
	parent      io.ReaderAt
	parentClose func() error
}

// looksLikeVHDX reports the file identifier at offset 0.
func looksLikeVHDX(f io.ReaderAt) bool {
	var b [8]byte
	if _, err := f.ReadAt(b[:], 0); err != nil {
		return false
	}
	return bytes.Equal(b[:], sigVhdxfile)
}

type vhdxMetaEntry struct {
	id     [16]byte
	offset uint32
	length uint32
}

func vhdxMetaEntries(f io.ReaderAt, metaOff int64) ([]vhdxMetaEntry, error) {
	var hdr [32]byte
	if _, err := f.ReadAt(hdr[:], metaOff); err != nil {
		return nil, fmt.Errorf("vhdx: read metadata table: %w", err)
	}
	if !bytes.Equal(hdr[0:8], sigVhdxMeta) {
		return nil, errors.New("vhdx: bad metadata signature")
	}
	count := int(binary.LittleEndian.Uint16(hdr[10:12]))
	if count > 2047 {
		return nil, errors.New("vhdx: metadata entry count too large")
	}
	raw := make([]byte, count*32)
	if _, err := f.ReadAt(raw, metaOff+32); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("vhdx: read metadata entries: %w", err)
	}
	out := make([]vhdxMetaEntry, count)
	for i := range out {
		e := raw[i*32:]
		copy(out[i].id[:], e[0:16])
		out[i].offset = binary.LittleEndian.Uint32(e[16:20])
		out[i].length = binary.LittleEndian.Uint32(e[20:24])
	}
	return out, nil
}

func utf16leString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// vhdxParentRef reads the parent locator's relative_path (else
// absolute_win32_path).
func vhdxParentRef(f io.ReaderAt, metaOff int64, entries []vhdxMetaEntry) string {
	for _, e := range entries {
		if e.id != vhdxMetaParent || e.length < 20 || e.length > 1<<16 {
			continue
		}
		base := metaOff + int64(e.offset)
		var hdr [20]byte
		if _, err := f.ReadAt(hdr[:], base); err != nil {
			return ""
		}
		kvCount := int(binary.LittleEndian.Uint16(hdr[18:20]))
		if kvCount > 64 {
			return ""
		}
		kvs := make([]byte, kvCount*12)
		if _, err := f.ReadAt(kvs, base+20); err != nil && !errors.Is(err, io.EOF) {
			return ""
		}
		var rel, abs string
		for i := 0; i < kvCount; i++ {
			kv := kvs[i*12:]
			ko := int64(binary.LittleEndian.Uint32(kv[0:4]))
			vo := int64(binary.LittleEndian.Uint32(kv[4:8]))
			kl := int(binary.LittleEndian.Uint16(kv[8:10]))
			vl := int(binary.LittleEndian.Uint16(kv[10:12]))
			if kl > 4096 || vl > 4096 {
				continue
			}
			kb, vb := make([]byte, kl), make([]byte, vl)
			if _, err := f.ReadAt(kb, base+ko); err != nil && !errors.Is(err, io.EOF) {
				continue
			}
			if _, err := f.ReadAt(vb, base+vo); err != nil && !errors.Is(err, io.EOF) {
				continue
			}
			switch utf16leString(kb) {
			case "relative_path":
				rel = utf16leString(vb)
			case "absolute_win32_path":
				abs = utf16leString(vb)
			}
		}
		if rel != "" {
			return rel
		}
		return abs
	}
	return ""
}

func openVHDX(path string, depth int) (*vhdxDisk, error) {
	if depth > 16 {
		return nil, errors.New("vhdx: differencing chain deeper than 16")
	}
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, err
	}
	if !looksLikeVHDX(f) {
		f.Close()
		return nil, errors.New("vhdx: bad file identifier")
	}
	// the region table: at 0x30000, its copy at 0x40000
	var regOff int64 = -1
	var rt [16]byte
	for _, off := range []int64{0x30000, 0x40000} {
		if _, err := f.ReadAt(rt[:], off); err == nil && bytes.Equal(rt[0:4], sigVhdxRegi) {
			regOff = off
			break
		}
	}
	if regOff < 0 {
		f.Close()
		return nil, errors.New("vhdx: no region table")
	}
	count := int(binary.LittleEndian.Uint32(rt[8:12]))
	if count > 2047 {
		f.Close()
		return nil, errors.New("vhdx: region entry count too large")
	}
	raw := make([]byte, count*32)
	if _, err := f.ReadAt(raw, regOff+16); err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return nil, fmt.Errorf("vhdx: read region table: %w", err)
	}
	var batOff, metaOff int64
	var batLen uint32
	for i := 0; i < count; i++ {
		e := raw[i*32:]
		var id [16]byte
		copy(id[:], e[0:16])
		off := int64(binary.LittleEndian.Uint64(e[16:24]))
		ln := binary.LittleEndian.Uint32(e[24:28])
		switch id {
		case vhdxGUIDBat:
			batOff, batLen = off, ln
		case vhdxGUIDMeta:
			metaOff = off
		}
	}
	if batOff == 0 || metaOff == 0 {
		f.Close()
		return nil, errors.New("vhdx: region table lacks BAT or metadata")
	}
	entries, err := vhdxMetaEntries(f, metaOff)
	if err != nil {
		f.Close()
		return nil, err
	}
	d := &vhdxDisk{f: f, sectorSize: 512}
	hasParent := false
	for _, e := range entries {
		base := metaOff + int64(e.offset)
		var b [8]byte
		switch e.id {
		case vhdxMetaParams:
			if e.length >= 8 {
				if _, err := f.ReadAt(b[:], base); err == nil {
					d.blockSize = int64(binary.LittleEndian.Uint32(b[0:4]))
					hasParent = binary.LittleEndian.Uint32(b[4:8])&2 != 0
				}
			}
		case vhdxMetaSize:
			if e.length >= 8 {
				if _, err := f.ReadAt(b[:], base); err == nil {
					d.size = int64(binary.LittleEndian.Uint64(b[:]))
				}
			}
		case vhdxMetaSector:
			if e.length >= 4 {
				if _, err := f.ReadAt(b[:4], base); err == nil {
					d.sectorSize = int64(binary.LittleEndian.Uint32(b[0:4]))
				}
			}
		}
	}
	if d.blockSize <= 0 || d.size <= 0 || d.sectorSize <= 0 || d.size > 1<<50 {
		f.Close()
		return nil, errors.New("vhdx: metadata lacks block size or disk size")
	}
	d.chunkRatio = (8388608 * d.sectorSize) / d.blockSize
	if d.chunkRatio == 0 {
		f.Close()
		return nil, errors.New("vhdx: invalid chunk ratio")
	}
	dataBlocks := (d.size + d.blockSize - 1) / d.blockSize
	var total int64
	switch {
	case hasParent:
		sb := (dataBlocks + d.chunkRatio - 1) / d.chunkRatio
		total = sb * (d.chunkRatio + 1)
	case dataBlocks > 0:
		total = dataBlocks + (dataBlocks-1)/d.chunkRatio
	}
	if max := int64(batLen) / 8; total > max {
		total = max
	}
	if total > 1<<26 {
		f.Close()
		return nil, errors.New("vhdx: implausible BAT size")
	}
	rawBat := make([]byte, total*8)
	if _, err := f.ReadAt(rawBat, batOff); err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return nil, fmt.Errorf("vhdx: read BAT: %w", err)
	}
	d.bat = make([]uint64, total)
	for i := range d.bat {
		d.bat[i] = binary.LittleEndian.Uint64(rawBat[i*8:])
	}
	if hasParent {
		if ref := vhdxParentRef(f, metaOff, entries); ref != "" {
			pp := resolveVHDParent(path, ref)
			if _, serr := os.Stat(pp); serr == nil {
				if parent, perr := openVHDX(pp, depth+1); perr == nil {
					d.parent, d.parentClose = parent, parent.Close
				}
			}
		}
		// no reachable parent: absent blocks read as zeros
	}
	return d, nil
}

func (d *vhdxDisk) Close() error {
	err := d.f.Close()
	if d.parentClose != nil {
		if perr := d.parentClose(); err == nil {
			err = perr
		}
	}
	return err
}

func (d *vhdxDisk) fromParentOrZero(p []byte, off int64) {
	if d.parent != nil {
		n, err := d.parent.ReadAt(p, off)
		if err == nil || n == len(p) {
			return
		}
		for i := n; i < len(p); i++ {
			p[i] = 0
		}
		return
	}
	for i := range p {
		p[i] = 0
	}
}

func (d *vhdxDisk) fileRead(p []byte, off int64) {
	n, err := d.f.ReadAt(p, off)
	if err != nil && n < len(p) {
		for i := n; i < len(p); i++ {
			p[i] = 0 // truncated: zeros, not a failure
		}
	}
}

// readBlock fills p (within one payload block) from disk offset off.
func (d *vhdxDisk) readBlock(p []byte, off int64) error {
	blockIdx := off / d.blockSize
	within := off % d.blockSize
	batIdx := blockIdx + blockIdx/d.chunkRatio
	var entry uint64
	if batIdx < int64(len(d.bat)) {
		entry = d.bat[batIdx]
	}
	state := entry & 7
	fileOff := int64(entry & vhdxOffsetMask)
	switch state {
	case vhdxBlockFullyPresent:
		d.fileRead(p, fileOff+within)
	case vhdxBlockPartiallyPresent:
		chunk := blockIdx / d.chunkRatio
		sbIdx := chunk*(d.chunkRatio+1) + d.chunkRatio
		var sb uint64
		if sbIdx < int64(len(d.bat)) {
			sb = d.bat[sbIdx]
		}
		sbOff := int64(sb & vhdxOffsetMask)
		if sb&7 != vhdxBlockFullyPresent || sbOff == 0 {
			d.fromParentOrZero(p, off)
			return nil
		}
		// the bitmap covers the whole chunk: sector index counted from the
		// chunk's first block
		sectorBase := (blockIdx % d.chunkRatio) * (d.blockSize / d.sectorSize)
		filled := 0
		pos := within
		for filled < len(p) {
			sector := sectorBase + pos/d.sectorSize
			var bm [1]byte
			if _, err := d.f.ReadAt(bm[:], sbOff+sector/8); err != nil {
				return fmt.Errorf("vhdx: read sector bitmap: %w", err)
			}
			inChild := bm[0]>>(uint(sector%8))&1 == 1
			n := int(d.sectorSize - pos%d.sectorSize)
			if n > len(p)-filled {
				n = len(p) - filled
			}
			if inChild {
				d.fileRead(p[filled:filled+n], fileOff+pos)
			} else {
				d.fromParentOrZero(p[filled:filled+n], blockIdx*d.blockSize+pos)
			}
			filled += n
			pos += int64(n)
		}
	case vhdxBlockNotPresent:
		d.fromParentOrZero(p, off)
	default: // undefined, zero, unmapped
		for i := range p {
			p[i] = 0
		}
	}
	return nil
}

func (d *vhdxDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vhdx: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= d.size {
			return total, io.EOF
		}
		n := int64(len(p))
		within := off % d.blockSize
		if within+n > d.blockSize {
			n = d.blockSize - within
		}
		if off+n > d.size {
			n = d.size - off
		}
		if err := d.readBlock(p[:n], off); err != nil {
			return total, err
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}

// vhdxParentBasename is the fallback for an absolute Windows path.
func vhdxParentBasename(ref string) string {
	return filepath.Base(filepath.FromSlash(strings.ReplaceAll(ref, "\\", "/")))
}
