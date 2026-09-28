// VMDK (VMware virtual disk) containers, read-only. A VMDK is either a
// text DESCRIPTOR naming one or more extents, or a SPARSE extent file that
// carries its own header (magic "KDMV") with the descriptor embedded — the
// monolithicSparse layout a VM export ships as one .vmdk. This file decodes
// both and presents the virtual disk as one io.ReaderAt of exactly
// `capacity` bytes, the same seam the raw and EWF containers use:
//
//   - a sparse extent maps the disk through a grain directory (GD) and grain
//     tables (GT) to fixed-size grains in the file; an unallocated grain
//     reads as zeros (or as the parent disk's bytes when the descriptor
//     names a parentFileNameHint — a snapshot delta). streamOptimized
//     extents (flag bit 16) hold each grain deflate-compressed behind a
//     grain marker and keep the GD in a footer copy of the header;
//   - a FLAT/VMFS extent is a raw file (with a byte offset);
//   - a ZERO extent has no file and reads as zeros.
//
// Extents concatenate in descriptor order; every file opens O_RDONLY.
//
// The descriptor grammar, the flat extent type list, the "-sNNN" sibling
// discovery for a split disk that lost its descriptor, and the policy that a
// truncated extent reads as zeros follow VMkatz's vmdk.rs
// (github.com/nikaiw/VMkatz, MIT, Nicolas Devillers); the streamOptimized
// (compressed grain + footer) path is gomount's own.
package image

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	vmdkMagic          = 0x564d444b // "KDMV" little-endian
	vmdkSector         = 512
	vmdkHeaderSize     = 512
	vmdkFlagCompressed = 1 << 16
	vmdkFlagMarkers    = 1 << 17
	// the footer of a streamOptimized extent: a header copy 1024 bytes
	// before EOF (followed by the end-of-stream marker)
	vmdkFooterFromEnd = 1024
)

var sigKDMV = []byte("KDMV")

// vmdkSparseHeader is the on-disk SparseExtentHeader (little-endian).
type vmdkSparseHeader struct {
	Version           uint32
	Flags             uint32
	Capacity          uint64 // sectors
	GrainSize         uint64 // sectors
	DescriptorOffset  uint64 // sectors
	DescriptorSize    uint64 // sectors
	NumGTEsPerGT      uint32
	RGDOffset         uint64 // sectors
	GDOffset          uint64 // sectors
	OverHead          uint64 // sectors
	CompressAlgorithm uint16
}

func parseVMDKSparseHeader(b []byte) (vmdkSparseHeader, error) {
	var h vmdkSparseHeader
	if len(b) < vmdkHeaderSize {
		return h, errors.New("vmdk: short sparse header")
	}
	if binary.LittleEndian.Uint32(b[0:4]) != vmdkMagic {
		return h, errors.New("vmdk: not a sparse extent (no KDMV magic)")
	}
	h.Version = binary.LittleEndian.Uint32(b[4:8])
	h.Flags = binary.LittleEndian.Uint32(b[8:12])
	h.Capacity = binary.LittleEndian.Uint64(b[12:20])
	h.GrainSize = binary.LittleEndian.Uint64(b[20:28])
	h.DescriptorOffset = binary.LittleEndian.Uint64(b[28:36])
	h.DescriptorSize = binary.LittleEndian.Uint64(b[36:44])
	h.NumGTEsPerGT = binary.LittleEndian.Uint32(b[44:48])
	h.RGDOffset = binary.LittleEndian.Uint64(b[48:56])
	h.GDOffset = binary.LittleEndian.Uint64(b[56:64])
	h.OverHead = binary.LittleEndian.Uint64(b[64:72])
	h.CompressAlgorithm = binary.LittleEndian.Uint16(b[77:79])
	switch {
	case h.Version < 1 || h.Version > 3:
		return h, fmt.Errorf("vmdk: unsupported sparse header version %d", h.Version)
	case h.GrainSize == 0 || h.GrainSize > 1<<20:
		return h, fmt.Errorf("vmdk: implausible grain size %d sectors", h.GrainSize)
	case h.NumGTEsPerGT == 0 || h.NumGTEsPerGT > 1<<20:
		return h, fmt.Errorf("vmdk: implausible grain table size %d", h.NumGTEsPerGT)
	case h.Capacity == 0 || h.Capacity > 1<<40:
		return h, fmt.Errorf("vmdk: implausible capacity %d sectors", h.Capacity)
	case h.Flags&vmdkFlagCompressed != 0 && h.CompressAlgorithm != 1:
		return h, fmt.Errorf("vmdk: unsupported compression algorithm %d", h.CompressAlgorithm)
	}
	return h, nil
}

// looksLikeVMDK reports whether the file is a sparse extent (KDMV) or a
// text descriptor ("# Disk DescriptorFile"); a bare .vmdk extension with
// neither is not claimed, so a mislabelled raw image still opens as raw.
func looksLikeVMDK(f io.ReaderAt) (sparse, descriptor bool) {
	var hdr [64]byte
	n, _ := f.ReadAt(hdr[:], 0)
	if n >= 4 && bytes.Equal(hdr[:4], sigKDMV) {
		return true, false
	}
	head := strings.TrimLeft(string(hdr[:n]), "\xef\xbb\xbf \t\r\n")
	if strings.HasPrefix(head, "# Disk DescriptorFile") {
		return false, true
	}
	return false, false
}

// vmdkExtentDesc is one "RW <sectors> <TYPE> ["<file>" [<offset>]]" line.
type vmdkExtentDesc struct {
	Sectors uint64
	Type    string // SPARSE | FLAT | VMFS | ZERO | VMFSSPARSE …
	File    string
	Offset  uint64 // FLAT: sector offset within the file
}

// vmdkDescriptor is the parsed text descriptor.
type vmdkDescriptor struct {
	CreateType string
	Parent     string // parentFileNameHint, "" when none
	Extents    []vmdkExtentDesc
}

func parseVMDKDescriptor(text string) (vmdkDescriptor, error) {
	var d vmdkDescriptor
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "RW ") && !strings.HasPrefix(line, "RDONLY ") && !strings.HasPrefix(line, "NOACCESS ") {
			k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
			switch k {
			case "createType":
				d.CreateType = v
			case "parentFileNameHint":
				d.Parent = v
			}
			continue
		}
		// <access> <sectors> <type> ["<file>" [<offset>]] — the file name may
		// hold spaces, so only the three fixed tokens split on space and the
		// name is taken from its quotes
		head := strings.SplitN(line, " ", 4)
		if len(head) < 3 {
			continue
		}
		switch head[0] {
		case "RW", "RDONLY", "NOACCESS":
		default:
			continue
		}
		sectors, err := strconv.ParseUint(head[1], 10, 64)
		if err != nil {
			return d, fmt.Errorf("vmdk: bad extent line %q", line)
		}
		e := vmdkExtentDesc{Sectors: sectors, Type: strings.ToUpper(head[2])}
		if len(head) == 4 {
			tail := strings.TrimSpace(head[3])
			after := ""
			if i := strings.IndexByte(tail, '"'); i >= 0 {
				rest := tail[i+1:]
				if j := strings.IndexByte(rest, '"'); j >= 0 {
					e.File, after = rest[:j], rest[j+1:]
				} else {
					e.File = strings.Trim(tail, `"`)
				}
			} else {
				fs := strings.Fields(tail)
				if len(fs) > 0 {
					e.File = fs[0]
					after = strings.Join(fs[1:], " ")
				}
			}
			if fs := strings.Fields(after); len(fs) > 0 {
				if off, err := strconv.ParseUint(fs[0], 10, 64); err == nil {
					e.Offset = off
				}
			}
		}
		d.Extents = append(d.Extents, e)
	}
	if len(d.Extents) == 0 {
		return d, errors.New("vmdk: descriptor names no extent")
	}
	return d, nil
}

// vmdkExtent is one opened extent: a ReaderAt over its whole logical range.
type vmdkExtent struct {
	size  int64 // bytes
	ra    io.ReaderAt
	close func() error
}

// vmdkDisk concatenates extents into the virtual disk.
type vmdkDisk struct {
	extents []vmdkExtent
	size    int64
}

func (d *vmdkDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vmdk: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= d.size {
			return total, io.EOF
		}
		var base int64
		var ext *vmdkExtent
		for i := range d.extents {
			if off < base+d.extents[i].size {
				ext = &d.extents[i]
				break
			}
			base += d.extents[i].size
		}
		if ext == nil {
			return total, io.EOF
		}
		within := off - base
		n := int64(len(p))
		if within+n > ext.size {
			n = ext.size - within
		}
		got, err := ext.ra.ReadAt(p[:n], within)
		total += got
		if err != nil && !(errors.Is(err, io.EOF) && int64(got) == n) {
			return total, err
		}
		p = p[got:]
		off += int64(got)
		if int64(got) < n {
			return total, io.ErrUnexpectedEOF
		}
	}
	return total, nil
}

func (d *vmdkDisk) Close() error {
	var first error
	for _, e := range d.extents {
		if e.close != nil {
			if err := e.close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// zeroReader is a ZERO extent (or the backing of an unallocated grain).
type zeroReader struct{ size int64 }

func (z zeroReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= z.size {
		return 0, io.EOF
	}
	n := int64(len(p))
	if off+n > z.size {
		n = z.size - off
	}
	for i := range p[:n] {
		p[i] = 0
	}
	if n < int64(len(p)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

// offsetReader is a FLAT extent: a raw file from a byte offset.
type offsetReader struct {
	ra   io.ReaderAt
	base int64
}

func (o offsetReader) ReadAt(p []byte, off int64) (int, error) { return o.ra.ReadAt(p, o.base+off) }

// sparseExtent decodes one KDMV extent through its grain directory.
type sparseExtent struct {
	f          io.ReaderAt
	hdr        vmdkSparseHeader
	size       int64 // capacity in bytes
	grainBytes int64
	gtBytes    int64 // one grain table's span of the disk
	gd         []uint32
	compressed bool
	parent     io.ReaderAt // backing for unallocated grains (snapshot delta) or nil

	mu      sync.Mutex
	gts     map[uint32][]uint32 // grain table cache by GDE
	lastIdx int64               // decompressed-grain cache (one grain)
	last    []byte
}

func openSparseExtent(f io.ReaderAt, fileSize int64, parent io.ReaderAt) (*sparseExtent, error) {
	var hb [vmdkHeaderSize]byte
	if _, err := f.ReadAt(hb[:], 0); err != nil {
		return nil, fmt.Errorf("vmdk: read sparse header: %w", err)
	}
	hdr, err := parseVMDKSparseHeader(hb[:])
	if err != nil {
		return nil, err
	}
	// streamOptimized: the header at 0 has no grain directory yet (all ones);
	// the footer 1024 bytes before EOF is the completed copy.
	if hdr.GDOffset == ^uint64(0) {
		if fileSize < vmdkFooterFromEnd+vmdkHeaderSize {
			return nil, errors.New("vmdk: streamOptimized extent too short for a footer")
		}
		if _, err := f.ReadAt(hb[:], fileSize-vmdkFooterFromEnd); err != nil {
			return nil, fmt.Errorf("vmdk: read footer: %w", err)
		}
		if hdr, err = parseVMDKSparseHeader(hb[:]); err != nil {
			return nil, fmt.Errorf("vmdk: footer: %w", err)
		}
	}
	gdOff := hdr.GDOffset
	if gdOff == 0 {
		gdOff = hdr.RGDOffset
	}
	if gdOff == 0 || gdOff == ^uint64(0) {
		return nil, errors.New("vmdk: no grain directory")
	}
	e := &sparseExtent{
		f:          f,
		hdr:        hdr,
		size:       int64(hdr.Capacity) * vmdkSector,
		grainBytes: int64(hdr.GrainSize) * vmdkSector,
		compressed: hdr.Flags&vmdkFlagCompressed != 0,
		parent:     parent,
		gts:        map[uint32][]uint32{},
		lastIdx:    -1,
	}
	e.gtBytes = e.grainBytes * int64(hdr.NumGTEsPerGT)
	numGDE := (e.size + e.gtBytes - 1) / e.gtBytes
	if numGDE > 1<<24 {
		return nil, errors.New("vmdk: implausible grain directory size")
	}
	raw := make([]byte, numGDE*4)
	if _, err := f.ReadAt(raw, int64(gdOff)*vmdkSector); err != nil {
		return nil, fmt.Errorf("vmdk: read grain directory: %w", err)
	}
	e.gd = make([]uint32, numGDE)
	for i := range e.gd {
		e.gd[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	return e, nil
}

// grainTable loads (and caches) the grain table a GDE points at.
func (e *sparseExtent) grainTable(gde uint32) ([]uint32, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if gt, ok := e.gts[gde]; ok {
		return gt, nil
	}
	raw := make([]byte, int(e.hdr.NumGTEsPerGT)*4)
	if _, err := e.f.ReadAt(raw, int64(gde)*vmdkSector); err != nil {
		return nil, fmt.Errorf("vmdk: read grain table at sector %d: %w", gde, err)
	}
	gt := make([]uint32, e.hdr.NumGTEsPerGT)
	for i := range gt {
		gt[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	e.gts[gde] = gt
	return gt, nil
}

// grainOffset resolves a disk offset to the file sector of its grain, or 0
// when the grain is unallocated (1 = explicitly zeroed in v2+ extents).
func (e *sparseExtent) grainOffset(off int64) (uint32, error) {
	gdi := off / e.gtBytes
	if gdi >= int64(len(e.gd)) {
		return 0, io.EOF
	}
	gde := e.gd[gdi]
	if gde == 0 {
		return 0, nil // the whole table is unallocated
	}
	gt, err := e.grainTable(gde)
	if err != nil {
		return 0, err
	}
	gti := (off % e.gtBytes) / e.grainBytes
	gte := gt[gti]
	if gte <= 1 {
		return 0, nil
	}
	return gte, nil
}

// readGrain returns the grain holding off, decompressing a streamOptimized
// grain (kept in a one-grain cache: sequential reads hit it repeatedly).
func (e *sparseExtent) readGrain(idx int64, gte uint32) ([]byte, error) {
	e.mu.Lock()
	if e.lastIdx == idx {
		b := e.last
		e.mu.Unlock()
		return b, nil
	}
	e.mu.Unlock()
	// grain marker: uint64 lba, uint32 compressed size, then the data
	var mk [12]byte
	base := int64(gte) * vmdkSector
	if _, err := e.f.ReadAt(mk[:], base); err != nil {
		return nil, fmt.Errorf("vmdk: read grain marker: %w", err)
	}
	csize := int64(binary.LittleEndian.Uint32(mk[8:12]))
	if csize <= 0 || csize > e.grainBytes*2+1024 {
		return nil, fmt.Errorf("vmdk: implausible compressed grain size %d", csize)
	}
	comp := make([]byte, csize)
	n, rerr := e.f.ReadAt(comp, base+12)
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		return nil, fmt.Errorf("vmdk: read compressed grain: %w", rerr)
	}
	// only what the file holds goes to the inflater; a grain cut short by a
	// truncated extent (or whose stream does not decode) reads as zeros, the
	// same policy as an uncompressed grain past the end of its file
	out, ierr := inflateGrain(comp[:n], e.grainBytes)
	if ierr != nil {
		if int64(n) < csize {
			out = make([]byte, e.grainBytes)
		} else {
			return nil, ierr
		}
	}
	e.mu.Lock()
	e.lastIdx, e.last = idx, out
	e.mu.Unlock()
	return out, nil
}

// inflateGrain decodes a grain that is zlib-wrapped (what VMware and qemu
// write) or, failing that, raw deflate; the result is padded to the grain.
func inflateGrain(comp []byte, grainBytes int64) ([]byte, error) {
	out := make([]byte, grainBytes)
	// a zlib header (CMF/FLG check) means a zlib stream: decode it as one and
	// never retry its bytes as raw deflate — that retry would hand corruption
	// back as data
	if len(comp) >= 2 && comp[0]&0x0f == 8 && (uint16(comp[0])<<8|uint16(comp[1]))%31 == 0 {
		zr, err := zlib.NewReader(bytes.NewReader(comp))
		if err != nil {
			return nil, fmt.Errorf("vmdk: inflate grain: %w", err)
		}
		n, rerr := io.ReadFull(zr, out)
		zr.Close()
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			return nil, fmt.Errorf("vmdk: inflate grain: %w", rerr)
		}
		for i := n; i < len(out); i++ {
			out[i] = 0
		}
		return out, nil
	}
	fr := flate.NewReader(bytes.NewReader(comp))
	n, rerr := io.ReadFull(fr, out)
	fr.Close()
	if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
		return nil, fmt.Errorf("vmdk: inflate grain: %w", rerr)
	}
	for i := n; i < len(out); i++ {
		out[i] = 0
	}
	return out, nil
}

func (e *sparseExtent) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vmdk: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= e.size {
			return total, io.EOF
		}
		idx := off / e.grainBytes
		within := off % e.grainBytes
		n := int64(len(p))
		if within+n > e.grainBytes {
			n = e.grainBytes - within
		}
		if off+n > e.size {
			n = e.size - off
		}
		gte, err := e.grainOffset(off)
		if err != nil {
			return total, err
		}
		switch {
		case gte == 0 && e.parent != nil:
			got, perr := e.parent.ReadAt(p[:n], off)
			if perr != nil && !(errors.Is(perr, io.EOF) && int64(got) == n) {
				// a parent shorter than the child reads as zeros past its end
				for i := got; i < int(n); i++ {
					p[i] = 0
				}
			}
		case gte == 0:
			for i := range p[:n] {
				p[i] = 0
			}
		case e.compressed:
			g, gerr := e.readGrain(idx, gte)
			if gerr != nil {
				return total, gerr
			}
			copy(p[:n], g[within:within+n])
		default:
			got, rerr := e.f.ReadAt(p[:n], int64(gte)*vmdkSector+within)
			if rerr != nil && !(errors.Is(rerr, io.EOF) && int64(got) == n) {
				// a truncated extent reads its missing tail as zeros rather
				// than failing the whole image (evidence is what it is)
				for i := got; i < int(n); i++ {
					p[i] = 0
				}
			}
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}

// openVMDK opens the VMDK at path (a sparse extent or a descriptor) as one
// virtual disk. depth bounds the parent (snapshot) chain.
func openVMDK(path string, depth int) (*vmdkDisk, error) {
	if depth > 16 {
		return nil, errors.New("vmdk: snapshot chain deeper than 16")
	}
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	sparse, descriptor := looksLikeVMDK(f)
	dir := filepath.Dir(path)

	var desc vmdkDescriptor
	switch {
	case sparse:
		var hb [vmdkHeaderSize]byte
		if _, err := f.ReadAt(hb[:], 0); err != nil {
			f.Close()
			return nil, err
		}
		hdr, err := parseVMDKSparseHeader(hb[:])
		if err != nil {
			f.Close()
			return nil, err
		}
		if hdr.DescriptorOffset > 0 && hdr.DescriptorSize > 0 && hdr.DescriptorSize < 1<<16 {
			raw := make([]byte, hdr.DescriptorSize*vmdkSector)
			if _, err := f.ReadAt(raw, int64(hdr.DescriptorOffset)*vmdkSector); err == nil {
				if i := bytes.IndexByte(raw, 0); i >= 0 {
					raw = raw[:i]
				}
				desc, _ = parseVMDKDescriptor(string(raw)) // best-effort: the header alone suffices
			}
		}
		// A split extent (name-sNNN.vmdk) opened without its descriptor: its
		// numbered siblings in the directory are the disk, in number order,
		// each covering its own capacity; a missing number reads as zeros.
		if len(desc.Extents) == 0 {
			if sibs := vmdkSplitSiblings(path); len(sibs) > 1 {
				f.Close()
				return openVMDKSplit(sibs, depth)
			}
		}
		// A monolithic sparse file is its own single extent whatever the
		// embedded descriptor says about its name.
		if len(desc.Extents) <= 1 || desc.Parent == "" && sameExtentFile(desc, filepath.Base(path)) {
			var parent io.ReaderAt
			var parentDisk *vmdkDisk
			if desc.Parent != "" {
				if parentDisk, err = openVMDK(resolveVMDKPath(dir, desc.Parent), depth+1); err != nil {
					f.Close()
					return nil, fmt.Errorf("vmdk: parent %s: %w", desc.Parent, err)
				}
				parent = parentDisk
			}
			ext, err := openSparseExtent(f, st.Size(), parent)
			if err != nil {
				f.Close()
				if parentDisk != nil {
					parentDisk.Close()
				}
				return nil, err
			}
			closer := func() error {
				err := f.Close()
				if parentDisk != nil {
					if perr := parentDisk.Close(); err == nil {
						err = perr
					}
				}
				return err
			}
			return &vmdkDisk{extents: []vmdkExtent{{size: ext.size, ra: ext, close: closer}}, size: ext.size}, nil
		}
		f.Close()
	case descriptor:
		raw := make([]byte, st.Size())
		if st.Size() > 1<<20 {
			f.Close()
			return nil, errors.New("vmdk: descriptor implausibly large")
		}
		if _, err := f.ReadAt(raw, 0); err != nil && !errors.Is(err, io.EOF) {
			f.Close()
			return nil, err
		}
		f.Close()
		if desc, err = parseVMDKDescriptor(string(raw)); err != nil {
			return nil, err
		}
	default:
		f.Close()
		return nil, errors.New("vmdk: neither a sparse extent nor a descriptor")
	}

	// Multi-extent: open every extent in order against the descriptor's dir.
	var parent io.ReaderAt
	var parentDisk *vmdkDisk
	if desc.Parent != "" {
		var err error
		if parentDisk, err = openVMDK(resolveVMDKPath(dir, desc.Parent), depth+1); err != nil {
			return nil, fmt.Errorf("vmdk: parent %s: %w", desc.Parent, err)
		}
		parent = parentDisk
	}
	disk := &vmdkDisk{}
	if parentDisk != nil {
		disk.extents = append(disk.extents, vmdkExtent{size: 0, ra: zeroReader{}, close: parentDisk.Close})
	}
	var base int64
	for _, ed := range desc.Extents {
		size := int64(ed.Sectors) * vmdkSector
		switch ed.Type {
		case "ZERO":
			disk.extents = append(disk.extents, vmdkExtent{size: size, ra: zeroReader{size: size}})
		case "FLAT", "VMFS", "VMFSRAW", "VMFSRDM", "VMFSRDMP":
			ef, err := os.Open(resolveVMDKPath(dir, ed.File))
			if err != nil {
				disk.Close()
				return nil, fmt.Errorf("vmdk: extent %s: %w", ed.File, err)
			}
			disk.extents = append(disk.extents, vmdkExtent{size: size,
				ra: offsetReader{ra: ef, base: int64(ed.Offset) * vmdkSector}, close: ef.Close})
		case "SPARSE", "VMFSSPARSE":
			ef, err := os.Open(resolveVMDKPath(dir, ed.File))
			if err != nil {
				disk.Close()
				return nil, fmt.Errorf("vmdk: extent %s: %w", ed.File, err)
			}
			est, err := ef.Stat()
			if err != nil {
				ef.Close()
				disk.Close()
				return nil, err
			}
			var pr io.ReaderAt
			if parent != nil {
				pr = offsetReader{ra: parent, base: base}
			}
			ext, err := openSparseExtent(ef, est.Size(), pr)
			if err != nil {
				ef.Close()
				disk.Close()
				return nil, fmt.Errorf("vmdk: extent %s: %w", ed.File, err)
			}
			if ext.size < size {
				size = ext.size
			}
			disk.extents = append(disk.extents, vmdkExtent{size: size, ra: ext, close: ef.Close})
		default:
			disk.Close()
			return nil, fmt.Errorf("vmdk: unsupported extent type %s", ed.Type)
		}
		base += size
	}
	disk.size = base
	if disk.size <= 0 {
		disk.Close()
		return nil, errors.New("vmdk: descriptor yields an empty disk")
	}
	return disk, nil
}

// vmdkSplitSiblings lists the "-sNNN.vmdk" sparse extents beside path that
// share its stem, keyed by extent number (1-based), or nil when path is not
// such an extent.
func vmdkSplitSiblings(path string) map[int]string {
	stem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	i := strings.LastIndex(stem, "-s")
	if i < 0 {
		return nil
	}
	for _, c := range stem[i+2:] {
		if c < '0' || c > '9' {
			return nil
		}
	}
	if len(stem[i+2:]) == 0 {
		return nil
	}
	prefix := stem[:i]
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil
	}
	out := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".vmdk") {
			continue
		}
		st := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		j := strings.LastIndex(st, "-s")
		if j < 0 || !strings.EqualFold(st[:j], prefix) {
			continue
		}
		n, err := strconv.Atoi(st[j+2:])
		if err != nil || n <= 0 {
			continue
		}
		p := filepath.Join(filepath.Dir(path), e.Name())
		if ef, err := os.Open(p); err == nil {
			sparse, _ := looksLikeVMDK(ef)
			ef.Close()
			if sparse {
				out[n] = p
			}
		}
	}
	return out
}

// openVMDKSplit assembles numbered sparse extents into one disk; extent N
// covers [(N-1)*capacity, N*capacity) and a missing number reads as zeros.
func openVMDKSplit(sibs map[int]string, depth int) (*vmdkDisk, error) {
	maxN := 0
	for n := range sibs {
		if n > maxN {
			maxN = n
		}
	}
	disk := &vmdkDisk{}
	var per int64
	for n := 1; n <= maxN; n++ {
		p, ok := sibs[n]
		if !ok {
			if per == 0 {
				return nil, errors.New("vmdk: split extent set starts with a gap")
			}
			disk.extents = append(disk.extents, vmdkExtent{size: per, ra: zeroReader{size: per}})
			disk.size += per
			continue
		}
		ef, err := os.Open(p)
		if err != nil {
			disk.Close()
			return nil, err
		}
		st, err := ef.Stat()
		if err != nil {
			ef.Close()
			disk.Close()
			return nil, err
		}
		ext, err := openSparseExtent(ef, st.Size(), nil)
		if err != nil {
			ef.Close()
			disk.Close()
			return nil, fmt.Errorf("vmdk: extent %s: %w", filepath.Base(p), err)
		}
		if per == 0 {
			per = ext.size
		}
		disk.extents = append(disk.extents, vmdkExtent{size: ext.size, ra: ext, close: ef.Close})
		disk.size += ext.size
	}
	return disk, nil
}

// sameExtentFile reports whether every extent the descriptor names is the
// file itself (a monolithic sparse extent's self-reference).
func sameExtentFile(d vmdkDescriptor, self string) bool {
	for _, e := range d.Extents {
		if e.File != "" && !strings.EqualFold(filepath.Base(e.File), self) {
			return false
		}
	}
	return true
}

// resolveVMDKPath resolves an extent or parent name against the descriptor's
// directory; a name that does not exist there is retried case-insensitively
// (VM exports move between filesystems that fold case).
func resolveVMDKPath(dir, name string) string {
	p := name
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(name, "\\", "/")))
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	base := filepath.Base(p)
	if entries, err := os.ReadDir(filepath.Dir(p)); err == nil {
		for _, e := range entries {
			if strings.EqualFold(e.Name(), base) {
				return filepath.Join(filepath.Dir(p), e.Name())
			}
		}
	}
	return p
}
