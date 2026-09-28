// VDI (VirtualBox) containers, read-only: dynamic and differencing images
// through the block allocation table, a differencing image's parent found
// by UUID — through a .vbox next to or above the child, else by scanning
// sibling .vdi headers. Ported from VMkatz's vdi.rs (github.com/nikaiw/VMkatz,
// MIT, Nicolas Devillers).
package image

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	vdiMagic       = 0xbeda107f
	vdiBATUnalloc  = 0xffffffff
	vdiBATZero     = 0xfffffffe
	vdiImageDiff   = 4
	vdiHeaderReach = 0x1b8
)

type vdiHeader struct {
	imageType  uint32
	batOffset  int64
	dataOffset int64
	size       int64
	blockSize  int64
	blocks     uint32
	imageUUID  [16]byte
	parentUUID [16]byte
}

func parseVDIHeader(f io.ReaderAt) (vdiHeader, error) {
	var h vdiHeader
	var b [vdiHeaderReach]byte
	if _, err := f.ReadAt(b[:], 0); err != nil {
		return h, fmt.Errorf("vdi: read header: %w", err)
	}
	if binary.LittleEndian.Uint32(b[0x40:0x44]) != vdiMagic {
		return h, errors.New("vdi: bad magic")
	}
	h.imageType = binary.LittleEndian.Uint32(b[0x4c:0x50])
	h.batOffset = int64(binary.LittleEndian.Uint32(b[0x154:0x158]))
	h.dataOffset = int64(binary.LittleEndian.Uint32(b[0x158:0x15c]))
	h.size = int64(binary.LittleEndian.Uint64(b[0x170:0x178]))
	h.blockSize = int64(binary.LittleEndian.Uint32(b[0x178:0x17c]))
	h.blocks = binary.LittleEndian.Uint32(b[0x180:0x184])
	copy(h.imageUUID[:], b[0x188:0x198])
	copy(h.parentUUID[:], b[0x1a8:0x1b8])
	if h.blockSize == 0 || h.size <= 0 || h.blocks > 1<<24 {
		return h, errors.New("vdi: invalid header")
	}
	return h, nil
}

// looksLikeVDI reports the VDI magic at 0x40.
func looksLikeVDI(f io.ReaderAt) bool {
	var b [4]byte
	if _, err := f.ReadAt(b[:], 0x40); err != nil {
		return false
	}
	return binary.LittleEndian.Uint32(b[:]) == vdiMagic
}

type vdiDisk struct {
	f           *os.File
	hdr         vdiHeader
	bat         []uint32
	parent      io.ReaderAt
	parentClose func() error
}

func openVDI(path string, depth int) (*vdiDisk, error) {
	if depth > 16 {
		return nil, errors.New("vdi: differencing chain deeper than 16")
	}
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, err
	}
	hdr, err := parseVDIHeader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	raw := make([]byte, int(hdr.blocks)*4)
	if _, err := f.ReadAt(raw, hdr.batOffset); err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return nil, fmt.Errorf("vdi: read block table: %w", err)
	}
	d := &vdiDisk{f: f, hdr: hdr, bat: make([]uint32, hdr.blocks)}
	for i := range d.bat {
		d.bat[i] = binary.LittleEndian.Uint32(raw[i*4:])
	}
	if hdr.imageType == vdiImageDiff && hdr.parentUUID != [16]byte{} {
		if pp := findVDIParent(path, hdr.parentUUID); pp != "" {
			if parent, perr := openVDI(pp, depth+1); perr == nil {
				d.parent, d.parentClose = parent, parent.Close
			}
		}
		// no reachable parent: unallocated blocks read as zeros
	}
	return d, nil
}

// vdiUUIDString renders the 16 raw bytes the way a .vbox names them
// (Microsoft mixed-endian text form).
func vdiUUIDString(b [16]byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// findVDIParent looks for the parent image: a .vbox in the child's directory
// or up to three above naming the UUID, else a sibling .vdi (two levels
// deep) whose header carries it.
func findVDIParent(child string, parent [16]byte) string {
	want := vdiUUIDString(parent)
	dir := filepath.Dir(child)
	for i := 0; i < 4; i++ {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".vbox") {
					continue
				}
				if p := vboxDiskLocation(filepath.Join(dir, e.Name()), want, dir); p != "" {
					return p
				}
			}
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	dir = filepath.Dir(child)
	for i := 0; i < 3; i++ {
		if p := scanVDIForUUID(dir, parent, child, 0); p != "" {
			return p
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return ""
}

// vboxDiskLocation finds <HardDisk uuid="{want}" location="…"> in a .vbox.
func vboxDiskLocation(vbox, want, base string) string {
	b, err := os.ReadFile(vbox)
	if err != nil || len(b) > 1<<22 {
		return ""
	}
	s := string(b)
	i := strings.Index(strings.ToLower(s), strings.ToLower(`uuid="{`+want+`}`))
	if i < 0 {
		return ""
	}
	region := s[i:]
	if len(region) > 500 {
		region = region[:500]
	}
	j := strings.Index(region, `location="`)
	if j < 0 {
		return ""
	}
	rest := region[j+len(`location="`):]
	k := strings.IndexByte(rest, '"')
	if k < 0 {
		return ""
	}
	loc := filepath.FromSlash(strings.ReplaceAll(rest[:k], "\\", "/"))
	if !filepath.IsAbs(loc) {
		loc = filepath.Join(base, loc)
	}
	if _, err := os.Stat(loc); err != nil {
		return ""
	}
	return loc
}

func scanVDIForUUID(dir string, want [16]byte, exclude string, depth int) string {
	if depth > 2 {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if depth < 2 {
				if r := scanVDIForUUID(p, want, exclude, depth+1); r != "" {
					return r
				}
			}
			continue
		}
		if !strings.EqualFold(filepath.Ext(e.Name()), ".vdi") || sameFile(p, exclude) {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		h, herr := parseVDIHeader(f)
		f.Close()
		if herr == nil && h.imageUUID == want {
			return p
		}
	}
	return ""
}

func sameFile(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

func (d *vdiDisk) Close() error {
	err := d.f.Close()
	if d.parentClose != nil {
		if perr := d.parentClose(); err == nil {
			err = perr
		}
	}
	return err
}

func (d *vdiDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vdi: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= d.hdr.size {
			return total, io.EOF
		}
		blockIdx := off / d.hdr.blockSize
		within := off % d.hdr.blockSize
		n := int64(len(p))
		if within+n > d.hdr.blockSize {
			n = d.hdr.blockSize - within
		}
		if off+n > d.hdr.size {
			n = d.hdr.size - off
		}
		entry := uint32(vdiBATUnalloc)
		if blockIdx < int64(len(d.bat)) {
			entry = d.bat[blockIdx]
		}
		switch {
		case entry == vdiBATUnalloc && d.parent != nil:
			got, err := d.parent.ReadAt(p[:n], off)
			if err != nil && int64(got) < n {
				for i := got; i < int(n); i++ {
					p[i] = 0
				}
			}
		case entry == vdiBATUnalloc || entry == vdiBATZero:
			for i := range p[:n] {
				p[i] = 0
			}
		default:
			got, err := d.f.ReadAt(p[:n], d.hdr.dataOffset+int64(entry)*d.hdr.blockSize+within)
			if err != nil && int64(got) < n {
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
