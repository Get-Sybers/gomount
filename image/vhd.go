// VHD (Virtual Hard Disk v1, "conectix") containers, read-only: fixed,
// dynamic and differencing disks, the differencing chain resolved through
// the dynamic header's parent locators. All multi-byte fields are
// big-endian. Ported from VMkatz's vhd.rs (github.com/nikaiw/VMkatz, MIT,
// Nicolas Devillers).
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

const (
	vhdBATUnused         = 0xffffffff
	vhdTypeFixed         = 2
	vhdTypeDynamic       = 3
	vhdTypeDifferencing  = 4
	vhdFooterSize        = 512
	vhdDynamicHeaderSize = 1024
)

var (
	sigConectix = []byte("conectix")
	sigCxsparse = []byte("cxsparse")
)

type vhdDisk struct {
	f             *os.File
	size          int64
	diskType      uint32
	bat           []uint32
	blockSize     int64
	bitmapSectors int64
	parent        io.ReaderAt
	parentClose   func() error
}

// looksLikeVHD reports whether the file ends in a VHD footer.
func looksLikeVHD(f io.ReaderAt, size int64) bool {
	if size < vhdFooterSize {
		return false
	}
	var cookie [8]byte
	if _, err := f.ReadAt(cookie[:], size-vhdFooterSize); err != nil {
		return false
	}
	return bytes.Equal(cookie[:], sigConectix)
}

type vhdParentLocator struct {
	code   uint32
	length uint32
	offset uint64
}

func openVHD(path string, depth int) (*vhdDisk, error) {
	if depth > 16 {
		return nil, errors.New("vhd: differencing chain deeper than 16")
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
	if st.Size() < vhdFooterSize {
		f.Close()
		return nil, errors.New("vhd: file too small for a footer")
	}
	var ft [vhdFooterSize]byte
	if _, err := f.ReadAt(ft[:], st.Size()-vhdFooterSize); err != nil {
		f.Close()
		return nil, fmt.Errorf("vhd: read footer: %w", err)
	}
	if !bytes.Equal(ft[0:8], sigConectix) {
		f.Close()
		return nil, errors.New("vhd: no conectix footer")
	}
	dataOffset := binary.BigEndian.Uint64(ft[16:24])
	currentSize := binary.BigEndian.Uint64(ft[48:56])
	diskType := binary.BigEndian.Uint32(ft[60:64])
	if currentSize == 0 || currentSize > 1<<50 {
		f.Close()
		return nil, errors.New("vhd: implausible disk size")
	}
	d := &vhdDisk{f: f, size: int64(currentSize), diskType: diskType}
	if diskType == vhdTypeFixed {
		return d, nil
	}
	if diskType != vhdTypeDynamic && diskType != vhdTypeDifferencing {
		f.Close()
		return nil, fmt.Errorf("vhd: unsupported disk type %d", diskType)
	}

	var dh [vhdDynamicHeaderSize]byte
	if _, err := f.ReadAt(dh[:], int64(dataOffset)); err != nil {
		f.Close()
		return nil, fmt.Errorf("vhd: read dynamic header: %w", err)
	}
	if !bytes.Equal(dh[0:8], sigCxsparse) {
		f.Close()
		return nil, errors.New("vhd: bad dynamic header cookie")
	}
	tableOffset := binary.BigEndian.Uint64(dh[16:24])
	maxEntries := binary.BigEndian.Uint32(dh[28:32])
	blockSize := binary.BigEndian.Uint32(dh[32:36])
	var parentID [16]byte
	copy(parentID[:], dh[40:56])
	if blockSize == 0 || blockSize%512 != 0 || maxEntries > 1<<24 {
		f.Close()
		return nil, errors.New("vhd: invalid dynamic header")
	}
	d.blockSize = int64(blockSize)
	sectorsPerBlock := int64(blockSize / 512)
	bitmapBytes := (sectorsPerBlock + 7) / 8
	d.bitmapSectors = (bitmapBytes + 511) / 512

	raw := make([]byte, int(maxEntries)*4)
	if _, err := f.ReadAt(raw, int64(tableOffset)); err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return nil, fmt.Errorf("vhd: read BAT: %w", err)
	}
	d.bat = make([]uint32, maxEntries)
	for i := range d.bat {
		d.bat[i] = binary.BigEndian.Uint32(raw[i*4:])
	}

	if diskType == vhdTypeDifferencing && parentID != [16]byte{} {
		// eight parent locators of 24 bytes from offset 576
		for i := 0; i < 8; i++ {
			e := dh[576+i*24 : 576+(i+1)*24]
			loc := vhdParentLocator{
				code:   binary.BigEndian.Uint32(e[0:4]),
				length: binary.BigEndian.Uint32(e[8:12]),
				offset: binary.BigEndian.Uint64(e[16:24]),
			}
			if loc.code == 0 || loc.length == 0 || loc.length > 1<<16 {
				continue
			}
			ref := readVHDParentRef(f, loc)
			if ref == "" {
				continue
			}
			pp := resolveVHDParent(path, ref)
			if _, serr := os.Stat(pp); serr != nil {
				continue
			}
			parent, perr := openVHD(pp, depth+1)
			if perr != nil {
				continue
			}
			d.parent, d.parentClose = parent, parent.Close
			break
		}
		// no reachable parent: unallocated sectors read as zeros (the
		// child's own sectors are still exact)
	}
	return d, nil
}

func readVHDParentRef(f io.ReaderAt, loc vhdParentLocator) string {
	data := make([]byte, loc.length)
	if _, err := f.ReadAt(data, int64(loc.offset)); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	switch loc.code {
	case 0x5769326b, 0x57693272, 0x57326b75, 0x57327275: // Wi2k Wi2r W2ku W2ru: UTF-16LE
		u := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			c := binary.LittleEndian.Uint16(data[i:])
			if c == 0 {
				break
			}
			u = append(u, c)
		}
		return string(utf16.Decode(u))
	default: // MacX and others: UTF-8
		return strings.TrimRight(string(data), "\x00")
	}
}

// resolveVHDParent resolves a parent reference against the child's directory;
// an absolute Windows path that does not exist here is retried by basename.
func resolveVHDParent(child, ref string) string {
	norm := strings.ReplaceAll(ref, "\\", "/")
	norm = strings.TrimPrefix(norm, "file://")
	dir := filepath.Dir(child)
	if filepath.IsAbs(norm) || (len(norm) > 2 && norm[1] == ':') {
		if _, err := os.Stat(norm); err == nil {
			return norm
		}
		return filepath.Join(dir, filepath.Base(norm))
	}
	if strings.HasPrefix(norm, "./") || strings.HasPrefix(norm, ".\\") {
		norm = norm[2:]
	}
	return filepath.Join(dir, filepath.FromSlash(norm))
}

func (d *vhdDisk) Close() error {
	err := d.f.Close()
	if d.parentClose != nil {
		if perr := d.parentClose(); err == nil {
			err = perr
		}
	}
	return err
}

func (d *vhdDisk) fromParentOrZero(p []byte, off int64) {
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

// readBlock fills p (within one block) from disk offset off.
func (d *vhdDisk) readBlock(p []byte, off int64) error {
	if d.diskType == vhdTypeFixed {
		n, err := d.f.ReadAt(p, off)
		if err != nil && n < len(p) {
			for i := n; i < len(p); i++ {
				p[i] = 0
			}
		}
		return nil
	}
	blockIdx := off / d.blockSize
	within := off % d.blockSize
	if blockIdx >= int64(len(d.bat)) || d.bat[blockIdx] == vhdBATUnused {
		d.fromParentOrZero(p, off)
		return nil
	}
	blockStart := int64(d.bat[blockIdx]) * 512
	dataStart := blockStart + d.bitmapSectors*512
	if d.diskType == vhdTypeDynamic {
		n, err := d.f.ReadAt(p, dataStart+within)
		if err != nil && n < len(p) {
			for i := n; i < len(p); i++ {
				p[i] = 0
			}
		}
		return nil
	}
	// differencing: the sector bitmap says which sectors the child holds
	bitmap := make([]byte, d.bitmapSectors*512)
	if _, err := d.f.ReadAt(bitmap, blockStart); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("vhd: read sector bitmap: %w", err)
	}
	filled := 0
	pos := within
	for filled < len(p) {
		sector := pos / 512
		inChild := bitmap[sector/8]>>(7-uint(sector%8))&1 == 1
		chunk := int(512 - pos%512)
		if chunk > len(p)-filled {
			chunk = len(p) - filled
		}
		if inChild {
			n, err := d.f.ReadAt(p[filled:filled+chunk], dataStart+pos)
			if err != nil && n < chunk {
				for i := filled + n; i < filled+chunk; i++ {
					p[i] = 0
				}
			}
		} else {
			d.fromParentOrZero(p[filled:filled+chunk], blockIdx*d.blockSize+pos)
		}
		filled += chunk
		pos += int64(chunk)
	}
	return nil
}

func (d *vhdDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vhd: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= d.size {
			return total, io.EOF
		}
		n := int64(len(p))
		if d.diskType != vhdTypeFixed {
			within := off % d.blockSize
			if within+n > d.blockSize {
				n = d.blockSize - within
			}
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
