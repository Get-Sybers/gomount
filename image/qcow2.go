// QCOW2 (QEMU copy-on-write v2/v3) containers, read-only: the two-level
// L1/L2 cluster map, a backing-file chain for unallocated clusters, and
// zlib-compressed clusters (the qemu-img -c layout). Encrypted images are
// refused. Ported from VMkatz's qcow2.rs (github.com/nikaiw/VMkatz, MIT,
// Nicolas Devillers); the compressed-cluster path is gomount's own.
package image

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	qcow2Magic          = 0x514649fb // "QFI\xfb" big-endian
	qcow2OffsetMask     = 0x00fffffffffffe00
	qcow2CompressedFlag = 1 << 62
	qcow2L2CacheTables  = 64
)

var sigQFI = []byte{0x51, 0x46, 0x49, 0xfb}

type qcow2Disk struct {
	f           *os.File
	clusterBits uint32
	clusterSize int64
	l2Bits      uint32
	l2Entries   int
	l1          []uint64
	size        int64
	parent      io.ReaderAt
	parentClose func() error

	mu      sync.Mutex
	l2Cache map[uint64][]uint64
}

// openQCOW2 opens the image and, recursively, its backing file chain.
func openQCOW2(path string, depth int) (*qcow2Disk, error) {
	if depth > 16 {
		return nil, errors.New("qcow2: backing chain deeper than 16")
	}
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, err
	}
	var hdr [72]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("qcow2: read header: %w", err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != qcow2Magic {
		f.Close()
		return nil, errors.New("qcow2: bad magic")
	}
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != 2 && version != 3 {
		f.Close()
		return nil, fmt.Errorf("qcow2: unsupported version %d", version)
	}
	backingOff := binary.BigEndian.Uint64(hdr[8:16])
	backingLen := binary.BigEndian.Uint32(hdr[16:20])
	clusterBits := binary.BigEndian.Uint32(hdr[20:24])
	if clusterBits < 9 || clusterBits > 24 {
		f.Close()
		return nil, fmt.Errorf("qcow2: invalid cluster_bits %d", clusterBits)
	}
	size := binary.BigEndian.Uint64(hdr[24:32])
	if enc := binary.BigEndian.Uint32(hdr[32:36]); enc != 0 {
		f.Close()
		return nil, fmt.Errorf("qcow2: encrypted image (method %d) not supported", enc)
	}
	l1Size := binary.BigEndian.Uint32(hdr[36:40])
	l1Off := binary.BigEndian.Uint64(hdr[40:48])
	if l1Size > 1<<24 || size > 1<<50 {
		f.Close()
		return nil, errors.New("qcow2: implausible L1 table or disk size")
	}

	d := &qcow2Disk{
		f:           f,
		clusterBits: clusterBits,
		clusterSize: int64(1) << clusterBits,
		l2Bits:      clusterBits - 3,
		l2Entries:   1 << (clusterBits - 3),
		size:        int64(size),
		l2Cache:     map[uint64][]uint64{},
	}
	raw := make([]byte, int(l1Size)*8)
	if _, err := f.ReadAt(raw, int64(l1Off)); err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return nil, fmt.Errorf("qcow2: read L1 table: %w", err)
	}
	d.l1 = make([]uint64, l1Size)
	for i := range d.l1 {
		d.l1[i] = binary.BigEndian.Uint64(raw[i*8:])
	}

	if backingOff != 0 && backingLen > 0 && backingLen < 4096 {
		name := make([]byte, backingLen)
		if _, err := f.ReadAt(name, int64(backingOff)); err == nil {
			bp := string(name)
			if !filepath.IsAbs(bp) {
				bp = filepath.Join(filepath.Dir(path), filepath.FromSlash(strings.ReplaceAll(bp, "\\", "/")))
			}
			parent, err := openQCOW2(bp, depth+1)
			if err != nil {
				// a raw backing file is legal too
				pf, perr := os.Open(bp)
				if perr != nil {
					f.Close()
					return nil, fmt.Errorf("qcow2: backing file %s: %w", bp, err)
				}
				d.parent, d.parentClose = pf, pf.Close
			} else {
				d.parent, d.parentClose = parent, parent.Close
			}
		}
	}
	return d, nil
}

func (d *qcow2Disk) Close() error {
	err := d.f.Close()
	if d.parentClose != nil {
		if perr := d.parentClose(); err == nil {
			err = perr
		}
	}
	return err
}

func (d *qcow2Disk) l2Lookup(tableOff uint64, idx int) (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.l2Cache[tableOff]; ok {
		return t[idx], nil
	}
	raw := make([]byte, d.l2Entries*8)
	if _, err := d.f.ReadAt(raw, int64(tableOff)); err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("qcow2: read L2 table: %w", err)
	}
	t := make([]uint64, d.l2Entries)
	for i := range t {
		t[i] = binary.BigEndian.Uint64(raw[i*8:])
	}
	if len(d.l2Cache) >= qcow2L2CacheTables {
		d.l2Cache = map[uint64][]uint64{}
	}
	d.l2Cache[tableOff] = t
	return t[idx], nil
}

func (d *qcow2Disk) fromParentOrZero(p []byte, off int64) {
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

// readCluster fills p (which lies within one cluster) from offset off.
func (d *qcow2Disk) readCluster(p []byte, off int64) error {
	l1Idx := int(off >> (d.l2Bits + d.clusterBits))
	l2Idx := int((off >> d.clusterBits) & (int64(1)<<d.l2Bits - 1))
	within := off & (d.clusterSize - 1)
	if l1Idx >= len(d.l1) {
		d.fromParentOrZero(p, off)
		return nil
	}
	l2Off := d.l1[l1Idx] & qcow2OffsetMask
	if l2Off == 0 {
		d.fromParentOrZero(p, off)
		return nil
	}
	entry, err := d.l2Lookup(l2Off, l2Idx)
	if err != nil {
		return err
	}
	if entry&qcow2CompressedFlag != 0 {
		// compressed cluster descriptor: host offset in the low bits, the
		// compressed size (in 512-byte sectors, minus one) above it
		x := 62 - (d.clusterBits - 8)
		hostOff := int64(entry & (uint64(1)<<x - 1))
		sectors := int64((entry >> x) & (uint64(1)<<(d.clusterBits-8) - 1))
		csize := (sectors + 1) * 512
		comp := make([]byte, csize)
		n, rerr := d.f.ReadAt(comp, hostOff)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return fmt.Errorf("qcow2: read compressed cluster: %w", rerr)
		}
		fr := flate.NewReader(bytes.NewReader(comp[:n]))
		out := make([]byte, d.clusterSize)
		got, ferr := io.ReadFull(fr, out)
		fr.Close()
		if ferr != nil && !errors.Is(ferr, io.ErrUnexpectedEOF) && !errors.Is(ferr, io.EOF) {
			return fmt.Errorf("qcow2: inflate cluster: %w", ferr)
		}
		for i := got; i < len(out); i++ {
			out[i] = 0
		}
		copy(p, out[within:within+int64(len(p))])
		return nil
	}
	dataOff := entry & qcow2OffsetMask
	if dataOff == 0 {
		d.fromParentOrZero(p, off)
		return nil
	}
	n, rerr := d.f.ReadAt(p, int64(dataOff)+within)
	if rerr != nil && n < len(p) {
		for i := n; i < len(p); i++ {
			p[i] = 0 // truncated image: zeros, not a failure
		}
	}
	return nil
}

func (d *qcow2Disk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("qcow2: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= d.size {
			return total, io.EOF
		}
		n := int64(len(p))
		within := off & (d.clusterSize - 1)
		if within+n > d.clusterSize {
			n = d.clusterSize - within
		}
		if off+n > d.size {
			n = d.size - off
		}
		if err := d.readCluster(p[:n], off); err != nil {
			return total, err
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}
