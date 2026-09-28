// Apple sparse disk images, read-only: the .sparseimage file (a "sprs"
// header whose band table maps the file's bands onto the virtual disk) and
// the .sparsebundle directory (Info.plist plus one file per band under
// bands/, named by the band number in hex). Bands never written read as
// zeros. An encrypted image (the "encrcdsa" header) is recognised and
// refused. Written clean-room from the libyal "Mac OS disk image types"
// documentation; gomount's own code. All sprs fields are big-endian.
package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const (
	sprsHeaderSize   = 4096
	sprsTableOff     = 64
	sprsMaxBandBytes = 1 << 32
	bundleOpenBands  = 16 // band files kept open
)

var (
	sigSprs     = []byte("sprs")
	sigEncrcdsa = []byte("encrcdsa") // encrypted image header (v2)
	sigCdsaencr = []byte("cdsaencr") // encrypted image trailer (v1)
)

// looksLikeEncryptedDMG reports an Apple encrypted disk image: the v2
// header at 0 or the v1 trailer in the last 8 bytes.
func looksLikeEncryptedDMG(f io.ReaderAt, size int64) bool {
	var b [8]byte
	if _, err := f.ReadAt(b[:], 0); err == nil && bytes.Equal(b[:], sigEncrcdsa) {
		return true
	}
	if size >= 8 {
		if _, err := f.ReadAt(b[:], size-8); err == nil && bytes.Equal(b[:], sigCdsaencr) {
			return true
		}
	}
	return false
}

// sparseImage is a .sparseimage: fileBand[i] is where disk band i lies in
// the file (-1: never written).
type sparseImage struct {
	f         *os.File
	fileSize  int64
	size      int64
	bandBytes int64
	dataOff   int64
	fileBand  []int64
}

func openSparseImage(path string) (*sparseImage, error) {
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	s, err := parseSparseImage(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	s.f = f
	return s, nil
}

func parseSparseImage(f io.ReaderAt, fileSize int64) (*sparseImage, error) {
	var h [sprsTableOff]byte
	if _, err := f.ReadAt(h[:], 0); err != nil {
		return nil, fmt.Errorf("sparseimage: read header: %w", err)
	}
	if !bytes.Equal(h[0:4], sigSprs) {
		return nil, errors.New("sparseimage: no sprs header")
	}
	spb := uint64(binary.BigEndian.Uint32(h[8:12]))
	sectors := uint64(binary.BigEndian.Uint32(h[16:20]))
	bandBytes := spb * 512
	if spb == 0 || bandBytes > sprsMaxBandBytes {
		return nil, fmt.Errorf("sparseimage: implausible band of %d sectors", spb)
	}
	if sectors == 0 {
		return nil, errors.New("sparseimage: zero-sector image")
	}
	nBands := (sectors + spb - 1) / spb
	// The band table runs from offset 64; the documented header is 4096
	// bytes, which holds 1008 entries. A larger table is taken to grow the
	// header to the next 4096 boundary — accepted only when the file's
	// length agrees with that layout, never guessed silently.
	tableBytes := nBands * 4
	headerSize := uint64(sprsHeaderSize)
	if sprsTableOff+tableBytes > headerSize {
		headerSize = (sprsTableOff + tableBytes + sprsHeaderSize - 1) / sprsHeaderSize * sprsHeaderSize
	}
	if uint64(fileSize) < headerSize {
		return nil, errors.New("sparseimage: file shorter than its header")
	}
	table := make([]byte, tableBytes)
	if _, err := f.ReadAt(table, sprsTableOff); err != nil {
		return nil, fmt.Errorf("sparseimage: read band table: %w", err)
	}
	s := &sparseImage{
		fileSize:  fileSize,
		size:      int64(sectors * 512),
		bandBytes: int64(bandBytes),
		dataOff:   int64(headerSize),
		fileBand:  make([]int64, nBands),
	}
	for i := range s.fileBand {
		s.fileBand[i] = -1
	}
	last := -1
	for i := uint64(0); i < nBands; i++ {
		v := uint64(binary.BigEndian.Uint32(table[i*4:]))
		if v == 0 {
			continue
		}
		if v > nBands {
			return nil, fmt.Errorf("sparseimage: file band %d maps to band %d of %d", i, v-1, nBands)
		}
		if s.fileBand[v-1] >= 0 {
			return nil, fmt.Errorf("sparseimage: band %d stored twice", v-1)
		}
		s.fileBand[v-1] = int64(i)
		last = int(i)
	}
	// the stored bands must be in the file: the last may be short (the
	// file is cut where the data ends), none may lie wholly past its end;
	// the grown-header layout must account for the file exactly
	data := uint64(fileSize) - headerSize
	if last >= 0 && data <= uint64(last)*bandBytes {
		return nil, fmt.Errorf("sparseimage: %d bands stored but the file holds %d bytes of band data", last+1, data)
	}
	if headerSize != sprsHeaderSize && data > uint64(last+1)*bandBytes {
		return nil, fmt.Errorf("sparseimage: a %d-band table and %d bytes of band data do not agree on the header size", nBands, data)
	}
	return s, nil
}

func (s *sparseImage) Close() error { return s.f.Close() }

func (s *sparseImage) ReadAt(p []byte, off int64) (int, error) {
	return readBanded(p, off, s.size, s.bandBytes, func(band int64, q []byte, within int64) error {
		i := s.fileBand[band]
		if i < 0 {
			clear(q)
			return nil
		}
		return readOrZero(s.f, q, s.dataOff+i*s.bandBytes+within)
	})
}

// sparseBundle is a .sparsebundle directory.
type sparseBundle struct {
	dir       string
	size      int64
	bandBytes int64

	mu   sync.Mutex
	open map[int64]*os.File // band files kept open (nil: absent)
	lru  []int64
}

// bundleInfo reads a directory's Info.plist and reports whether it
// describes a sparse bundle.
func bundleInfo(dir string) (*plistValue, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "Info.plist"))
	if err != nil || len(b) > 1<<20 {
		return nil, false
	}
	pl, err := parsePlist(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	t := pl.get("diskimage-bundle-type")
	return pl, t != nil && t.text == "com.apple.diskimage.sparsebundle"
}

func openSparseBundle(dir string) (*sparseBundle, error) {
	pl, ok := bundleInfo(dir)
	if !ok {
		return nil, errors.New("sparsebundle: Info.plist does not describe a sparse bundle")
	}
	bandBytes, ok1 := pl.get("band-size").uint()
	size, ok2 := pl.get("size").uint()
	if !ok1 || !ok2 {
		return nil, errors.New("sparsebundle: Info.plist lacks band-size or size")
	}
	if bandBytes == 0 || bandBytes > sprsMaxBandBytes || size == 0 || size > udifMaxDiskBytes {
		return nil, fmt.Errorf("sparsebundle: implausible geometry (band-size %d, size %d)", bandBytes, size)
	}
	// an encrypted bundle keeps its encryption header in the token file
	if t, err := os.Open(filepath.Join(dir, "token")); err == nil {
		st, _ := t.Stat()
		enc := st != nil && looksLikeEncryptedDMG(t, st.Size())
		t.Close()
		if enc {
			return nil, errors.New("sparsebundle: encrypted disk image (encrcdsa) — decryption is not supported")
		}
	}
	if st, err := os.Stat(filepath.Join(dir, "bands")); err != nil || !st.IsDir() {
		return nil, errors.New("sparsebundle: no bands directory")
	}
	return &sparseBundle{dir: dir, size: int64(size), bandBytes: int64(bandBytes), open: map[int64]*os.File{}}, nil
}

// readBand fills q from band i at offset within. The lock is held across
// the read so an eviction never closes a file another reader is using.
func (b *sparseBundle) readBand(i int64, q []byte, within int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.open[i]
	if ok {
		for j, k := range b.lru { // most recently used last
			if k == i {
				b.lru = append(append(b.lru[:j:j], b.lru[j+1:]...), i)
				break
			}
		}
	} else {
		var err error
		f, err = os.Open(filepath.Join(b.dir, "bands", strconv.FormatInt(i, 16)))
		if errors.Is(err, os.ErrNotExist) {
			f, err = nil, nil // never written
		}
		if err != nil {
			return fmt.Errorf("sparsebundle: band %x: %w", i, err)
		}
		if len(b.lru) >= bundleOpenBands {
			old := b.lru[0]
			b.lru = b.lru[1:]
			if of := b.open[old]; of != nil {
				of.Close()
			}
			delete(b.open, old)
		}
		b.open[i] = f
		b.lru = append(b.lru, i)
	}
	if f == nil {
		clear(q)
		return nil
	}
	// a band file shorter than band-size ends where its data does
	return readOrZero(f, q, within)
}

func (b *sparseBundle) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var first error
	for _, f := range b.open {
		if f != nil {
			if err := f.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	b.open = map[int64]*os.File{}
	b.lru = nil
	return first
}

func (b *sparseBundle) ReadAt(p []byte, off int64) (int, error) {
	return readBanded(p, off, b.size, b.bandBytes, b.readBand)
}

// readBanded splits a read at band boundaries and hands each piece to
// read(band, piece, offset within the band).
func readBanded(p []byte, off, size, bandBytes int64, read func(band int64, q []byte, within int64) error) (int, error) {
	if off < 0 {
		return 0, errors.New("sparse image: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= size {
			return total, io.EOF
		}
		band, within := off/bandBytes, off%bandBytes
		n := min(int64(len(p)), bandBytes-within, size-off)
		if err := read(band, p[:n], within); err != nil {
			return total, err
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}

// readOrZero fills q from f at off; bytes past the end of f read as zeros.
func readOrZero(f io.ReaderAt, q []byte, off int64) error {
	n, err := f.ReadAt(q, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	clear(q[n:])
	return nil
}
