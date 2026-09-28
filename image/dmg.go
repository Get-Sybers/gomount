// UDIF (Apple Universal Disk Image Format, .dmg) containers, read-only: the
// 512-byte "koly" trailer, the block tables ("mish") it points at through the
// XML property list — or, for images without one, the classic resource fork —
// and the chunks those tables map onto the virtual disk: zero-fill, raw, ADC,
// zlib, bzip2 and LZFSE. LZMA (ULMO) chunks are recognised and refused with a
// clear error; a segmented set (.dmgpart) is refused. Written clean-room from
// the libyal "Mac OS disk image types" documentation and the public format
// descriptions; gomount's own code.
//
// The result is an io.ReaderAt over the raw disk the image holds, decoded on
// demand chunk by chunk (a small byte-bounded cache keeps the recent ones),
// so the partition layer (GPT, Apple Partition Map, MBR) and the filesystem
// backends read it unchanged. Sectors no chunk covers read as zeros. All
// multi-byte fields are big-endian.
package image

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/get-sybers/gomount/lzfse"
)

const (
	udifTrailerSize   = 512
	udifSector        = 512
	mishHeaderSize    = 204 // through the chunk count at 200
	mishEntrySize     = 40
	udifMaxPlist      = 64 << 20 // an installer's plist is ~100 KB
	udifMaxChunkBytes = 64 << 20 // one chunk decoded (hdiutil writes ≤ 4 MiB)
	udifMaxDiskBytes  = 1 << 50
	udifCacheBytes    = 32 << 20 // decoded chunks kept for sequential reads

	udifChunkZero       = 0x00000000
	udifChunkRaw        = 0x00000001
	udifChunkIgnore     = 0x00000002
	udifChunkComment    = 0x7ffffffe
	udifChunkADC        = 0x80000004
	udifChunkZlib       = 0x80000005
	udifChunkBzip2      = 0x80000006
	udifChunkLZFSE      = 0x80000007
	udifChunkLZMA       = 0x80000008
	udifChunkTerminator = 0xffffffff
)

var sigKoly = []byte("koly")

// udifChunk is one run of sectors on the virtual disk and where its bytes
// live in the file (raw and compressed chunks only).
type udifChunk struct {
	typ          uint32
	start, count int64 // sectors on the virtual disk
	off, length  int64 // bytes in the image file
}

func (c udifChunk) end() int64 { return c.start + c.count }

type dmgDisk struct {
	f      io.ReaderAt
	closer func() error
	size   int64
	chunks []udifChunk // sorted by start, non-overlapping; comments and terminators dropped

	mu          sync.Mutex
	cache       map[int][]byte // decoded compressed chunks by index
	lru         []int          // cache order, least recent first
	cacheBytes  int
	cacheBudget int
}

// looksLikeDMG reports whether the file ends in a UDIF trailer.
func looksLikeDMG(f io.ReaderAt, size int64) bool {
	if size < udifTrailerSize {
		return false
	}
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], size-udifTrailerSize); err != nil {
		return false
	}
	return bytes.Equal(magic[:], sigKoly)
}

// udifChunkName names a chunk type for the error messages and identify.
func udifChunkName(t uint32) string {
	switch t {
	case udifChunkZero:
		return "zero"
	case udifChunkRaw:
		return "raw"
	case udifChunkIgnore:
		return "ignore"
	case udifChunkComment:
		return "comment"
	case udifChunkADC:
		return "ADC"
	case udifChunkZlib:
		return "zlib"
	case udifChunkBzip2:
		return "bzip2"
	case udifChunkLZFSE:
		return "LZFSE"
	case udifChunkLZMA:
		return "LZMA"
	case udifChunkTerminator:
		return "terminator"
	}
	return fmt.Sprintf("0x%08x", t)
}

func openDMG(path string) (*dmgDisk, error) {
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	d, err := parseDMG(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	d.closer = f.Close
	return d, nil
}

// parseDMG reads the trailer and the block tables of a UDIF file of
// fileSize bytes and builds the chunk map over f (the caller owns closing).
func parseDMG(f io.ReaderAt, fileSize int64) (*dmgDisk, error) {
	if fileSize < udifTrailerSize {
		return nil, errors.New("dmg: file too small for a koly trailer")
	}
	var k [udifTrailerSize]byte
	if _, err := f.ReadAt(k[:], fileSize-udifTrailerSize); err != nil {
		return nil, fmt.Errorf("dmg: read trailer: %w", err)
	}
	if !bytes.Equal(k[0:4], sigKoly) {
		return nil, errors.New("dmg: no koly trailer")
	}
	if hs := binary.BigEndian.Uint32(k[8:12]); hs != udifTrailerSize {
		return nil, fmt.Errorf("dmg: trailer size %d, want 512", hs)
	}
	if segs := binary.BigEndian.Uint32(k[60:64]); segs > 1 {
		return nil, fmt.Errorf("dmg: segmented image (%d segments, .dmgpart set) is not supported", segs)
	}
	body := uint64(fileSize - udifTrailerSize) // everything before the trailer
	span := func(what string, off, n uint64) error {
		if off > body || n > body-off {
			return fmt.Errorf("dmg: %s [%d,+%d) lies outside the file", what, off, n)
		}
		return nil
	}
	dataOff, dataLen := binary.BigEndian.Uint64(k[24:32]), binary.BigEndian.Uint64(k[32:40])
	rsrcOff, rsrcLen := binary.BigEndian.Uint64(k[40:48]), binary.BigEndian.Uint64(k[48:56])
	xmlOff, xmlLen := binary.BigEndian.Uint64(k[216:224]), binary.BigEndian.Uint64(k[224:232])
	sectors := binary.BigEndian.Uint64(k[492:500])
	if err := span("data fork", dataOff, dataLen); err != nil {
		return nil, err
	}

	// the block tables: the XML plist's resource-fork/blkx, else the
	// classic resource fork's 'blkx' resources
	var tables [][]byte
	switch {
	case xmlLen > 0:
		if err := span("XML plist", xmlOff, xmlLen); err != nil {
			return nil, err
		}
		if xmlLen > udifMaxPlist {
			return nil, fmt.Errorf("dmg: XML plist of %d bytes is implausibly large", xmlLen)
		}
		buf := make([]byte, xmlLen)
		if _, err := f.ReadAt(buf, int64(xmlOff)); err != nil {
			return nil, fmt.Errorf("dmg: read XML plist: %w", err)
		}
		pl, err := parsePlist(bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("dmg: %w", err)
		}
		blkx := pl.get("resource-fork").get("blkx")
		if blkx == nil || blkx.kind != "array" {
			return nil, errors.New("dmg: the plist has no resource-fork/blkx array")
		}
		for i, e := range blkx.arr {
			data := e.get("Data")
			if data == nil || data.kind != "data" {
				return nil, fmt.Errorf("dmg: blkx entry %d has no Data", i)
			}
			tables = append(tables, data.data)
		}
	case rsrcLen > 0:
		if err := span("resource fork", rsrcOff, rsrcLen); err != nil {
			return nil, err
		}
		if rsrcLen > udifMaxPlist {
			return nil, fmt.Errorf("dmg: resource fork of %d bytes is implausibly large", rsrcLen)
		}
		buf := make([]byte, rsrcLen)
		if _, err := f.ReadAt(buf, int64(rsrcOff)); err != nil {
			return nil, fmt.Errorf("dmg: read resource fork: %w", err)
		}
		var err error
		if tables, err = resourceForkBlkx(buf); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("dmg: neither an XML plist nor a resource fork holds the block tables")
	}
	if len(tables) == 0 {
		return nil, errors.New("dmg: no block tables")
	}

	d := &dmgDisk{f: f, cache: map[int][]byte{}, cacheBudget: udifCacheBytes}
	maxEnd := int64(0)
	for ti, m := range tables {
		chunks, err := parseMish(m, dataOff, fileSize-udifTrailerSize)
		if err != nil {
			return nil, fmt.Errorf("dmg: block table %d: %w", ti, err)
		}
		for _, c := range chunks {
			if c.end() > maxEnd {
				maxEnd = c.end()
			}
		}
		d.chunks = append(d.chunks, chunks...)
	}
	if sectors > udifMaxDiskBytes/udifSector {
		return nil, fmt.Errorf("dmg: implausible sector count %d", sectors)
	}
	total := int64(sectors)
	if maxEnd > total {
		total = maxEnd // a trailer that undercounts never hides mapped sectors
	}
	if total == 0 {
		return nil, errors.New("dmg: the image maps no sectors")
	}
	d.size = total * udifSector
	sort.Slice(d.chunks, func(i, j int) bool { return d.chunks[i].start < d.chunks[j].start })
	for i := 1; i < len(d.chunks); i++ {
		if d.chunks[i].start < d.chunks[i-1].end() {
			return nil, fmt.Errorf("dmg: chunks at sectors %d and %d overlap", d.chunks[i-1].start, d.chunks[i].start)
		}
	}
	return d, nil
}

// parseMish decodes one "mish" block table into chunks with absolute disk
// sectors and absolute file offsets (the chunk offsets count from the data
// fork plus the table's own data offset), each bounded to the file's first
// body bytes.
func parseMish(m []byte, dataForkOff uint64, body int64) ([]udifChunk, error) {
	if len(m) < mishHeaderSize || !bytes.Equal(m[0:4], []byte("mish")) {
		return nil, errors.New("not a mish block")
	}
	base := binary.BigEndian.Uint64(m[8:16])
	tableSectors := binary.BigEndian.Uint64(m[16:24])
	tableDataOff := binary.BigEndian.Uint64(m[24:32])
	n := binary.BigEndian.Uint32(m[200:204])
	if uint64(n) > uint64(len(m)-mishHeaderSize)/mishEntrySize {
		return nil, fmt.Errorf("%d chunks do not fit a %d-byte table", n, len(m))
	}
	const maxSectors = udifMaxDiskBytes / udifSector
	if base > maxSectors || tableSectors > maxSectors-base {
		return nil, fmt.Errorf("implausible sector range %d+%d", base, tableSectors)
	}
	if dataForkOff > uint64(body) || tableDataOff > uint64(body)-dataForkOff {
		return nil, fmt.Errorf("data offset %d lies outside the file", tableDataOff)
	}
	fileBase := dataForkOff + tableDataOff
	var out []udifChunk
	for i := uint32(0); i < n; i++ {
		e := m[mishHeaderSize+int(i)*mishEntrySize:]
		typ := binary.BigEndian.Uint32(e[0:4])
		sec := binary.BigEndian.Uint64(e[8:16])
		cnt := binary.BigEndian.Uint64(e[16:24])
		off := binary.BigEndian.Uint64(e[24:32])
		length := binary.BigEndian.Uint64(e[32:40])
		if typ == udifChunkTerminator {
			break
		}
		if typ == udifChunkComment || cnt == 0 {
			continue
		}
		if sec > maxSectors-base || cnt > maxSectors-base-sec {
			return nil, fmt.Errorf("chunk %d: implausible sector range %d+%d", i, base+sec, cnt)
		}
		c := udifChunk{typ: typ, start: int64(base + sec), count: int64(cnt)}
		switch typ {
		case udifChunkZero, udifChunkIgnore:
			// no bytes in the file
		default:
			if off > uint64(body)-fileBase || length > uint64(body)-fileBase-off {
				return nil, fmt.Errorf("chunk %d (%s, sector %d): data [%d,+%d) lies outside the file", i, udifChunkName(typ), c.start, fileBase+off, length)
			}
			c.off, c.length = int64(fileBase+off), int64(length)
			if typ == udifChunkRaw {
				if length < cnt*udifSector {
					return nil, fmt.Errorf("chunk %d (raw, sector %d): %d bytes stored for %d sectors", i, c.start, length, cnt)
				}
			} else if cnt*udifSector > udifMaxChunkBytes {
				return nil, fmt.Errorf("chunk %d (%s, sector %d): decodes to %d bytes, above the %d-byte bound", i, udifChunkName(typ), c.start, cnt*udifSector, udifMaxChunkBytes)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// resourceForkBlkx returns the data of every 'blkx' resource in a classic
// Mac resource fork (the pre-plist home of the block tables). Layout per
// Inside Macintosh: a 16-byte header (data offset, map offset, data length,
// map length); the map holds a type list and, per type, a reference list of
// 12-byte entries whose low 24 bits of the second word are the resource's
// offset into the data area, where a 4-byte length precedes its bytes.
func resourceForkBlkx(b []byte) ([][]byte, error) {
	bad := errors.New("dmg: malformed resource fork")
	if len(b) < 16 {
		return nil, bad
	}
	dataOff := uint64(binary.BigEndian.Uint32(b[0:4]))
	mapOff := uint64(binary.BigEndian.Uint32(b[4:8]))
	size := uint64(len(b))
	if dataOff > size || mapOff+30 > size {
		return nil, bad
	}
	typeList := mapOff + uint64(binary.BigEndian.Uint16(b[mapOff+24:mapOff+26]))
	if typeList+2 > size {
		return nil, bad
	}
	nTypes := uint64(binary.BigEndian.Uint16(b[typeList:typeList+2])) + 1
	if nTypes == 0x10000 { // 0xFFFF: an empty type list
		nTypes = 0
	}
	var out [][]byte
	for t := uint64(0); t < nTypes; t++ {
		te := typeList + 2 + t*8
		if te+8 > size {
			return nil, bad
		}
		if string(b[te:te+4]) != "blkx" {
			continue
		}
		nRefs := uint64(binary.BigEndian.Uint16(b[te+4:te+6])) + 1
		refList := typeList + uint64(binary.BigEndian.Uint16(b[te+6:te+8]))
		for r := uint64(0); r < nRefs; r++ {
			re := refList + r*12
			if re+12 > size {
				return nil, bad
			}
			at := dataOff + uint64(binary.BigEndian.Uint32(b[re+4:re+8])&0x00ffffff)
			if at+4 > size {
				return nil, bad
			}
			n := uint64(binary.BigEndian.Uint32(b[at : at+4]))
			if n > size-at-4 {
				return nil, bad
			}
			out = append(out, b[at+4:at+4+n])
		}
	}
	if len(out) == 0 {
		return nil, errors.New("dmg: the resource fork holds no blkx resources")
	}
	return out, nil
}

func (d *dmgDisk) Close() error {
	if d.closer == nil {
		return nil
	}
	return d.closer()
}

// chunkAt returns the index of the first chunk ending after sector s.
func (d *dmgDisk) chunkAt(s int64) int {
	return sort.Search(len(d.chunks), func(i int) bool { return d.chunks[i].end() > s })
}

func (d *dmgDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("dmg: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= d.size {
			return total, io.EOF
		}
		avail := d.size - off
		i := d.chunkAt(off / udifSector)
		var n int64
		if i == len(d.chunks) || d.chunks[i].start*udifSector > off {
			// a gap no chunk maps: zeros up to the next chunk
			n = avail
			if i < len(d.chunks) {
				n = d.chunks[i].start*udifSector - off
			}
			if n > int64(len(p)) {
				n = int64(len(p))
			}
			clear(p[:n])
		} else {
			c := d.chunks[i]
			within := off - c.start*udifSector
			n = c.count*udifSector - within
			if n > int64(len(p)) {
				n = int64(len(p))
			}
			if n > avail {
				n = avail
			}
			switch c.typ {
			case udifChunkZero, udifChunkIgnore:
				clear(p[:n])
			case udifChunkRaw:
				if m, err := d.f.ReadAt(p[:n], c.off+within); int64(m) < n {
					return total, fmt.Errorf("dmg: raw chunk at sector %d: %w", c.start, err)
				}
			default:
				buf, err := d.decoded(i)
				if err != nil {
					return total, err
				}
				copy(p[:n], buf[within:within+n])
			}
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}

// decoded returns chunk i decompressed, through the cache. The lock is not
// held while a chunk is read and decoded, so readers of different chunks
// run in parallel; two readers of one uncached chunk may both decode it,
// and the first to finish fills the cache.
func (d *dmgDisk) decoded(i int) ([]byte, error) {
	if b, ok := d.cached(i); ok {
		return b, nil
	}
	b, err := d.decodeChunk(d.chunks[i])
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if have, ok := d.cache[i]; ok {
		return have, nil
	}
	for len(d.lru) > 0 && d.cacheBytes+len(b) > d.cacheBudget {
		old := d.lru[0]
		d.lru = d.lru[1:]
		d.cacheBytes -= len(d.cache[old])
		delete(d.cache, old)
	}
	d.cache[i] = b
	d.lru = append(d.lru, i)
	d.cacheBytes += len(b)
	return b, nil
}

// cached returns chunk i from the cache, marking it most recently used.
func (d *dmgDisk) cached(i int) ([]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	b, ok := d.cache[i]
	if ok {
		for j, k := range d.lru {
			if k == i {
				d.lru = append(append(d.lru[:j:j], d.lru[j+1:]...), i)
				break
			}
		}
	}
	return b, ok
}

// decodeChunk decompresses one chunk to exactly its sector span; a stream
// that decodes short, or does not decode, is an error — never zeros or
// garbage handed back as evidence.
func (d *dmgDisk) decodeChunk(c udifChunk) ([]byte, error) {
	name := udifChunkName(c.typ)
	fail := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("dmg: %s chunk at sector %d: %w", name, c.start, err)
	}
	switch c.typ {
	case udifChunkADC, udifChunkZlib, udifChunkBzip2, udifChunkLZFSE:
	case udifChunkLZMA:
		return fail(errors.New("LZMA chunks are not supported (an ULMO image)"))
	default:
		return fail(errors.New("unsupported chunk type"))
	}
	comp := make([]byte, c.length)
	if m, err := d.f.ReadAt(comp, c.off); int64(m) < c.length {
		return fail(fmt.Errorf("read %d of %d bytes: %w", m, c.length, err))
	}
	out := make([]byte, c.count*udifSector)
	var n int
	var err error
	switch c.typ {
	case udifChunkZlib:
		var zr io.ReadCloser
		if zr, err = zlib.NewReader(bytes.NewReader(comp)); err == nil {
			n, err = io.ReadFull(zr, out)
			zr.Close()
		}
	case udifChunkBzip2:
		n, err = io.ReadFull(bzip2.NewReader(bytes.NewReader(comp)), out)
	case udifChunkLZFSE:
		n, err = lzfse.Decode(out, comp)
	case udifChunkADC:
		n, err = adcDecode(out, comp)
	}
	if err != nil {
		return fail(err)
	}
	if n != len(out) {
		return fail(fmt.Errorf("decoded %d bytes, want %d", n, len(out)))
	}
	return out, nil
}

// chunkTypes counts the chunks of each type (tests and diagnostics).
func (d *dmgDisk) chunkTypes() map[string]int {
	m := map[string]int{}
	for _, c := range d.chunks {
		m[udifChunkName(c.typ)]++
	}
	return m
}
