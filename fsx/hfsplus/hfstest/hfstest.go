// Package hfstest builds small HFS+ / HFSX volumes in memory for the
// backend's tests: no Linux build host can format one (mkfs.hfsplus is not
// in Debian's main archive), so the fixture is written from the format —
// volume header, allocation file, the catalog, extents-overflow and
// attributes B-trees with real index levels, fragmented forks that spill
// into the overflow tree, symbolic links, hard links through the private
// metadata directory, extended attributes and decmpfs content (zlib inline,
// zlib and raw resource forks, zeros) — and optionally wrapped in a classic
// HFS master directory block the way Apple's tools always did.
package hfstest

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
	"unicode/utf16"
)

// File is a regular file, symlink or hard link to build.
type File struct {
	Name     string
	Data     []byte
	Mode     uint16 // permission bits; the type comes from the kind (default 0644)
	UID, GID uint32
	Mtime    time.Time
	Fragment bool              // spread the data over one-block extents with gaps
	Compress uint32            // decmpfs type: 0 none, 3 zlib inline, 4 zlib rsrc, 5 zeros, 10 raw rsrc
	Xattrs   map[string][]byte // extended attributes (inline)
	Symlink  string            // a symbolic link to this target
	LinkRef  uint32            // a hard link to the indirect node of this reference (see Options.Inodes)
}

// Dir is a directory to build.
type Dir struct {
	Name  string
	Mode  uint16
	Files []File
	Dirs  []Dir
}

// Options shape the volume.
type Options struct {
	CaseSensitive bool // HFSX ("HX", binary key compare) instead of HFS+ ("H+", case folding)
	Wrapper       bool // embed the volume in a classic HFS wrapper (MDB at 1024)
	BlockSize     int  // allocation block size (default 4096)
	Blocks        int  // total allocation blocks (default 2048)
	NodeSize      int  // B-tree node size (default 4096)
	Label         string
	Inodes        map[uint32]File // hard-link targets by link reference: iNode<ref> in the private directory
}

const (
	be16           = 2
	hfsEpochOffset = 2082844800
)

var be = binary.BigEndian

type builder struct {
	opt       Options
	img       []byte
	blockSize int
	next      uint32 // next free allocation block
	nextCNID  uint32
	catalog   []rec
	overflow  []rec
	attrs     []rec
	files     uint32
	folders   uint32
	created   uint32
}

type rec struct {
	key  []byte // without the 2-byte length
	data []byte
}

// Build lays out the volume and returns its bytes.
func Build(root Dir, opt Options) []byte {
	if opt.BlockSize == 0 {
		opt.BlockSize = 4096
	}
	if opt.Blocks == 0 {
		opt.Blocks = 2048
	}
	if opt.NodeSize == 0 {
		opt.NodeSize = 4096
	}
	if opt.Label == "" {
		opt.Label = "Fixture"
	}
	b := &builder{opt: opt, blockSize: opt.BlockSize, img: make([]byte, opt.BlockSize*opt.Blocks), nextCNID: 16}
	b.created = hfsTime(time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC))
	b.next = 2 // block 0: the header; block 1: the allocation file
	// the root folder (id 2, parent 1) named after the volume
	b.folder(1, 2, opt.Label, root, 0o755)
	// the private metadata directory holds the hard-link targets
	if len(opt.Inodes) > 0 {
		refs := make([]uint32, 0, len(opt.Inodes))
		for r := range opt.Inodes {
			refs = append(refs, r)
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
		priv := Dir{Name: "\x00\x00\x00\x00HFS+ Private Data", Mode: 0o700}
		for _, r := range refs {
			f := opt.Inodes[r]
			f.Name = fmt.Sprintf("iNode%d", r)
			f.LinkRef = 0
			priv.Files = append(priv.Files, f)
		}
		b.folderRec(2, priv)
	}

	// the B-tree files, allocated after every fork
	sortRecs(b.catalog, opt.CaseSensitive)
	sortRecs(b.overflow, true)
	sortAttrs(b.attrs)
	keyCompare := byte(0xcf)
	if opt.CaseSensitive {
		keyCompare = 0xbc
	}
	catTree := buildTree(b.catalog, opt.NodeSize, 516, true, keyCompare)
	extTree := buildTree(b.overflow, opt.NodeSize, 10, false, 0xbc)
	var attrTree []byte
	if len(b.attrs) > 0 {
		attrTree = buildTree(b.attrs, opt.NodeSize, 522, true, 0xbc)
	}
	catDesc := b.placeFork(catTree)
	extDesc := b.placeFork(extTree)
	var attrDesc []byte
	if attrTree != nil {
		attrDesc = b.placeFork(attrTree)
	} else {
		attrDesc = make([]byte, 80)
	}

	// the allocation file: one block, every block below next marked used
	alloc := b.img[b.blockSize : 2*b.blockSize]
	for blk := uint32(0); blk < b.next && int(blk/8) < len(alloc); blk++ {
		alloc[blk/8] |= 0x80 >> (blk % 8)
	}
	alloc[len(alloc)-1] |= 1 // the alternate header's block
	allocDesc := forkDesc(int64(b.blockSize), []ext{{1, 1}})

	hdr := make([]byte, 512)
	if opt.CaseSensitive {
		copy(hdr, "HX")
		be.PutUint16(hdr[2:], 5)
	} else {
		copy(hdr, "H+")
		be.PutUint16(hdr[2:], 4)
	}
	be.PutUint32(hdr[4:], 0x100) // unmounted cleanly
	copy(hdr[8:], "10.0")
	be.PutUint32(hdr[16:], b.created)
	be.PutUint32(hdr[20:], b.created+60)
	be.PutUint32(hdr[28:], b.created+120)
	be.PutUint32(hdr[32:], b.files)
	be.PutUint32(hdr[36:], b.folders-1)
	be.PutUint32(hdr[40:], uint32(b.blockSize))
	be.PutUint32(hdr[44:], uint32(opt.Blocks))
	be.PutUint32(hdr[48:], uint32(opt.Blocks)-b.next-1)
	be.PutUint32(hdr[52:], b.next)
	be.PutUint32(hdr[56:], 65536)
	be.PutUint32(hdr[60:], 65536)
	be.PutUint32(hdr[64:], b.nextCNID)
	be.PutUint32(hdr[68:], 7)
	be.PutUint64(hdr[72:], 1)
	copy(hdr[104:112], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}) // finderInfo[6..7]: the UUID seed
	copy(hdr[112:192], allocDesc)
	copy(hdr[192:272], extDesc)
	copy(hdr[272:352], catDesc)
	copy(hdr[352:432], attrDesc)
	copy(b.img[1024:], hdr)
	copy(b.img[len(b.img)-1024:], hdr) // the alternate volume header

	if !opt.Wrapper {
		return b.img
	}
	// the classic HFS wrapper: an MDB whose embed extent points at the
	// volume, which starts at wrapper allocation block 1 (drAlBlSt 8
	// sectors = 4096 bytes, block size 4096: base 8192)
	pre := make([]byte, 8192)
	mdb := pre[1024:]
	copy(mdb, "BD")
	be.PutUint16(mdb[10:], 0x8100) // software locked, unmounted
	be.PutUint32(mdb[20:], 4096)   // drAlBlkSiz
	be.PutUint16(mdb[28:], 8)      // drAlBlSt (512-byte sectors)
	copy(mdb[124:], "H+")          // drEmbedSigWord
	be.PutUint16(mdb[126:], 1)     // drEmbedExtent.startBlock
	be.PutUint16(mdb[128:], uint16(opt.Blocks))
	return append(pre, b.img...)
}

// WrapAPM places a volume in an Apple Partition Map image: the driver
// descriptor at block 0, the map's own entry and the volume's entry from
// block 1, the volume from block 64 — the layout of a PowerPC-era disk or
// an uncompressed DMG.
func WrapAPM(vol []byte, typ, name string) []byte {
	const blk = 512
	start := int64(64)
	img := make([]byte, start*blk+int64(len(vol)))
	copy(img, "ER")
	be.PutUint16(img[2:], blk)
	be.PutUint32(img[4:], uint32(len(img)/blk))
	entry := func(n int64, first, count uint32, ename, etype string) {
		e := img[n*blk : (n+1)*blk]
		copy(e, "PM")
		be.PutUint32(e[4:], 2)
		be.PutUint32(e[8:], first)
		be.PutUint32(e[12:], count)
		copy(e[16:], ename)
		copy(e[48:], etype)
		be.PutUint32(e[84:], count) // data area size
		be.PutUint32(e[88:], 0x33)  // valid, allocated, readable, writable, bootable
	}
	entry(1, 1, 63, "Apple", "Apple_partition_map")
	entry(2, uint32(start), uint32(len(vol)/blk), name, typ)
	copy(img[start*blk:], vol)
	return img
}

// Fixture is the tree the backend's tests and mkhfs build: a Mac-shaped
// root with SystemVersion.plist, a fragmented twelve-block file, a symlink,
// two hard links to iNode500 (Options.Inodes supplies it), extended
// attributes, decmpfs files of every encoded shape, and a 300-file
// directory so the catalog grows an index level.
func Fixture() Dir {
	many := Dir{Name: "many"}
	for i := 0; i < 300; i++ {
		many.Files = append(many.Files, File{Name: fmt.Sprintf("file-%03d.txt", i), Data: []byte(fmt.Sprintf("content %d\n", i))})
	}
	return Dir{
		Files: []File{
			{Name: "hosts", Data: []byte("127.0.0.1 localhost\n"), Mode: 0o644, Mtime: time.Date(2019, 7, 4, 9, 30, 0, 0, time.UTC)},
			{Name: "big.bin", Data: BigData, Fragment: true, UID: 501, GID: 20},
			{Name: "link-to-hosts", Symlink: "/private/etc/hosts"},
			{Name: "tagged.txt", Data: []byte("tagged\n"), Xattrs: map[string][]byte{"com.apple.quarantine": []byte("0083;5f0a1b2c;Safari;"), "user.note": []byte("a note")}},
			{Name: "zlib-inline.plist", Data: InlineTxt, Compress: 3},
			{Name: "zlib-rsrc.txt", Data: ZlibData, Compress: 4},
			{Name: "raw-rsrc.bin", Data: RawData, Compress: 10},
			{Name: "zeros.bin", Data: make([]byte, 100000), Compress: 5},
			{Name: "hard-a", LinkRef: 500, Mode: 0o600},
			{Name: "hard-b", LinkRef: 500, Mode: 0o600},
		},
		Dirs: []Dir{
			{Name: "Users", Dirs: []Dir{{Name: "alice", Files: []File{{Name: ".zsh_history", Data: []byte("ls\n"), UID: 501, GID: 20}}}}},
			{Name: "System", Dirs: []Dir{{Name: "Library", Dirs: []Dir{{Name: "CoreServices", Files: []File{{Name: "SystemVersion.plist", Data: InlineTxt}}}}}}},
			many,
		},
	}
}

// The fixture's larger contents, exported so the tests can compare.
var (
	BigData   = pattern(12*4096-100, 1)                        // twelve blocks: eight extents in the catalog, four in the overflow tree
	ZlibData  = bytes.Repeat([]byte("hello, decmpfs. "), 5000) // more than one 64 KiB chunk
	RawData   = pattern(70000, 9)
	InlineTxt = []byte("<plist version=\"1.0\"><dict><key>ProductVersion</key><string>10.13.6</string></dict></plist>\n")
)

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7+int(seed)) ^ byte(i>>8)
	}
	return b
}

// ---- the tree of records ----------------------------------------------------------

func hfsTime(t time.Time) uint32 {
	if t.IsZero() {
		return 0
	}
	return uint32(t.Unix() + hfsEpochOffset)
}

func (b *builder) folder(parent, id uint32, name string, d Dir, mode uint16) {
	b.folders++
	if mode == 0 {
		mode = 0o755
	}
	data := make([]byte, 88)
	be.PutUint16(data, 1)
	be.PutUint32(data[4:], uint32(len(d.Files)+len(d.Dirs)))
	be.PutUint32(data[8:], id)
	be.PutUint32(data[12:], b.created)
	be.PutUint32(data[16:], b.created+1)
	be.PutUint32(data[20:], b.created+2)
	be.PutUint32(data[24:], b.created+3)
	be.PutUint32(data[32:], 501)
	be.PutUint32(data[36:], 20)
	be.PutUint16(data[42:], 0x4000|mode)
	b.catalog = append(b.catalog, rec{key: catKey(parent, name), data: data})
	b.catalog = append(b.catalog, rec{key: catKey(id, ""), data: thread(3, parent, name)})
	for _, f := range d.Files {
		b.file(id, f)
	}
	for _, sub := range d.Dirs {
		b.folderRec(id, sub)
	}
}

func (b *builder) folderRec(parent uint32, d Dir) {
	id := b.nextCNID
	b.nextCNID++
	b.folder(parent, id, d.Name, d, d.Mode)
}

type ext struct{ start, count uint32 }

// alloc takes n contiguous blocks.
func (b *builder) alloc(n uint32) uint32 {
	s := b.next
	b.next += n
	if int(b.next) >= b.opt.Blocks-1 {
		panic("hfstest: volume too small")
	}
	return s
}

// write stores data in freshly allocated blocks; fragmented forks get one
// block per extent with an unused block between.
func (b *builder) write(data []byte, fragment bool) []ext {
	if len(data) == 0 {
		return nil
	}
	blocks := (len(data) + b.blockSize - 1) / b.blockSize
	if !fragment {
		s := b.alloc(uint32(blocks))
		copy(b.img[int(s)*b.blockSize:], data)
		return []ext{{s, uint32(blocks)}}
	}
	var exts []ext
	for i := 0; i < blocks; i++ {
		s := b.alloc(1)
		b.alloc(1) // the gap
		copy(b.img[int(s)*b.blockSize:], data[i*b.blockSize:min(len(data), (i+1)*b.blockSize)])
		exts = append(exts, ext{s, 1})
	}
	return exts
}

func forkDesc(size int64, exts []ext) []byte {
	d := make([]byte, 80)
	be.PutUint64(d, uint64(size))
	var total uint32
	for _, e := range exts {
		total += e.count
	}
	be.PutUint32(d[12:], total)
	for i, e := range exts {
		if i >= 8 {
			break
		}
		be.PutUint32(d[16+8*i:], e.start)
		be.PutUint32(d[20+8*i:], e.count)
	}
	return d
}

func (b *builder) file(parent uint32, f File) {
	id := b.nextCNID
	b.nextCNID++
	b.files++
	data := make([]byte, 248)
	be.PutUint16(data, 2)
	flags := uint16(0x2) // thread exists
	be.PutUint32(data[8:], id)
	be.PutUint32(data[12:], b.created)
	mt := b.created + 10
	if !f.Mtime.IsZero() {
		mt = hfsTime(f.Mtime)
	}
	be.PutUint32(data[16:], mt)
	be.PutUint32(data[20:], mt+1)
	be.PutUint32(data[24:], mt+2)
	be.PutUint32(data[32:], f.UID)
	be.PutUint32(data[36:], f.GID)
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	var dataFork, rsrcFork []byte
	switch {
	case f.Symlink != "":
		be.PutUint16(data[42:], 0xa000|0o755)
		copy(data[48:], "slnkrhap")
		exts := b.write([]byte(f.Symlink), false)
		dataFork = forkDesc(int64(len(f.Symlink)), exts)
	case f.LinkRef != 0:
		be.PutUint16(data[42:], 0x8000|mode)
		flags |= 0x20
		be.PutUint32(data[44:], f.LinkRef)
		copy(data[48:], "hlnkhfs+")
		dataFork = make([]byte, 80)
	case f.Compress != 0:
		be.PutUint16(data[42:], 0x8000|mode)
		data[41] |= 0x20 // UF_COMPRESSED
		flags |= 0x4
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr, 0x636d7066)
		binary.LittleEndian.PutUint32(hdr[4:], f.Compress)
		binary.LittleEndian.PutUint64(hdr[8:], uint64(len(f.Data)))
		var attr []byte
		switch f.Compress {
		case 3:
			var z bytes.Buffer
			w := zlib.NewWriter(&z)
			w.Write(f.Data)
			w.Close()
			attr = append(hdr, z.Bytes()...)
		case 5:
			attr = append(hdr, make([]byte, 12)...)
		case 4:
			attr = hdr
			rsrc := zlibRsrcFork(f.Data)
			rsrcFork = forkDesc(int64(len(rsrc)), b.write(rsrc, false))
		case 10:
			attr = hdr
			rsrc := rawRsrcFork(f.Data)
			rsrcFork = forkDesc(int64(len(rsrc)), b.write(rsrc, false))
		default:
			panic("hfstest: unsupported decmpfs type")
		}
		if f.Xattrs == nil {
			f.Xattrs = map[string][]byte{}
		}
		f.Xattrs["com.apple.decmpfs"] = attr
		dataFork = make([]byte, 80)
	default:
		be.PutUint16(data[42:], 0x8000|mode)
		exts := b.write(f.Data, f.Fragment)
		dataFork = forkDesc(int64(len(f.Data)), exts)
		if len(exts) > 8 {
			// the tail spills into the overflow tree, eight per record
			var have uint32
			for _, e := range exts[:8] {
				have += e.count
			}
			for i := 8; i < len(exts); i += 8 {
				chunk := exts[i:min(len(exts), i+8)]
				rd := make([]byte, 64)
				for j, e := range chunk {
					be.PutUint32(rd[8*j:], e.start)
					be.PutUint32(rd[8*j+4:], e.count)
				}
				b.overflow = append(b.overflow, rec{key: extKey(0, id, have), data: rd})
				for _, e := range chunk {
					have += e.count
				}
			}
		}
	}
	if rsrcFork == nil {
		rsrcFork = make([]byte, 80)
	}
	if len(f.Xattrs) > 0 {
		flags |= 0x4
		names := make([]string, 0, len(f.Xattrs))
		for n := range f.Xattrs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v := f.Xattrs[n]
			ad := make([]byte, 16+len(v))
			be.PutUint32(ad, 0x10)
			be.PutUint32(ad[12:], uint32(len(v)))
			copy(ad[16:], v)
			b.attrs = append(b.attrs, rec{key: attrKey(id, n, 0), data: ad})
		}
	}
	be.PutUint16(data[2:], flags)
	copy(data[88:], dataFork)
	copy(data[168:], rsrcFork)
	b.catalog = append(b.catalog, rec{key: catKey(parent, f.Name), data: data})
	b.catalog = append(b.catalog, rec{key: catKey(id, ""), data: thread(4, parent, f.Name)})
}

// zlibRsrcFork lays out a type-4 resource fork: 256-byte header, data
// length at 0x100, the chunk table at 0x104, the chunks, a resource map.
func zlibRsrcFork(data []byte) []byte {
	var chunks [][]byte
	for off := 0; off < len(data) || (off == 0 && len(data) == 0); off += 65536 {
		var z bytes.Buffer
		w := zlib.NewWriter(&z)
		w.Write(data[off:min(len(data), off+65536)])
		w.Close()
		chunks = append(chunks, z.Bytes())
		if len(data) == 0 {
			break
		}
	}
	n := len(chunks)
	table := make([]byte, 4+8*n)
	binary.LittleEndian.PutUint32(table, uint32(n))
	var body []byte
	off := uint32(len(table))
	for i, c := range chunks {
		binary.LittleEndian.PutUint32(table[4+8*i:], off)
		binary.LittleEndian.PutUint32(table[8+8*i:], uint32(len(c)))
		body = append(body, c...)
		off += uint32(len(c))
	}
	dataLen := 4 + len(table) + len(body)
	out := make([]byte, 256)
	be.PutUint32(out, 256)
	be.PutUint32(out[4:], uint32(256+dataLen))
	be.PutUint32(out[8:], uint32(dataLen))
	be.PutUint32(out[12:], 50)
	lenField := make([]byte, 4)
	be.PutUint32(lenField, uint32(len(table)+len(body)))
	out = append(out, lenField...)
	out = append(out, table...)
	out = append(out, body...)
	out = append(out, make([]byte, 50)...) // a token resource map
	return out
}

// rawRsrcFork lays out a type-10 resource fork: an offset table whose
// first entry is its own size, then 0xcc-prefixed raw chunks.
func rawRsrcFork(data []byte) []byte {
	n := (len(data) + 65535) / 65536
	if n == 0 {
		n = 1
	}
	table := make([]byte, 4*(n+1))
	off := uint32(len(table))
	var body []byte
	binary.LittleEndian.PutUint32(table, off)
	for i := 0; i < n; i++ {
		chunk := append([]byte{0xcc}, data[i*65536:min(len(data), (i+1)*65536)]...)
		body = append(body, chunk...)
		off += uint32(len(chunk))
		binary.LittleEndian.PutUint32(table[4*(i+1):], off)
	}
	return append(table, body...)
}

// placeFork writes a B-tree file into fresh blocks and returns its descriptor.
func (b *builder) placeFork(tree []byte) []byte {
	exts := b.write(tree, false)
	return forkDesc(int64(len(tree)), exts)
}

// ---- keys -------------------------------------------------------------------------

func utf16be(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		be.PutUint16(out[2*i:], u)
	}
	return out
}

func catKey(parent uint32, name string) []byte {
	n := utf16be(name)
	k := make([]byte, 6+len(n))
	be.PutUint32(k, parent)
	be.PutUint16(k[4:], uint16(len(n)/2))
	copy(k[6:], n)
	return k
}

func extKey(fork byte, id, start uint32) []byte {
	k := make([]byte, 10)
	k[0] = fork
	be.PutUint32(k[2:], id)
	be.PutUint32(k[6:], start)
	return k
}

func attrKey(id uint32, name string, start uint32) []byte {
	n := utf16be(name)
	k := make([]byte, 12+len(n))
	be.PutUint32(k[2:], id)
	be.PutUint32(k[6:], start)
	be.PutUint16(k[10:], uint16(len(n)/2))
	copy(k[12:], n)
	return k
}

func thread(typ uint16, parent uint32, name string) []byte {
	n := utf16be(name)
	d := make([]byte, 10+len(n))
	be.PutUint16(d, typ)
	be.PutUint32(d[4:], parent)
	be.PutUint16(d[8:], uint16(len(n)/2))
	copy(d[10:], n)
	return d
}

// sortRecs orders records the way the tree's comparator does: the key's
// leading integers, then the name's code units (folded to lower case on a
// case-insensitive catalog — the fixtures use names for which that
// ordering agrees with Apple's table).
func sortRecs(recs []rec, binary bool) {
	fold := func(k []byte) []byte {
		if binary {
			return k
		}
		out := append([]byte(nil), k...)
		for i := 6; i+1 < len(out); i += 2 {
			if out[i] == 0 && out[i+1] >= 'A' && out[i+1] <= 'Z' {
				out[i+1] += 'a' - 'A'
			}
		}
		return out
	}
	sort.SliceStable(recs, func(i, j int) bool {
		return bytes.Compare(fold(recs[i].key), fold(recs[j].key)) < 0
	})
}

// sortAttrs orders attribute records by (file id, name, start block) —
// the name before the start block, unlike the key's byte layout.
func sortAttrs(recs []rec) {
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i].key, recs[j].key
		if c := bytes.Compare(a[2:6], b[2:6]); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(a[12:], b[12:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(a[6:10], b[6:10]) < 0
	})
}

// ---- the B-tree file --------------------------------------------------------------

type treeNode struct {
	recs []rec // index nodes: key + 4-byte child
	kind int8
}

// buildTree packs records into leaves, builds index levels up to a root,
// and prepends the header node. Node 0 is the header; leaves follow, then
// each index level.
func buildTree(recs []rec, nodeSize, maxKeyLen int, varIndex bool, keyCompare byte) []byte {
	size := func(r rec, index bool) int {
		kl := len(r.key)
		if index && !varIndex {
			kl = maxKeyLen
		}
		n := 2 + kl
		n += n & 1
		n += len(r.data)
		n += n & 1
		return n
	}
	pack := func(in []rec, index bool) [][]rec {
		var nodes [][]rec
		var cur []rec
		used := 14 + 2 // descriptor + the free-space offset
		for _, r := range in {
			s := size(r, index) + 2
			if len(cur) > 0 && used+s > nodeSize {
				nodes = append(nodes, cur)
				cur, used = nil, 16
			}
			cur = append(cur, r)
			used += s
		}
		if len(cur) > 0 {
			nodes = append(nodes, cur)
		}
		return nodes
	}
	var levels [][][]rec // levels[0] = leaves
	if len(recs) > 0 {
		levels = append(levels, pack(recs, false))
		for len(levels[len(levels)-1]) > 1 {
			below := levels[len(levels)-1]
			var up []rec
			firstNum := uint32(1)
			for _, l := range levels[:len(levels)-1] {
				firstNum += uint32(len(l))
			}
			for i, n := range below {
				child := make([]byte, 4)
				be.PutUint32(child, firstNum+uint32(i))
				up = append(up, rec{key: n[0].key, data: child})
			}
			levels = append(levels, pack(up, true))
		}
	}
	total := 1
	for _, l := range levels {
		total += len(l)
	}
	out := make([]byte, total*nodeSize)
	num := uint32(1)
	var firstLeaf, lastLeaf, root uint32
	leafRecs := 0
	for li, level := range levels {
		index := li > 0
		start := num
		for i, n := range level {
			node := out[int(num)*nodeSize : int(num+1)*nodeSize]
			if i+1 < len(level) {
				be.PutUint32(node, num+1)
			}
			if i > 0 {
				be.PutUint32(node[4:], num-1)
			}
			if index {
				node[8] = 0
			} else {
				node[8] = 0xff
				leafRecs += len(n)
			}
			node[9] = byte(li + 1)
			be.PutUint16(node[10:], uint16(len(n)))
			off := 14
			for j, r := range n {
				be.PutUint16(node[nodeSize-2*(j+1):], uint16(off))
				kl := len(r.key)
				span := kl
				if index && !varIndex {
					span = maxKeyLen
				}
				be.PutUint16(node[off:], uint16(kl))
				copy(node[off+2:], r.key)
				p := 2 + span
				p += p & 1
				copy(node[off+p:], r.data)
				p += len(r.data)
				p += p & 1
				off += p
			}
			be.PutUint16(node[nodeSize-2*(len(n)+1):], uint16(off))
			num++
		}
		if !index {
			firstLeaf, lastLeaf = start, num-1
		}
		root = num - 1
	}
	// the header node
	h := out[:nodeSize]
	h[8] = 1
	be.PutUint16(h[10:], 3)
	rec := h[14:]
	be.PutUint16(rec, uint16(len(levels)))
	be.PutUint32(rec[2:], root)
	be.PutUint32(rec[6:], uint32(leafRecs))
	be.PutUint32(rec[10:], firstLeaf)
	be.PutUint32(rec[14:], lastLeaf)
	be.PutUint16(rec[18:], uint16(nodeSize))
	be.PutUint16(rec[20:], uint16(maxKeyLen))
	be.PutUint32(rec[22:], uint32(total))
	be.PutUint32(rec[26:], 0)
	be.PutUint32(rec[32:], uint32(nodeSize))
	rec[36] = 0
	rec[37] = keyCompare
	attrs := uint32(0x2)
	if varIndex {
		attrs |= 0x4
	}
	be.PutUint32(rec[38:], attrs)
	be.PutUint16(h[nodeSize-2:], 14)
	be.PutUint16(h[nodeSize-4:], 120)
	be.PutUint16(h[nodeSize-6:], 248)
	be.PutUint16(h[nodeSize-8:], uint16(nodeSize-8))
	m := h[248 : nodeSize-8]
	for i := 0; i < total && i/8 < len(m); i++ {
		m[i/8] |= 0x80 >> (i % 8)
	}
	return out
}
