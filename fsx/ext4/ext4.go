// Package ext4 is the clean-room ext2/ext3/ext4 backend of the fsx seam
// (docs/linux §5.1): superblock and group descriptors, 128- and 256-byte
// inodes (crtime and the extra-epoch nanosecond fields when present),
// extent trees and the legacy direct/indirect block maps, inline data,
// fast and slow symlinks, linear and htree directories — all parsed
// directly over the bounded volume io.ReaderAt, every offset checked, no
// third-party filesystem library. The residue seam (§5.5) lives in
// residue.go.
package ext4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/get-sybers/gomount/fsx"
)

func init() {
	fsx.Register(fsx.Detector{
		Type:  "ext4",
		Probe: func(ra io.ReaderAt, size int64) bool { return probe(ra, size) },
		Open:  func(ra io.ReaderAt, size int64) (fsx.FS, error) { return Open(ra, size) },
	})
}

const (
	sbOffset = 1024
	sbMagic  = 0xEF53

	rootIno  = 2
	firstIno = 11 // first non-reserved inode (also sb.s_first_ino on rev1)

	// incompat features this reader understands (or can safely ignore).
	incompatFiletype = 0x0002
	incompatRecover  = 0x0004 // dirty journal: still readable, plan reads dirty
	incompatExtents  = 0x0040
	incompat64Bit    = 0x0080
	incompatMMP      = 0x0100
	incompatFlexBG   = 0x0200
	incompatEAInode  = 0x0400
	incompatCsumSeed = 0x2000
	incompatLargeDir = 0x4000
	incompatInline   = 0x8000
	incompatEncrypt  = 0x10000
	incompatKnown    = incompatFiletype | incompatRecover | incompatExtents |
		incompat64Bit | incompatMMP | incompatFlexBG | incompatEAInode |
		incompatCsumSeed | incompatLargeDir | incompatInline | incompatEncrypt

	// inode flags
	flagExtents = 0x80000
	flagInline  = 0x10000000

	// mode type bits
	sIFMT  = 0xF000
	sIFDIR = 0x4000
	sIFREG = 0x8000
	sIFLNK = 0xA000
)

// FS is one opened ext2/3/4 volume.
type FS struct {
	ra   io.ReaderAt
	size int64

	blockSize      int64
	inodesCount    uint32
	inodeSize      int
	inodesPerGroup uint32
	blocksPerGroup uint32
	firstDataBlock uint32
	groups         int
	descSize       int
	gdtOffset      int64
	featIncompat   uint32
	lastOrphan     uint32
	uuid           string
	label          string
	typ            string
}

// probe checks the 0xEF53 magic at superblock+56.
func probe(ra io.ReaderAt, size int64) bool {
	if size < sbOffset+1024 {
		return false
	}
	b, err := fsx.ReadFull(ra, sbOffset+0x38, 2)
	return err == nil && binary.LittleEndian.Uint16(b) == sbMagic
}

// Open parses the superblock and group descriptor table.
func Open(ra io.ReaderAt, size int64) (*FS, error) {
	sb, err := fsx.ReadFull(ra, sbOffset, 1024)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if le.Uint16(sb[0x38:]) != sbMagic {
		return nil, fmt.Errorf("ext: bad superblock magic")
	}
	f := &FS{ra: ra, size: size}
	f.inodesCount = le.Uint32(sb[0x00:])
	blocksCount := uint64(le.Uint32(sb[0x04:]))
	f.firstDataBlock = le.Uint32(sb[0x14:])
	logBS := le.Uint32(sb[0x18:])
	if logBS > 6 {
		return nil, fmt.Errorf("ext: implausible block size log %d", logBS)
	}
	f.blockSize = int64(1024) << logBS
	f.blocksPerGroup = le.Uint32(sb[0x20:])
	f.inodesPerGroup = le.Uint32(sb[0x28:])
	if f.inodesPerGroup == 0 || f.blocksPerGroup == 0 {
		return nil, fmt.Errorf("ext: zero per-group counts")
	}
	rev := le.Uint32(sb[0x4C:])
	f.inodeSize = 128
	if rev >= 1 {
		f.inodeSize = int(le.Uint16(sb[0x58:]))
	}
	if f.inodeSize < 128 || f.inodeSize > int(f.blockSize) {
		return nil, fmt.Errorf("ext: implausible inode size %d", f.inodeSize)
	}
	f.featIncompat = le.Uint32(sb[0x60:])
	if unknown := f.featIncompat &^ uint32(incompatKnown); unknown != 0 {
		return nil, fmt.Errorf("ext: unsupported incompat features %#x", unknown)
	}
	if f.featIncompat&incompat64Bit != 0 {
		f.descSize = int(le.Uint16(sb[0xFE:]))
		if f.descSize < 64 {
			f.descSize = 64
		}
		blocksCount |= uint64(le.Uint32(sb[0x150:])) << 32 // s_blocks_count_hi
	} else {
		f.descSize = 32
	}
	f.lastOrphan = le.Uint32(sb[0xE8:])
	f.uuid = formatUUID(sb[0x68:0x78])
	f.label = strings.TrimRight(string(sb[0x78:0x88]), "\x00")
	f.groups = int((blocksCount - uint64(f.firstDataBlock) + uint64(f.blocksPerGroup) - 1) / uint64(f.blocksPerGroup))
	if f.groups <= 0 || f.groups > 1<<22 {
		return nil, fmt.Errorf("ext: implausible group count %d", f.groups)
	}
	f.gdtOffset = int64(f.firstDataBlock+1) * f.blockSize
	switch {
	case f.featIncompat&incompatExtents != 0:
		f.typ = "ext4"
	case le.Uint32(sb[0x5C:])&0x0004 != 0: // compat HAS_JOURNAL
		f.typ = "ext3"
	default:
		f.typ = "ext2"
	}
	// Sanity: the root inode must parse.
	if _, err := f.inode(rootIno); err != nil {
		return nil, fmt.Errorf("ext: root inode: %w", err)
	}
	return f, nil
}

func formatUUID(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Info implements fsx.FS.
func (f *FS) Info() fsx.Info {
	return fsx.Info{Type: f.typ, UUID: f.uuid, Label: f.label, BlockSize: f.blockSize}
}

// groupDesc reads one group descriptor's bitmap/table locations.
type groupDesc struct {
	blockBitmap uint64
	inodeBitmap uint64
	inodeTable  uint64
}

func (f *FS) groupDesc(g int) (groupDesc, error) {
	if g < 0 || g >= f.groups {
		return groupDesc{}, fmt.Errorf("ext: group %d out of range", g)
	}
	b, err := fsx.ReadFull(f.ra, f.gdtOffset+int64(g)*int64(f.descSize), f.descSize)
	if err != nil {
		return groupDesc{}, err
	}
	le := binary.LittleEndian
	d := groupDesc{
		blockBitmap: uint64(le.Uint32(b[0x00:])),
		inodeBitmap: uint64(le.Uint32(b[0x04:])),
		inodeTable:  uint64(le.Uint32(b[0x08:])),
	}
	if f.descSize >= 64 {
		d.blockBitmap |= uint64(le.Uint32(b[0x20:])) << 32
		d.inodeBitmap |= uint64(le.Uint32(b[0x24:])) << 32
		d.inodeTable |= uint64(le.Uint32(b[0x28:])) << 32
	}
	return d, nil
}

// inode is one parsed on-disk inode.
type inode struct {
	ino    uint64
	mode   uint16
	uid    uint32
	gid    uint32
	size   int64
	links  uint16
	flags  uint32
	dtime  uint32
	blocks [60]byte // raw i_block area (map, extent root, inline data or fast symlink)

	atime, ctime, mtime, crtime time.Time
}

func (f *FS) inode(ino uint64) (*inode, error) {
	if ino == 0 || ino > uint64(f.inodesCount) {
		return nil, fmt.Errorf("ext: inode %d out of range", ino)
	}
	g := int((ino - 1) / uint64(f.inodesPerGroup))
	idx := (ino - 1) % uint64(f.inodesPerGroup)
	d, err := f.groupDesc(g)
	if err != nil {
		return nil, err
	}
	off := int64(d.inodeTable)*f.blockSize + int64(idx)*int64(f.inodeSize)
	b, err := fsx.ReadFull(f.ra, off, f.inodeSize)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	in := &inode{ino: ino}
	in.mode = le.Uint16(b[0x00:])
	in.uid = uint32(le.Uint16(b[0x02:]))
	in.gid = uint32(le.Uint16(b[0x18:]))
	in.size = int64(le.Uint32(b[0x04:]))
	in.links = le.Uint16(b[0x1A:])
	in.flags = le.Uint32(b[0x20:])
	in.dtime = le.Uint32(b[0x14:])
	copy(in.blocks[:], b[0x28:0x28+60])
	if in.mode&sIFMT == sIFREG {
		in.size |= int64(le.Uint32(b[0x6C+8:])) << 32 // i_size_high
	}
	// osd2 (linux): uid/gid high halves.
	in.uid |= uint32(le.Uint16(b[0x78:])) << 16
	in.gid |= uint32(le.Uint16(b[0x7A:])) << 16

	atime, ctime, mtime := le.Uint32(b[0x08:]), le.Uint32(b[0x0C:]), le.Uint32(b[0x10:])
	var aX, cX, mX, crt, crtX uint32
	if f.inodeSize > 128 {
		extra := int(le.Uint16(b[0x80:]))
		has := func(end int) bool { return end <= 128+extra && end <= f.inodeSize }
		if has(0x88) {
			cX = le.Uint32(b[0x84:])
		}
		if has(0x8C) {
			mX = le.Uint32(b[0x88:])
		}
		if has(0x90) {
			aX = le.Uint32(b[0x8C:])
		}
		if has(0x98) {
			crt = le.Uint32(b[0x90:])
			crtX = le.Uint32(b[0x94:])
		}
	}
	in.atime = extTime(atime, aX)
	in.ctime = extTime(ctime, cX)
	in.mtime = extTime(mtime, mX)
	in.crtime = extTime(crt, crtX)
	return in, nil
}

// extTime decodes an ext timestamp with its extra field: the low two bits
// of extra extend the epoch (past 2038), the rest are nanoseconds. A zero
// pair is an honest zero time.
func extTime(sec, extra uint32) time.Time {
	if sec == 0 && extra == 0 {
		return time.Time{}
	}
	s := int64(sec) + int64(extra&0x3)<<32
	return time.Unix(s, int64(extra>>2)).UTC()
}

// ---- block maps --------------------------------------------------------------

// blockReader returns an io.ReaderAt over the inode's data, holes reading
// as zeros, plus the data length.
func (f *FS) blockReader(in *inode) (io.ReaderAt, int64, error) {
	if in.flags&flagInline != 0 {
		// Inline data: the first 60 bytes live in i_block; a tail past 60
		// bytes would live in the xattr area — out of scope, so the
		// addressable prefix is what we honestly serve, and the returned
		// length is the PREFIX's, so reads succeed over exactly what
		// exists (Stat still reports the inode's true size).
		n := in.size
		if n > 60 {
			n = 60
		}
		return bytes.NewReader(in.blocks[:n]), n, nil
	}
	var extents []extent
	var err error
	if in.flags&flagExtents != 0 {
		extents, err = f.extentList(in.blocks[:], 0)
	} else {
		extents, err = f.legacyList(in)
	}
	if err != nil {
		return nil, 0, err
	}
	return &extentReader{f: f, extents: extents, size: in.size}, in.size, nil
}

// extent is one contiguous mapping: file block lblock, disk block pblock,
// count blocks.
type extent struct {
	lblock uint64
	pblock uint64
	count  uint64
}

const maxExtentDepth = 8

// extentList walks an extent tree node (the inode's 60-byte root or a
// block-sized node) into a flat mapping list.
func (f *FS) extentList(node []byte, depth int) ([]extent, error) {
	if depth > maxExtentDepth {
		return nil, fmt.Errorf("ext: extent tree too deep")
	}
	le := binary.LittleEndian
	if len(node) < 12 || le.Uint16(node[0:]) != 0xF30A {
		return nil, fmt.Errorf("ext: bad extent header magic")
	}
	entries := int(le.Uint16(node[2:]))
	nodeDepth := int(le.Uint16(node[6:]))
	if 12+entries*12 > len(node) {
		return nil, fmt.Errorf("ext: extent entries overflow node")
	}
	var out []extent
	for i := 0; i < entries; i++ {
		e := node[12+i*12 : 24+i*12]
		if nodeDepth == 0 {
			l := uint64(le.Uint32(e[0:]))
			ln := uint64(le.Uint16(e[4:]))
			if ln > 32768 { // unwritten extent: length is len-32768, reads as data (zeros on disk region is fine to expose)
				ln -= 32768
			}
			p := uint64(le.Uint16(e[6:]))<<32 | uint64(le.Uint32(e[8:]))
			out = append(out, extent{lblock: l, pblock: p, count: ln})
			continue
		}
		leaf := uint64(le.Uint32(e[4:])) | uint64(le.Uint16(e[8:]))<<32
		child, err := f.readBlock(leaf)
		if err != nil {
			return nil, err
		}
		sub, err := f.extentList(child, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	return out, nil
}

// legacyList flattens the classic 12-direct + 3-indirect block map.
func (f *FS) legacyList(in *inode) ([]extent, error) {
	perBlock := f.blockSize / 4
	nBlocks := (in.size + f.blockSize - 1) / f.blockSize
	le := binary.LittleEndian
	var out []extent
	lblock := uint64(0)
	add := func(p uint32) {
		// Coalesce runs so the extent list stays small.
		if n := len(out); n > 0 && p != 0 &&
			out[n-1].pblock+out[n-1].count == uint64(p) &&
			out[n-1].lblock+out[n-1].count == lblock {
			out[n-1].count++
		} else if p != 0 {
			out = append(out, extent{lblock: lblock, pblock: uint64(p), count: 1})
		}
		lblock++
	}
	var walkIndirect func(blk uint32, level int) error
	walkIndirect = func(blk uint32, level int) error {
		if int64(lblock) >= nBlocks {
			return nil
		}
		if blk == 0 { // a hole spanning the whole indirect range
			span := int64(1)
			for i := 0; i < level; i++ {
				span *= perBlock
			}
			lblock += uint64(span)
			return nil
		}
		b, err := f.readBlock(uint64(blk))
		if err != nil {
			return err
		}
		for i := int64(0); i < perBlock && int64(lblock) < nBlocks; i++ {
			p := le.Uint32(b[i*4:])
			if level == 1 {
				add(p)
			} else if err := walkIndirect(p, level-1); err != nil {
				return err
			}
		}
		return nil
	}
	blocks := in.blocks[:]
	for i := 0; i < 12 && int64(lblock) < nBlocks; i++ {
		add(le.Uint32(blocks[i*4:]))
	}
	for level := 1; level <= 3 && int64(lblock) < nBlocks; level++ {
		if err := walkIndirect(le.Uint32(blocks[(11+level)*4:]), level); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (f *FS) readBlock(blk uint64) ([]byte, error) {
	off := int64(blk) * f.blockSize
	if off <= 0 || off+f.blockSize > f.size {
		return nil, fmt.Errorf("ext: block %d out of volume", blk)
	}
	return fsx.ReadFull(f.ra, off, int(f.blockSize))
}

// extentReader serves ReadAt over an extent list, holes as zeros.
type extentReader struct {
	f       *FS
	extents []extent
	size    int64
}

func (r *extentReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) && off < r.size {
		n, err := r.readOnce(p[total:], off)
		total += n
		off += int64(n)
		if err != nil {
			return total, err
		}
	}
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

func (r *extentReader) readOnce(p []byte, off int64) (int, error) {
	bs := r.f.blockSize
	lblock := uint64(off / bs)
	inBlock := off % bs
	remain := r.size - off
	if int64(len(p)) > remain {
		p = p[:remain]
	}
	for _, e := range r.extents {
		if lblock < e.lblock || lblock >= e.lblock+e.count {
			continue
		}
		// contiguous mapped run from lblock to extent end
		runBytes := int64(e.lblock+e.count-lblock)*bs - inBlock
		if int64(len(p)) < runBytes {
			runBytes = int64(len(p))
		}
		diskOff := int64(e.pblock+(lblock-e.lblock))*bs + inBlock
		if diskOff < 0 || diskOff+runBytes > r.f.size {
			return 0, fmt.Errorf("ext: mapped read out of volume")
		}
		return io.NewSectionReader(r.f.ra, diskOff, runBytes).Read(p[:runBytes])
	}
	// hole: zeros to the end of this block
	hole := bs - inBlock
	if int64(len(p)) < hole {
		hole = int64(len(p))
	}
	for i := int64(0); i < hole; i++ {
		p[i] = 0
	}
	return int(hole), nil
}

// ---- directories -------------------------------------------------------------

// dirent is one live directory entry.
type dirent struct {
	ino      uint64
	name     string
	fileType byte
}

// readDirents linearly scans every block of a directory inode. htree
// interior blocks self-skip (their fake entry has inode 0), so one scan
// serves linear, htree and largedir layouts alike.
func (f *FS) readDirents(in *inode) ([]dirent, error) {
	ra, size, err := f.blockReader(in)
	if err != nil {
		return nil, err
	}
	var out []dirent
	buf := make([]byte, f.blockSize)
	for off := int64(0); off < size; off += f.blockSize {
		n, err := ra.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			return nil, err
		}
		parseDirentBlock(buf[:n], func(d dirent) { out = append(out, d) }, nil)
	}
	return out, nil
}

// parseDirentBlock walks one directory block's live entries; slack, when
// non-nil, receives each live entry's trailing gap for residue scanning
// (residue.go).
func parseDirentBlock(b []byte, live func(dirent), slack func(gap []byte, prevEnd int)) {
	le := binary.LittleEndian
	off := 0
	for off+8 <= len(b) {
		ino := uint64(le.Uint32(b[off:]))
		recLen := int(le.Uint16(b[off+4:]))
		nameLen := int(b[off+6])
		ftype := b[off+7]
		if recLen < 8 || recLen%4 != 0 || off+recLen > len(b) {
			return // corrupt tail: stop this block
		}
		used := 8 + nameLen
		if ino != 0 && nameLen > 0 && used <= recLen {
			name := string(b[off+8 : off+8+nameLen])
			live(dirent{ino: ino, name: name, fileType: ftype})
		}
		if slack != nil {
			start := off + ((used + 3) &^ 3)
			if ino == 0 {
				start = off + 8 // an unused slot's whole body is slack
			}
			if start < off+recLen {
				slack(b[start:off+recLen], start)
			}
		}
		off += recLen
	}
}

// lookup resolves one path from the root, case-sensitively.
func (f *FS) lookup(p string) (*inode, string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	in, err := f.inode(rootIno)
	if err != nil {
		return nil, "", err
	}
	if clean == "/" {
		return in, "/", nil
	}
	cur := in
	for _, comp := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if cur.mode&sIFMT != sIFDIR {
			return nil, "", fmt.Errorf("%s: not a directory", clean)
		}
		ents, err := f.readDirents(cur)
		if err != nil {
			return nil, "", err
		}
		var next uint64
		for _, d := range ents {
			if d.name == comp {
				next = d.ino
				break
			}
		}
		if next == 0 {
			return nil, "", fmt.Errorf("%s: no such file or directory", clean)
		}
		if cur, err = f.inode(next); err != nil {
			return nil, "", err
		}
	}
	return cur, clean, nil
}

// entry shapes an inode (+ its name/path) into the fsx view.
func (f *FS) entry(in *inode, name, fullPath string) fsx.Entry {
	e := fsx.Entry{
		Name: name, Path: fullPath,
		IsDir: in.mode&sIFMT == sIFDIR,
		Mode:  uint32(in.mode),
		UID:   in.uid, GID: in.gid,
		Inode: in.ino, Nlink: uint32(in.links),
		Size:      in.size,
		Allocated: true,
		Btime:     in.crtime, Mtime: in.mtime, Atime: in.atime, Ctime: in.ctime,
	}
	if in.mode&sIFMT == sIFLNK {
		if t, err := f.readlink(in); err == nil {
			e.LinkTarget = t
		}
	}
	return e
}

// readlink returns the symlink target: fast (in i_block) or via the map.
func (f *FS) readlink(in *inode) (string, error) {
	if in.size < 60 && in.flags&flagExtents == 0 && in.flags&flagInline == 0 {
		return string(in.blocks[:in.size]), nil
	}
	ra, size, err := f.blockReader(in)
	if err != nil {
		return "", err
	}
	if size > 4096 {
		return "", fmt.Errorf("ext: implausible symlink length %d", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(ra, 0, size), b); err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- fsx.FS ------------------------------------------------------------------

func (f *FS) ReadDir(dir string) ([]fsx.Entry, error) {
	in, clean, err := f.lookup(dir)
	if err != nil {
		return nil, err
	}
	if in.mode&sIFMT != sIFDIR {
		return nil, fmt.Errorf("%s: not a directory", clean)
	}
	ents, err := f.readDirents(in)
	if err != nil {
		return nil, err
	}
	var out []fsx.Entry
	for _, d := range ents {
		if d.name == "." || d.name == ".." {
			continue
		}
		ci, err := f.inode(d.ino)
		if err != nil {
			continue // an unreadable child never hides its siblings
		}
		out = append(out, f.entry(ci, d.name, path.Join(clean, d.name)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *FS) Stat(p string) (fsx.Entry, error) {
	in, clean, err := f.lookup(p)
	if err != nil {
		return fsx.Entry{}, err
	}
	return f.entry(in, path.Base(clean), clean), nil
}

func (f *FS) Open(p string) (io.ReadCloser, error) {
	in, clean, err := f.lookup(p)
	if err != nil {
		return nil, err
	}
	if in.mode&sIFMT == sIFDIR {
		return nil, fmt.Errorf("%s: is a directory", clean)
	}
	return f.openInode(in)
}

func (f *FS) openInode(in *inode) (io.ReadCloser, error) {
	if in.mode&sIFMT == sIFLNK {
		// The icat precedent: a symlink's data IS its target string — a
		// fast symlink's i_block holds text, never block pointers.
		t, err := f.readlink(in)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(t)), nil
	}
	ra, size, err := f.blockReader(in)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(ra, 0, size)), nil
}

const maxWalkDepth = 128

// Walk streams every entry depth-first from the root.
func (f *FS) Walk(fn func(e fsx.Entry, open func() (io.ReadCloser, error)) error) error {
	var walk func(in *inode, dir string, depth int) error
	walk = func(in *inode, dir string, depth int) error {
		if depth > maxWalkDepth {
			return fmt.Errorf("ext: directory tree too deep at %s", dir)
		}
		ents, err := f.readDirents(in)
		if err != nil {
			return err
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].name < ents[j].name })
		for _, d := range ents {
			if d.name == "." || d.name == ".." {
				continue
			}
			ci, err := f.inode(d.ino)
			if err != nil {
				continue
			}
			e := f.entry(ci, d.name, path.Join(dir, d.name))
			var open func() (io.ReadCloser, error)
			if ci.mode&sIFMT == sIFREG {
				ciCopy := ci
				open = func() (io.ReadCloser, error) { return f.openInode(ciCopy) }
			}
			if err := fn(e, open); err != nil {
				return err
			}
			if e.IsDir {
				if err := walk(ci, e.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	root, err := f.inode(rootIno)
	if err != nil {
		return err
	}
	return walk(root, "/", 0)
}
