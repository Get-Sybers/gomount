// Package xfs is the clean-room XFS v5 read backend of the fsx seam:
// big-endian superblock and v3 inodes (crtime and bigtime timestamps),
// local/extents/btree data forks, shortform, block and leaf/node
// directories (data blocks only — the leaf index is for writers), and
// inline or block symlinks. Parsed directly over the bounded volume
// ReaderAt; checksums are not verified on this read-only path, magics
// and bounds are.
//
// Feature posture: FTYPE, SPINODES, BIGTIME and META_UUID are handled or
// safely ignorable; NREXT64 (and anything newer this reader does not
// know) is refused rather than misparsed.
package xfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
)

func init() {
	fsx.Register(fsx.Detector{
		Type:  "xfs",
		Probe: func(ra io.ReaderAt, size int64) bool { return probe(ra, size) },
		Open:  func(ra io.ReaderAt, size int64) (fsx.FS, error) { return Open(ra, size) },
	})
}

const (
	sbMagic = 0x58465342 // "XFSB"

	incompatFtype    = 0x1
	incompatSpinodes = 0x2
	incompatMetaUUID = 0x4
	incompatBigtime  = 0x8
	incompatKnown    = incompatFtype | incompatSpinodes | incompatMetaUUID | incompatBigtime

	inodeMagic = 0x494E // "IN"

	fmtLocal   = 1
	fmtExtents = 2
	fmtBtree   = 3

	diflag2Bigtime = 0x8

	sIFMT  = 0xF000
	sIFDIR = 0x4000
	sIFREG = 0x8000
	sIFLNK = 0xA000

	// directory logical space: data blocks live below the leaf offset
	dir2LeafOffset = int64(1) << 35

	dir3DataMagic       = 0x58444433 // "XDD3" multi-block data
	dir3BlockMagic      = 0x58444233 // "XDB3" single-block dir
	dir3DataEntryOffset = 64

	symlinkMagic = 0x58534C4D // "XSLM"
	symlinkHdr   = 56

	bmbtMagic5 = 0x424D4133 // "BMA3"
	btreeHdr5  = 72
)

// FS is one opened XFS volume.
type FS struct {
	ra   io.ReaderAt
	size int64

	blockSize int64
	agBlocks  uint32
	agCount   uint32
	rootIno   uint64
	inodeSize int
	agBlkLog  uint
	inopBlog  uint
	dirBlkLog uint
	hasFtype  bool
	uuid      string
	label     string
}

func probe(ra io.ReaderAt, size int64) bool {
	if size < 512 {
		return false
	}
	b, err := fsx.ReadFull(ra, 0, 4)
	return err == nil && binary.BigEndian.Uint32(b) == sbMagic
}

// Open parses the AG-0 superblock.
func Open(ra io.ReaderAt, size int64) (*FS, error) {
	b, err := fsx.ReadFull(ra, 0, 512)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(b[0:]) != sbMagic {
		return nil, fmt.Errorf("xfs: bad superblock magic")
	}
	f := &FS{ra: ra, size: size}
	f.blockSize = int64(be.Uint32(b[0x04:]))
	f.rootIno = be.Uint64(b[0x38:])
	f.agBlocks = be.Uint32(b[0x54:])
	f.agCount = be.Uint32(b[0x58:])
	version := be.Uint16(b[0x64:])
	f.inodeSize = int(be.Uint16(b[0x68:]))
	f.dirBlkLog = uint(b[0xC0])
	f.agBlkLog = uint(b[0x7C])
	f.inopBlog = uint(b[0x7B])
	if f.blockSize < 512 || f.blockSize > 65536 || f.inodeSize < 256 ||
		f.agBlocks == 0 || f.agCount == 0 {
		return nil, fmt.Errorf("xfs: implausible geometry")
	}
	if version&0xF != 5 {
		return nil, fmt.Errorf("xfs: version %d not supported (v5 only)", version&0xF)
	}
	incompat := be.Uint32(b[0xD8:])
	if unknown := incompat &^ uint32(incompatKnown); unknown != 0 {
		return nil, fmt.Errorf("xfs: unsupported incompat features %#x", unknown)
	}
	f.hasFtype = incompat&incompatFtype != 0
	f.uuid = formatUUID(b[0x20:0x30])
	f.label = strings.TrimRight(string(b[0x6C:0x78]), "\x00")
	if _, err := f.inode(f.rootIno); err != nil {
		return nil, fmt.Errorf("xfs: root inode: %w", err)
	}
	return f, nil
}

func formatUUID(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Info implements fsx.FS.
func (f *FS) Info() fsx.Info {
	return fsx.Info{Type: "xfs", UUID: f.uuid, Label: f.label, BlockSize: f.blockSize}
}

// inoOffset converts an inode number to a byte offset: ino packs
// (agno << (agblklog+inopblog)) | (agbno << inopblog) | slot.
func (f *FS) inoOffset(ino uint64) (int64, error) {
	slotMask := uint64(1)<<f.inopBlog - 1
	agMask := uint64(1)<<(f.agBlkLog+f.inopBlog) - 1
	agno := ino >> (f.agBlkLog + f.inopBlog)
	agbno := (ino & agMask) >> f.inopBlog
	slot := ino & slotMask
	if agno >= uint64(f.agCount) || agbno >= uint64(f.agBlocks) {
		return 0, fmt.Errorf("xfs: inode %d out of range", ino)
	}
	return (int64(agno)*int64(f.agBlocks)+int64(agbno))*f.blockSize + int64(slot)*int64(f.inodeSize), nil
}

// fsbOffset converts a filesystem block number to a byte offset.
func (f *FS) fsbOffset(fsb uint64) (int64, error) {
	agno := fsb >> f.agBlkLog
	agbno := fsb & (uint64(1)<<f.agBlkLog - 1)
	if agno >= uint64(f.agCount) || agbno >= uint64(f.agBlocks) {
		return 0, fmt.Errorf("xfs: block %d out of range", fsb)
	}
	return (int64(agno)*int64(f.agBlocks) + int64(agbno)) * f.blockSize, nil
}

// inode is one parsed v3 inode with its raw fork bytes.
type inode struct {
	ino    uint64
	mode   uint16
	format uint8
	uid    uint32
	gid    uint32
	nlink  uint32
	size   int64

	atime, mtime, ctime, crtime time.Time

	fork []byte // the data fork's literal area
}

func (f *FS) inode(ino uint64) (*inode, error) {
	off, err := f.inoOffset(ino)
	if err != nil {
		return nil, err
	}
	b, err := fsx.ReadFull(f.ra, off, f.inodeSize)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint16(b[0:]) != inodeMagic {
		return nil, fmt.Errorf("xfs: inode %d bad magic", ino)
	}
	if b[0x04] != 3 {
		return nil, fmt.Errorf("xfs: inode %d version %d (v3 only)", ino, b[0x04])
	}
	in := &inode{ino: ino}
	in.mode = be.Uint16(b[0x02:])
	in.format = b[0x05]
	in.uid = be.Uint32(b[0x08:])
	in.gid = be.Uint32(b[0x0C:])
	in.nlink = be.Uint32(b[0x10:])
	in.size = int64(be.Uint64(b[0x38:]))
	bigtime := be.Uint64(b[0x78:])&diflag2Bigtime != 0
	in.atime = xTime(b[0x20:0x28], bigtime)
	in.mtime = xTime(b[0x28:0x30], bigtime)
	in.ctime = xTime(b[0x30:0x38], bigtime)
	in.crtime = xTime(b[0x90:0x98], bigtime)

	forkOff := int(b[0x52]) * 8 // di_forkoff, 8-byte units; 0 = whole area
	forkStart := 0xB0
	forkLen := f.inodeSize - forkStart
	if forkOff > 0 && forkOff <= forkLen {
		forkLen = forkOff
	}
	in.fork = b[forkStart : forkStart+forkLen]
	return in, nil
}

// xTime decodes a v3 timestamp: classic {sec, nsec} pairs, or bigtime's
// unsigned nanoseconds since the pre-1970 epoch shift.
func xTime(b []byte, bigtime bool) time.Time {
	be := binary.BigEndian
	if bigtime {
		v := be.Uint64(b)
		if v == 0 {
			return time.Time{}
		}
		const shift = int64(1) << 31
		sec := int64(v/1e9) - shift
		return time.Unix(sec, int64(v%1e9)).UTC()
	}
	sec := int32(be.Uint32(b[0:]))
	nsec := be.Uint32(b[4:])
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), int64(nsec)).UTC()
}

// ---- extents -----------------------------------------------------------------

// extent is one bmbt mapping.
type extent struct {
	startOff   uint64 // file offset, blocks
	startBlock uint64 // fs block
	count      uint64
}

// unpackExtent decodes one packed 128-bit big-endian bmbt record.
func unpackExtent(b []byte) extent {
	be := binary.BigEndian
	l0, l1 := be.Uint64(b[0:]), be.Uint64(b[8:])
	return extent{
		startOff:   (l0 >> 9) & (1<<54 - 1),
		startBlock: (l0&0x1FF)<<43 | l1>>21,
		count:      l1 & 0x1FFFFF,
	}
}

const maxBtreeDepth = 8

// extents returns the inode's data-fork mappings, walking a btree fork
// when the extent list spilled out of the inode.
func (f *FS) extents(in *inode) ([]extent, error) {
	switch in.format {
	case fmtExtents:
		n := len(in.fork) / 16
		out := make([]extent, 0, n)
		for i := 0; i < n; i++ {
			e := unpackExtent(in.fork[i*16:])
			if e.count == 0 {
				break
			}
			out = append(out, e)
		}
		return out, nil
	case fmtBtree:
		return f.btreeExtents(in.fork, 0)
	default:
		return nil, fmt.Errorf("xfs: inode %d format %d has no extents", in.ino, in.format)
	}
}

// btreeExtents walks a bmbt root (in the inode fork) down to its leaves.
// The root holds {level, numrecs} then keys and pointers split across the
// fork's record capacity.
func (f *FS) btreeExtents(root []byte, depth int) ([]extent, error) {
	if depth > maxBtreeDepth || len(root) < 4 {
		return nil, fmt.Errorf("xfs: bmbt root too deep or short")
	}
	be := binary.BigEndian
	numrecs := int(be.Uint16(root[2:]))
	maxrecs := (len(root) - 4) / 16
	if numrecs > maxrecs {
		return nil, fmt.Errorf("xfs: bmbt root overflow")
	}
	ptrOff := 4 + maxrecs*8
	var out []extent
	for i := 0; i < numrecs; i++ {
		p := ptrOff + i*8
		if p+8 > len(root) {
			return nil, fmt.Errorf("xfs: bmbt root pointer out of fork")
		}
		sub, err := f.btreeNode(be.Uint64(root[p:]), depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	return out, nil
}

// btreeNode reads one on-disk BMA3 block: internal levels recurse, level
// zero yields packed extent records.
func (f *FS) btreeNode(fsb uint64, depth int) ([]extent, error) {
	if depth > maxBtreeDepth {
		return nil, fmt.Errorf("xfs: bmbt too deep")
	}
	off, err := f.fsbOffset(fsb)
	if err != nil {
		return nil, err
	}
	b, err := fsx.ReadFull(f.ra, off, int(f.blockSize))
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(b[0:]) != bmbtMagic5 {
		return nil, fmt.Errorf("xfs: bmbt block %d bad magic", fsb)
	}
	level := int(be.Uint16(b[4:]))
	numrecs := int(be.Uint16(b[6:]))
	if level == 0 {
		if btreeHdr5+numrecs*16 > len(b) {
			return nil, fmt.Errorf("xfs: bmbt leaf overflow")
		}
		out := make([]extent, 0, numrecs)
		for i := 0; i < numrecs; i++ {
			out = append(out, unpackExtent(b[btreeHdr5+i*16:]))
		}
		return out, nil
	}
	maxrecs := (len(b) - btreeHdr5) / 16
	ptrOff := btreeHdr5 + maxrecs*8
	var out []extent
	for i := 0; i < numrecs; i++ {
		p := ptrOff + i*8
		if p+8 > len(b) {
			return nil, fmt.Errorf("xfs: bmbt pointer overflow")
		}
		sub, err := f.btreeNode(be.Uint64(b[p:]), depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	return out, nil
}

// extentReader serves file content over the mappings, holes as zeros.
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
	fblock := uint64(off / bs)
	inBlock := off % bs
	if remain := r.size - off; int64(len(p)) > remain {
		p = p[:remain]
	}
	for _, e := range r.extents {
		if fblock < e.startOff || fblock >= e.startOff+e.count {
			continue
		}
		runBytes := int64(e.startOff+e.count-fblock)*bs - inBlock
		if int64(len(p)) < runBytes {
			runBytes = int64(len(p))
		}
		base, err := r.f.fsbOffset(e.startBlock + (fblock - e.startOff))
		if err != nil {
			return 0, err
		}
		return io.NewSectionReader(r.f.ra, base+inBlock, runBytes).Read(p[:runBytes])
	}
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

type dirent struct {
	ino  uint64
	name string
}

// readDirents lists one directory inode, whatever its form.
func (f *FS) readDirents(in *inode) ([]dirent, error) {
	if in.format == fmtLocal {
		return f.shortformDirents(in.fork)
	}
	exts, err := f.extents(in)
	if err != nil {
		return nil, err
	}
	dirBlkBlocks := int64(1) << f.dirBlkLog
	leafBlock := uint64(dir2LeafOffset / f.blockSize)
	var out []dirent
	buf := make([]byte, f.blockSize*dirBlkBlocks)
	for _, e := range exts {
		if e.startOff >= leafBlock {
			continue // leaf/freeindex space: writer's index, not names
		}
		for blk := uint64(0); blk < e.count; blk += uint64(dirBlkBlocks) {
			off, err := f.fsbOffset(e.startBlock + blk)
			if err != nil {
				return nil, err
			}
			if _, err := io.ReadFull(io.NewSectionReader(f.ra, off, int64(len(buf))), buf); err != nil {
				return nil, err
			}
			ents, err := f.dataBlockDirents(buf)
			if err != nil {
				return nil, err
			}
			out = append(out, ents...)
		}
	}
	return out, nil
}

// shortformDirents parses the inline directory form.
func (f *FS) shortformDirents(fork []byte) ([]dirent, error) {
	if len(fork) < 6 {
		return nil, fmt.Errorf("xfs: shortform dir too small")
	}
	be := binary.BigEndian
	count := int(fork[0])
	i8 := fork[1] != 0
	inoLen := 4
	if i8 {
		inoLen = 8
	}
	pos := 2 + inoLen // header + parent inode
	var out []dirent
	for i := 0; i < count; i++ {
		if pos+3 > len(fork) {
			return nil, fmt.Errorf("xfs: shortform entry overflow")
		}
		nameLen := int(fork[pos])
		pos += 3 // namelen + 2-byte offset tag
		if pos+nameLen > len(fork) {
			return nil, fmt.Errorf("xfs: shortform name overflow")
		}
		name := string(fork[pos : pos+nameLen])
		pos += nameLen
		if f.hasFtype {
			pos++
		}
		if pos+inoLen > len(fork) {
			return nil, fmt.Errorf("xfs: shortform inumber overflow")
		}
		var ino uint64
		if i8 {
			ino = be.Uint64(fork[pos:])
		} else {
			ino = uint64(be.Uint32(fork[pos:]))
		}
		pos += inoLen
		out = append(out, dirent{ino: ino, name: name})
	}
	return out, nil
}

// dataBlockDirents walks one directory data block's entries (XDD3, or the
// data area of a single-block XDB3 dir).
func (f *FS) dataBlockDirents(b []byte) ([]dirent, error) {
	be := binary.BigEndian
	magic := be.Uint32(b[0:])
	end := len(b)
	switch magic {
	case dir3BlockMagic:
		// single-block form: the leaf array + tail live at the block end
		if len(b) < 8 {
			return nil, fmt.Errorf("xfs: block dir too small")
		}
		count := int(be.Uint32(b[len(b)-8:]))
		end = len(b) - 8 - count*8
		if end < dir3DataEntryOffset || end > len(b) {
			return nil, fmt.Errorf("xfs: block dir tail overflow")
		}
	case dir3DataMagic:
	default:
		return nil, fmt.Errorf("xfs: dir data block bad magic %#x", magic)
	}
	var out []dirent
	pos := dir3DataEntryOffset
	for pos+8 <= end {
		if be.Uint16(b[pos:]) == 0xFFFF { // unused: freetag + length
			skip := int(be.Uint16(b[pos+2:]))
			if skip < 8 {
				return nil, fmt.Errorf("xfs: dir unused entry length %d", skip)
			}
			pos += skip
			continue
		}
		ino := be.Uint64(b[pos:])
		if pos+9 > end {
			break
		}
		nameLen := int(b[pos+8])
		entry := 8 + 1 + nameLen + 2 // inumber + namelen + name + tag
		if f.hasFtype {
			entry++
		}
		entry = (entry + 7) &^ 7
		if nameLen == 0 || pos+entry > end {
			break
		}
		out = append(out, dirent{ino: ino, name: string(b[pos+9 : pos+9+nameLen])})
		pos += entry
	}
	return out, nil
}

// ---- symlinks ----------------------------------------------------------------

func (f *FS) readlink(in *inode) (string, error) {
	if in.format == fmtLocal {
		return string(in.fork[:min(int(in.size), len(in.fork))]), nil
	}
	exts, err := f.extents(in)
	if err != nil {
		return "", err
	}
	if in.size > 4096 {
		return "", fmt.Errorf("xfs: implausible symlink length %d", in.size)
	}
	var sb strings.Builder
	remain := in.size
	for _, e := range exts {
		for blk := uint64(0); blk < e.count && remain > 0; blk++ {
			off, err := f.fsbOffset(e.startBlock + blk)
			if err != nil {
				return "", err
			}
			b, err := fsx.ReadFull(f.ra, off, int(f.blockSize))
			if err != nil {
				return "", err
			}
			data := b
			if binary.BigEndian.Uint32(b[0:]) == symlinkMagic {
				data = b[symlinkHdr:]
			}
			n := int64(len(data))
			if n > remain {
				n = remain
			}
			sb.Write(data[:n])
			remain -= n
		}
	}
	return sb.String(), nil
}

// ---- fsx.FS ------------------------------------------------------------------

func (f *FS) entry(in *inode, name, fullPath string) fsx.Entry {
	e := fsx.Entry{
		Name: name, Path: fullPath,
		IsDir: in.mode&sIFMT == sIFDIR,
		Mode:  uint32(in.mode),
		UID:   in.uid, GID: in.gid,
		Inode: in.ino, Nlink: in.nlink,
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

func (f *FS) lookup(p string) (*inode, string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	cur, err := f.inode(f.rootIno)
	if err != nil {
		return nil, "", err
	}
	if clean == "/" {
		return cur, "/", nil
	}
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
			continue
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
		// The icat precedent: a symlink's data IS its target string, and
		// its blocks carry the XSLM header a plain extent read would leak.
		t, err := f.readlink(in)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(t)), nil
	}
	if in.format == fmtLocal {
		n := min(int(in.size), len(in.fork))
		return io.NopCloser(strings.NewReader(string(in.fork[:n]))), nil
	}
	exts, err := f.extents(in)
	if err != nil {
		return nil, err
	}
	r := &extentReader{f: f, extents: exts, size: in.size}
	return io.NopCloser(io.NewSectionReader(r, 0, in.size)), nil
}

const maxWalkDepth = 128

func (f *FS) Walk(fn func(e fsx.Entry, open func() (io.ReadCloser, error)) error) error {
	var walk func(in *inode, dir string, depth int) error
	walk = func(in *inode, dir string, depth int) error {
		if depth > maxWalkDepth {
			return fmt.Errorf("xfs: directory tree too deep at %s", dir)
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
				c := ci
				open = func() (io.ReadCloser, error) { return f.openInode(c) }
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
	root, err := f.inode(f.rootIno)
	if err != nil {
		return err
	}
	return walk(root, "/", 0)
}
