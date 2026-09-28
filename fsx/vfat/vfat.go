// Package vfat is the clean-room FAT12/16/32 backend of the fsx seam:
// BPB geometry, the packed FAT12 / FAT16 / FAT32 allocation tables,
// fixed and cluster-chained root directories, 8.3 names with their VFAT
// long-name entries, and DOS timestamps decoded exactly as stored (FAT
// keeps local wall-clock time with no zone; the entry carries it
// naive-as-UTC and the knowledge store's zone is the parsers' business).
// Deleted (0xE5) entries surface through the residue seam as
// deleted_dirent rows, their long names reassembled from the deleted LFN
// chain when it survives.
package vfat

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/get-sybers/gomount/fsx"
)

func init() {
	fsx.Register(fsx.Detector{
		Type:  "vfat",
		Probe: func(ra io.ReaderAt, size int64) bool { return probe(ra, size) },
		Open:  func(ra io.ReaderAt, size int64) (fsx.FS, error) { return Open(ra, size) },
	})
}

const (
	attrReadOnly = 0x01
	attrHidden   = 0x02
	attrSystem   = 0x04
	attrLabel    = 0x08
	attrDir      = 0x10
	attrLFN      = 0x0F

	entryEnd     = 0x00
	entryDeleted = 0xE5
)

// FS is one opened FAT volume.
type FS struct {
	ra   io.ReaderAt
	size int64

	fatType       int // 12, 16 or 32
	bytesPerSec   int64
	secPerCluster int64
	fatOffset     int64 // bytes
	fatSize       int64 // bytes, one FAT
	rootOffset    int64 // FAT12/16 fixed root dir, bytes
	rootEntries   int
	rootCluster   uint32 // FAT32
	dataOffset    int64  // bytes, cluster 2
	clusterCount  uint32
	uuid          string
	label         string
}

// probe accepts a plausible FAT BPB and rejects NTFS (whose boot sector
// also ends 0x55AA and carries a BPB).
func probe(ra io.ReaderAt, size int64) bool {
	if size < 512 {
		return false
	}
	b, err := fsx.ReadFull(ra, 0, 512)
	if err != nil {
		return false
	}
	if b[510] != 0x55 || b[511] != 0xAA {
		return false
	}
	if string(b[3:11]) == "NTFS    " {
		return false
	}
	if b[0] != 0xEB && b[0] != 0xE9 {
		return false
	}
	bps := int64(binary.LittleEndian.Uint16(b[0x0B:]))
	spc := b[0x0D]
	if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) ||
		spc == 0 || spc&(spc-1) != 0 {
		return false
	}
	nFats := b[0x10]
	return nFats >= 1 && nFats <= 2
}

// Open parses the BPB and derives the canonical FAT type from the data
// cluster count.
func Open(ra io.ReaderAt, size int64) (*FS, error) {
	b, err := fsx.ReadFull(ra, 0, 512)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	f := &FS{ra: ra, size: size}
	f.bytesPerSec = int64(le.Uint16(b[0x0B:]))
	f.secPerCluster = int64(b[0x0D])
	if f.bytesPerSec == 0 || f.secPerCluster == 0 {
		return nil, fmt.Errorf("vfat: zero geometry")
	}
	reserved := int64(le.Uint16(b[0x0E:]))
	nFats := int64(b[0x10])
	f.rootEntries = int(le.Uint16(b[0x11:]))
	totalSec := int64(le.Uint16(b[0x13:]))
	if totalSec == 0 {
		totalSec = int64(le.Uint32(b[0x20:]))
	}
	fatSecs := int64(le.Uint16(b[0x16:]))
	if fatSecs == 0 {
		fatSecs = int64(le.Uint32(b[0x24:]))
	}
	if totalSec == 0 || fatSecs == 0 || nFats == 0 {
		return nil, fmt.Errorf("vfat: implausible BPB")
	}
	f.fatOffset = reserved * f.bytesPerSec
	f.fatSize = fatSecs * f.bytesPerSec
	rootDirSecs := (int64(f.rootEntries)*32 + f.bytesPerSec - 1) / f.bytesPerSec
	rootStart := reserved + nFats*fatSecs
	f.rootOffset = rootStart * f.bytesPerSec
	dataStart := rootStart + rootDirSecs
	f.dataOffset = dataStart * f.bytesPerSec
	dataSecs := totalSec - dataStart
	if dataSecs <= 0 {
		return nil, fmt.Errorf("vfat: no data region")
	}
	f.clusterCount = uint32(dataSecs / f.secPerCluster)
	switch {
	case f.clusterCount < 4085:
		f.fatType = 12
	case f.clusterCount < 65525:
		f.fatType = 16
	default:
		f.fatType = 32
	}
	if f.fatType == 32 {
		f.rootCluster = le.Uint32(b[0x2C:])
		if b[0x42] == 0x29 {
			f.uuid = serial(le.Uint32(b[0x43:]))
			f.label = strings.TrimRight(string(b[0x47:0x52]), " ")
		}
	} else if b[0x26] == 0x29 {
		f.uuid = serial(le.Uint32(b[0x27:]))
		f.label = strings.TrimRight(string(b[0x2B:0x36]), " ")
	}
	// The root volume-label entry, when present, is the canonical label.
	if ents, _, err := f.readDirRegion(f.rootRegion()); err == nil {
		for _, e := range ents {
			if e.attr&attrLabel != 0 && e.attr&attrLFN != attrLFN {
				f.label = strings.TrimRight(e.shortRaw, " ")
			}
		}
	}
	return f, nil
}

func serial(v uint32) string { return fmt.Sprintf("%04X-%04X", v>>16, v&0xFFFF) }

// Info implements fsx.FS.
func (f *FS) Info() fsx.Info {
	return fsx.Info{
		Type: "vfat", UUID: f.uuid, Label: f.label,
		BlockSize: f.bytesPerSec * f.secPerCluster,
	}
}

// fatEntry reads one FAT slot.
func (f *FS) fatEntry(cluster uint32) (uint32, error) {
	switch f.fatType {
	case 12:
		off := f.fatOffset + int64(cluster) + int64(cluster)/2
		b, err := fsx.ReadFull(f.ra, off, 2)
		if err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint16(b)
		if cluster&1 == 1 {
			return uint32(v >> 4), nil
		}
		return uint32(v & 0x0FFF), nil
	case 16:
		b, err := fsx.ReadFull(f.ra, f.fatOffset+int64(cluster)*2, 2)
		if err != nil {
			return 0, err
		}
		return uint32(binary.LittleEndian.Uint16(b)), nil
	default:
		b, err := fsx.ReadFull(f.ra, f.fatOffset+int64(cluster)*4, 4)
		if err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint32(b) & 0x0FFFFFFF, nil
	}
}

func (f *FS) isEOC(v uint32) bool {
	switch f.fatType {
	case 12:
		return v >= 0xFF8
	case 16:
		return v >= 0xFFF8
	default:
		return v >= 0x0FFFFFF8
	}
}

func (f *FS) clusterOffset(cluster uint32) int64 {
	return f.dataOffset + int64(cluster-2)*f.secPerCluster*f.bytesPerSec
}

// chain returns the cluster list of a file, bounded against loops.
func (f *FS) chain(start uint32) ([]uint32, error) {
	if start < 2 {
		return nil, nil
	}
	var out []uint32
	cur := start
	for range f.clusterCount + 2 {
		if cur < 2 || cur >= f.clusterCount+2 {
			break
		}
		out = append(out, cur)
		next, err := f.fatEntry(cur)
		if err != nil {
			return out, err
		}
		if f.isEOC(next) || next == 0 {
			break
		}
		cur = next
	}
	return out, nil
}

// region is either a fixed byte range (FAT12/16 root) or a cluster chain.
type region struct {
	fixedOff int64
	fixedLen int64
	chain    []uint32
}

func (f *FS) rootRegion() region {
	if f.fatType == 32 {
		ch, _ := f.chain(f.rootCluster)
		return region{chain: ch}
	}
	return region{fixedOff: f.rootOffset, fixedLen: int64(f.rootEntries) * 32}
}

// maxDirRegion bounds a directory's byte size: FAT directories are entry
// tables, and a chain claiming more than this is a crafted or corrupt
// filesystem, not a bigger directory.
const maxDirRegion = 16 << 20

func (f *FS) regionBytes(r region) ([]byte, error) {
	if r.chain == nil {
		if r.fixedLen > maxDirRegion {
			return nil, fmt.Errorf("vfat: directory region %d bytes over cap", r.fixedLen)
		}
		return fsx.ReadFull(f.ra, r.fixedOff, int(r.fixedLen))
	}
	cs := f.secPerCluster * f.bytesPerSec
	total := int64(len(r.chain)) * cs
	if total > maxDirRegion {
		return nil, fmt.Errorf("vfat: directory chain %d bytes over cap", total)
	}
	out := make([]byte, 0, total)
	for _, c := range r.chain {
		b, err := fsx.ReadFull(f.ra, f.clusterOffset(c), int(cs))
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// rawEntry is one parsed 32-byte directory slot (live or deleted).
type rawEntry struct {
	name     string // long name when present, else decoded 8.3
	shortRaw string // the 11 raw name bytes
	attr     byte
	cluster  uint32
	size     uint32
	deleted  bool

	btime, mtime, atime time.Time
}

// readDirRegion parses a directory region into live entries and deleted
// (0xE5) residue entries.
func (f *FS) readDirRegion(r region) (live, deleted []rawEntry, err error) {
	b, err := f.regionBytes(r)
	if err != nil {
		return nil, nil, err
	}
	var lfn []uint16    // accumulating live LFN name (built backwards)
	var lfnDel []uint16 // accumulating deleted LFN name
	for off := 0; off+32 <= len(b); off += 32 {
		e := b[off : off+32]
		switch e[0] {
		case entryEnd:
			return live, deleted, nil
		case entryDeleted:
			if e[11]&attrLFN == attrLFN {
				lfnDel = append(lfnPart(e), lfnDel...)
				continue
			}
			re := parseRaw(e)
			re.deleted = true
			if len(lfnDel) > 0 {
				re.name = decodeLFN(lfnDel)
				lfnDel = nil
			} else if len(re.name) > 0 {
				// The 0xE5 marker overwrote the first 8.3 byte; "_" is the
				// honest placeholder for the lost character.
				re.name = "_" + re.name[1:]
			}
			deleted = append(deleted, re)
			continue
		}
		if e[11]&attrLFN == attrLFN {
			lfn = append(lfnPart(e), lfn...)
			continue
		}
		re := parseRaw(e)
		if len(lfn) > 0 {
			re.name = decodeLFN(lfn)
			lfn = nil
		}
		lfnDel = nil
		live = append(live, re)
	}
	return live, deleted, nil
}

// lfnPart extracts the 13 UTF-16 units of one LFN slot.
func lfnPart(e []byte) []uint16 {
	var u []uint16
	for _, span := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for i := span[0]; i < span[1]; i += 2 {
			v := binary.LittleEndian.Uint16(e[i:])
			if v == 0x0000 || v == 0xFFFF {
				return u
			}
			u = append(u, v)
		}
	}
	return u
}

func decodeLFN(u []uint16) string { return string(utf16.Decode(u)) }

// parseRaw decodes one 8.3 slot (times, cluster, size, cased short name).
func parseRaw(e []byte) rawEntry {
	le := binary.LittleEndian
	base := strings.TrimRight(string(e[0:8]), " ")
	ext := strings.TrimRight(string(e[8:11]), " ")
	caseFlags := e[12]
	if caseFlags&0x08 != 0 {
		base = strings.ToLower(base)
	}
	if caseFlags&0x10 != 0 {
		ext = strings.ToLower(ext)
	}
	name := base
	if ext != "" {
		name = base + "." + ext
	}
	cluster := uint32(le.Uint16(e[0x1A:])) | uint32(le.Uint16(e[0x14:]))<<16
	return rawEntry{
		name:     name,
		shortRaw: string(e[0:11]),
		attr:     e[11],
		cluster:  cluster,
		size:     le.Uint32(e[0x1C:]),
		btime:    dosTime(le.Uint16(e[0x10:]), le.Uint16(e[0x0E:]), e[0x0D]),
		mtime:    dosTime(le.Uint16(e[0x18:]), le.Uint16(e[0x16:]), 0),
		atime:    dosTime(le.Uint16(e[0x12:]), 0, 0),
	}
}

// dosTime decodes the packed FAT date/time (+ 10ms create units). A zero
// date is an honest zero time.
func dosTime(date, tim uint16, tenth byte) time.Time {
	if date == 0 {
		return time.Time{}
	}
	year := 1980 + int(date>>9)
	month := int(date>>5) & 0xF
	day := int(date) & 0x1F
	hour := int(tim >> 11)
	min := int(tim>>5) & 0x3F
	sec := int(tim&0x1F)*2 + int(tenth)/100
	ns := (int(tenth) % 100) * 10 * int(time.Millisecond)
	return time.Date(year, time.Month(month), day, hour, min, sec, ns, time.UTC)
}

// entry maps a rawEntry onto the fsx view.
func (f *FS) entry(re rawEntry, dir string) fsx.Entry {
	return fsx.Entry{
		Name:      re.name,
		Path:      path.Join(dir, re.name),
		IsDir:     re.attr&attrDir != 0,
		Inode:     uint64(re.cluster),
		Size:      int64(re.size),
		Allocated: !re.deleted,
		Btime:     re.btime, Mtime: re.mtime, Atime: re.atime,
	}
}

// dirRegionFor returns the region of a directory rawEntry.
func (f *FS) dirRegionFor(re rawEntry) region {
	ch, _ := f.chain(re.cluster)
	return region{chain: ch}
}

func skipEntry(re rawEntry) bool {
	return re.attr&attrLabel != 0 || re.name == "." || re.name == ".." || re.name == ""
}

// lookup resolves a path case-insensitively (FAT name semantics).
func (f *FS) lookup(p string) (rawEntry, region, string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	cur := f.rootRegion()
	// A synthetic entry for the root itself.
	rootEnt := rawEntry{name: "/", attr: attrDir}
	if clean == "/" {
		return rootEnt, cur, "/", nil
	}
	ent := rootEnt
	for _, comp := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if ent.attr&attrDir == 0 {
			return rawEntry{}, region{}, "", fmt.Errorf("%s: not a directory", clean)
		}
		live, _, err := f.readDirRegion(cur)
		if err != nil {
			return rawEntry{}, region{}, "", err
		}
		found := false
		for _, re := range live {
			if skipEntry(re) {
				continue
			}
			if strings.EqualFold(re.name, comp) {
				ent, found = re, true
				break
			}
		}
		if !found {
			return rawEntry{}, region{}, "", fmt.Errorf("%s: no such file or directory", clean)
		}
		cur = f.dirRegionFor(ent)
	}
	return ent, cur, clean, nil
}

// ---- fsx.FS ------------------------------------------------------------------

func (f *FS) ReadDir(dir string) ([]fsx.Entry, error) {
	ent, reg, clean, err := f.lookup(dir)
	if err != nil {
		return nil, err
	}
	if ent.attr&attrDir == 0 {
		return nil, fmt.Errorf("%s: not a directory", clean)
	}
	live, _, err := f.readDirRegion(reg)
	if err != nil {
		return nil, err
	}
	var out []fsx.Entry
	for _, re := range live {
		if skipEntry(re) {
			continue
		}
		out = append(out, f.entry(re, clean))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *FS) Stat(p string) (fsx.Entry, error) {
	ent, _, clean, err := f.lookup(p)
	if err != nil {
		return fsx.Entry{}, err
	}
	if clean == "/" {
		return fsx.Entry{Name: "/", Path: "/", IsDir: true, Allocated: true}, nil
	}
	return f.entry(ent, path.Dir(clean)), nil
}

func (f *FS) Open(p string) (io.ReadCloser, error) {
	ent, _, clean, err := f.lookup(p)
	if err != nil {
		return nil, err
	}
	if ent.attr&attrDir != 0 {
		return nil, fmt.Errorf("%s: is a directory", clean)
	}
	return f.openRaw(ent)
}

func (f *FS) openRaw(re rawEntry) (io.ReadCloser, error) {
	ch, err := f.chain(re.cluster)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(&chainReader{f: f, chain: ch, size: int64(re.size)}), nil
}

// chainReader streams a cluster chain up to the entry's size.
type chainReader struct {
	f     *FS
	chain []uint32
	size  int64
	pos   int64
}

func (r *chainReader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	cs := r.f.secPerCluster * r.f.bytesPerSec
	idx := r.pos / cs
	if idx >= int64(len(r.chain)) {
		return 0, io.ErrUnexpectedEOF // chain shorter than the declared size
	}
	inCluster := r.pos % cs
	n := cs - inCluster
	if remain := r.size - r.pos; n > remain {
		n = remain
	}
	if int64(len(p)) < n {
		n = int64(len(p))
	}
	off := r.f.clusterOffset(r.chain[idx]) + inCluster
	m, err := io.NewSectionReader(r.f.ra, off, n).Read(p[:n])
	r.pos += int64(m)
	return m, err
}

const maxWalkDepth = 128

// Walk streams every live entry depth-first from the root.
func (f *FS) Walk(fn func(e fsx.Entry, open func() (io.ReadCloser, error)) error) error {
	var walk func(reg region, dir string, depth int) error
	walk = func(reg region, dir string, depth int) error {
		if depth > maxWalkDepth {
			return fmt.Errorf("vfat: directory tree too deep at %s", dir)
		}
		live, _, err := f.readDirRegion(reg)
		if err != nil {
			return err
		}
		sort.Slice(live, func(i, j int) bool { return live[i].name < live[j].name })
		for _, re := range live {
			if skipEntry(re) {
				continue
			}
			e := f.entry(re, dir)
			var open func() (io.ReadCloser, error)
			if !e.IsDir {
				rc := re
				open = func() (io.ReadCloser, error) { return f.openRaw(rc) }
			}
			if err := fn(e, open); err != nil {
				return err
			}
			if e.IsDir {
				if err := walk(f.dirRegionFor(re), e.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(f.rootRegion(), "/", 0)
}

// Residues implements fsx.Residuer: the 0xE5 deleted entries of every
// directory, long names reassembled from their deleted LFN chains. The
// FAT chain of a deleted file is freed at deletion, so recovered content
// is the CONTIGUOUS run from its first cluster, capped at the recorded
// size — the classic undelete assumption, stated in Detail.
func (f *FS) Residues(fn func(r fsx.Residue, open func() (io.ReadCloser, error)) error) error {
	var walk func(reg region, dir string, depth int) error
	walk = func(reg region, dir string, depth int) error {
		if depth > maxWalkDepth {
			return nil
		}
		live, deleted, err := f.readDirRegion(reg)
		if err != nil {
			return nil
		}
		for _, re := range deleted {
			if re.attr&attrLabel != 0 {
				continue
			}
			e := f.entry(re, dir)
			r := fsx.Residue{
				Kind:   "deleted_dirent",
				Detail: fmt.Sprintf("0xE5 entry %q in %s (first cluster %d; content recovered assuming contiguity)", re.name, dir, re.cluster),
				Entry:  e,
				ID:     fmt.Sprintf("dirent-%s-cluster-%d", path.Join(dir, re.name), re.cluster),
			}
			var open func() (io.ReadCloser, error)
			if re.attr&attrDir == 0 && re.cluster >= 2 && re.cluster < f.clusterCount+2 && re.size > 0 {
				rc := re
				open = func() (io.ReadCloser, error) {
					n := int64(rc.size)
					max := f.size - f.clusterOffset(rc.cluster)
					if n > max {
						n = max
					}
					return io.NopCloser(io.NewSectionReader(f.ra, f.clusterOffset(rc.cluster), n)), nil
				}
			}
			if err := fn(r, open); err != nil {
				return err
			}
		}
		for _, re := range live {
			if skipEntry(re) || re.attr&attrDir == 0 {
				continue
			}
			if err := walk(f.dirRegionFor(re), path.Join(dir, re.name), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(f.rootRegion(), "/", 0)
}
