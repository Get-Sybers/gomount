// Package hfsplus is the clean-room HFS+ / HFSX backend of the fsx seam:
// the volume header (also reached through an HFS wrapper), the three
// B-tree files — catalog, extents overflow, attributes — parsed directly
// over the bounded volume io.ReaderAt with every offset checked, file
// content through the fork descriptors and the overflow extents, symbolic
// links, hard links (file and directory, through the private metadata
// directories), extended attributes, and decmpfs-compressed content
// (zlib, LZVN, LZFSE, raw; inline or in the resource fork) decoded by the
// shared fsx/decmpfs package. Written against the libyal "Hierarchical
// File System (HFS)" documentation and Apple's TN1150.
//
// HFS+ is the filesystem of every Mac before APFS (macOS 10.12 and
// earlier), and stays on Time Machine drives, older external media and most
// disk images. Out of scope: classic HFS volumes themselves (only the
// wrapper around an HFS+ volume is understood), the journal, and the
// hot-file and startup files.
package hfsplus

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
)

const (
	sigHFSPlus = 0x482b // "H+"
	sigHFSX    = 0x4858 // "HX"
	sigHFS     = 0x4244 // "BD": a classic HFS master directory block (the wrapper)

	volumeHeaderOff  = 1024
	volumeHeaderSize = 512

	// reserved catalog node ids
	rootParentID   = 1
	rootFolderID   = 2
	extentsFileID  = 3
	catalogFileID  = 4
	allocationFile = 6
	attributesFile = 8
	firstUserCNID  = 16

	// key compare types (the catalog B-tree header)
	keyCompareBinary   = 0xbc
	keyCompareCaseFold = 0xcf

	forkData = 0x00
	forkRsrc = 0xff

	maxWalkDepth = 128

	// hfsEpoch is 1904-01-01T00:00:00Z as a Unix time.
	hfsEpoch = -2082844800
)

// the HFS+ UUID namespace: diskutil derives a volume's UUID as the v3 (MD5)
// UUID of the 8-byte finderInfo identifier under this namespace.
var uuidNamespace = [16]byte{0xB3, 0xE2, 0x0F, 0x39, 0xF2, 0x92, 0x11, 0xD6, 0x97, 0xA4, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC}

func init() {
	fsx.Register(fsx.Detector{
		Type:  "hfsplus",
		Probe: Probe,
		Open:  func(ra io.ReaderAt, size int64) (fsx.FS, error) { return Open(ra, size) },
	})
}

// Probe reports an HFS+/HFSX volume header at 1024, or an HFS wrapper
// whose master directory block embeds one.
func Probe(ra io.ReaderAt, size int64) bool {
	_, _, ok := locate(ra, size)
	return ok
}

// locate finds the HFS+ volume: at offset 0, or embedded in an HFS
// wrapper; returns the volume's base offset and size.
func locate(ra io.ReaderAt, size int64) (base, vsize int64, ok bool) {
	if size < volumeHeaderOff+volumeHeaderSize {
		return 0, 0, false
	}
	hdr, err := fsx.ReadFull(ra, volumeHeaderOff, volumeHeaderSize)
	if err != nil {
		return 0, 0, false
	}
	be := binary.BigEndian
	switch be.Uint16(hdr) {
	case sigHFSPlus, sigHFSX:
		if be.Uint16(hdr[2:]) != 4 && be.Uint16(hdr[2:]) != 5 {
			return 0, 0, false
		}
		return 0, size, true
	case sigHFS:
		// the master directory block: drAlBlkSiz at 20, drAlBlSt at 28,
		// drEmbedSigWord at 124, drEmbedExtent (start, count) at 126
		if be.Uint16(hdr[124:]) != sigHFSPlus {
			return 0, 0, false
		}
		alBlkSiz := int64(be.Uint32(hdr[20:]))
		alBlSt := int64(be.Uint16(hdr[28:]))
		start := int64(be.Uint16(hdr[126:]))
		count := int64(be.Uint16(hdr[128:]))
		if alBlkSiz == 0 || count == 0 {
			return 0, 0, false
		}
		base = alBlSt*512 + start*alBlkSiz
		vsize = count * alBlkSiz
		if base < 0 || base+volumeHeaderOff+volumeHeaderSize > size {
			return 0, 0, false
		}
		if vsize > size-base {
			vsize = size - base
		}
		inner, err := fsx.ReadFull(ra, base+volumeHeaderOff, 2)
		if err != nil || (be.Uint16(inner) != sigHFSPlus && be.Uint16(inner) != sigHFSX) {
			return 0, 0, false
		}
		return base, vsize, true
	}
	return 0, 0, false
}

// FS is one HFS+ volume.
type FS struct {
	ra   io.ReaderAt // the volume (already rebased when wrapped)
	size int64

	hfsx       bool
	caseFold   bool
	blockSize  int64
	totalBlks  uint32
	fileCount  uint32
	dirCount   uint32
	created    time.Time
	modified   time.Time
	uuid       string
	label      string
	journaled  bool
	catalog    *btree
	extents    *btree
	attributes *btree // nil when the volume has no attributes file

	// the private metadata directories (0 when absent)
	privFileDir uint32 // "\0\0\0\0HFS+ Private Data": hard-link targets iNode<N>
	privDirDir  uint32 // ".HFS+ Private Directory Data\r": directory hard-link targets dir_<N>
}

// Open parses the volume header and opens the B-tree files.
func Open(ra io.ReaderAt, size int64) (*FS, error) {
	base, vsize, ok := locate(ra, size)
	if !ok {
		return nil, fmt.Errorf("hfsplus: no HFS+ volume header")
	}
	if base != 0 {
		ra = io.NewSectionReader(ra, base, vsize)
	}
	hdr, err := fsx.ReadFull(ra, volumeHeaderOff, volumeHeaderSize)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	f := &FS{ra: ra, size: vsize}
	f.hfsx = be.Uint16(hdr) == sigHFSX
	f.blockSize = int64(be.Uint32(hdr[40:]))
	if f.blockSize < 512 || f.blockSize > 1<<20 || f.blockSize&(f.blockSize-1) != 0 {
		return nil, fmt.Errorf("hfsplus: allocation block size %d", f.blockSize)
	}
	f.totalBlks = be.Uint32(hdr[44:])
	f.fileCount = be.Uint32(hdr[32:])
	f.dirCount = be.Uint32(hdr[36:])
	f.created = hfsTime(be.Uint32(hdr[16:]))
	f.modified = hfsTime(be.Uint32(hdr[20:]))
	f.journaled = be.Uint32(hdr[4:])&0x2000 != 0
	if id := hdr[104:112]; be.Uint64(id) != 0 {
		f.uuid = volumeUUID(id)
	}

	// the special files: extents first (the others may overflow into it)
	ext, err := f.forkReaderRaw(extentsFileID, forkData, hdr[192:272], nil)
	if err != nil {
		return nil, fmt.Errorf("hfsplus: extents file: %w", err)
	}
	if f.extents, err = f.openBTree(ext, "extents"); err != nil {
		return nil, err
	}
	cat, err := f.forkReaderRaw(catalogFileID, forkData, hdr[272:352], f.extents)
	if err != nil {
		return nil, fmt.Errorf("hfsplus: catalog file: %w", err)
	}
	if f.catalog, err = f.openBTree(cat, "catalog"); err != nil {
		return nil, err
	}
	f.caseFold = f.catalog.keyCompare != keyCompareBinary
	if be.Uint64(hdr[352:]) != 0 { // the attributes file has a logical size
		attr, err := f.forkReaderRaw(attributesFile, forkData, hdr[352:432], f.extents)
		if err != nil {
			return nil, fmt.Errorf("hfsplus: attributes file: %w", err)
		}
		if f.attributes, err = f.openBTree(attr, "attributes"); err != nil {
			return nil, err
		}
	}

	// the root folder proves the catalog reads; its thread record names the volume
	if _, name, err := f.threadOf(rootFolderID); err != nil {
		return nil, fmt.Errorf("hfsplus: root folder: %w", err)
	} else {
		f.label = name
	}
	f.privFileDir = f.childID(rootFolderID, "\x00\x00\x00\x00HFS+ Private Data")
	f.privDirDir = f.childID(rootFolderID, ".HFS+ Private Directory Data\r")
	return f, nil
}

// Info implements fsx.FS.
func (f *FS) Info() fsx.Info {
	return fsx.Info{Type: "hfsplus", UUID: f.uuid, Label: f.label, BlockSize: f.blockSize}
}

// HFSX reports a case-sensitive (HFSX) volume.
func (f *FS) HFSX() bool { return f.hfsx }

// hfsTime converts seconds since 1904 (UTC on HFS+); 0 is an honest null.
func hfsTime(secs uint32) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return time.Unix(int64(secs)+hfsEpoch, 0).UTC()
}

// volumeUUID derives the UUID diskutil reports from the 8-byte identifier
// in finderInfo[6..7]: a version-3 UUID under the HFS+ namespace.
func volumeUUID(id []byte) string {
	h := md5.New()
	h.Write(uuidNamespace[:])
	h.Write(id)
	u := h.Sum(nil)
	u[6] = u[6]&0x0f | 0x30
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// readBlocks reads n bytes at a byte offset within the volume.
func (f *FS) readAt(off int64, n int) ([]byte, error) {
	if off < 0 || off+int64(n) > f.size {
		return nil, fmt.Errorf("hfsplus: read %d bytes at %#x: outside the volume", n, off)
	}
	return fsx.ReadFull(f.ra, off, n)
}
