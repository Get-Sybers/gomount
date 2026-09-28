// Package apfs is the clean-room Apple File System backend of the fsx seam:
// the container superblock and its newest checkpoint, the object maps,
// the B-trees (fixed and variable), one volume's file-system tree —
// inodes with their extended fields, hashed and plain directory records,
// extended attributes, data streams and file extents — and file content
// including decmpfs compression (zlib, LZVN, LZFSE, raw; inline or in the
// resource fork), all parsed directly over the bounded volume io.ReaderAt,
// every offset checked, no third-party filesystem library. Written against
// the libyal "Apple File System (APFS)" documentation and Apple's File
// System Reference.
//
// A container holds several volumes (a modern Mac boots a sealed System
// volume and keeps everything else on a Data volume). fsx.Open on the
// container opens its default volume — Data, else System, else the first
// — while OpenContainer exposes every volume for the stack resolver to
// address individually.
//
// Out of scope for now: FileVault (an encrypted volume's metadata reads,
// its file content does not), snapshots (the live tree only), Fusion
// containers and the LZBITMAP compressor.
package apfs

import (
	"encoding/binary"
	"io"

	"github.com/get-sybers/gomount/fsx"
)

func init() {
	fsx.Register(fsx.Detector{
		Type:  "apfs",
		Probe: func(ra io.ReaderAt, size int64) bool { return Probe(ra, size) },
		Open:  func(ra io.ReaderAt, size int64) (fsx.FS, error) { return Open(ra, size) },
	})
}

// Probe reports an APFS container: the NXSB magic in block 0's superblock.
func Probe(ra io.ReaderAt, size int64) bool {
	if size < 4096 {
		return false
	}
	b, err := fsx.ReadFull(ra, 32, 4)
	return err == nil && binary.LittleEndian.Uint32(b) == nxMagic
}

// Open opens the container's default volume as an fsx.FS.
func Open(ra io.ReaderAt, size int64) (fsx.FS, error) {
	c, err := OpenContainer(ra, size)
	if err != nil {
		return nil, err
	}
	return c.DefaultVolume()
}
