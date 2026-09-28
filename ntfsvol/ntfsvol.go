// Package ntfsvol reads the NTFS boot sector / BPB of a volume through
// Velociraptor's go-ntfs (Apache-2.0, the same parser the sibling GoDFIR tools
// use) and reports the geometry gomount needs to present the volume to ntfs-3g.
//
// The load-bearing value is Geometry.VolumeSize: ntfs-3g sizes its backing
// device with fstat/lseek, so the single regular file gomount's FUSE layer
// exports must report EXACTLY the volume's byte length in Getattr. That length
// is the partition's byte span (partSize) — for a superfloppy that is the whole
// file. The BPB "total sectors" field is NOT that length: NTFS records one
// sector fewer than the volume holds, because the final sector carries the
// backup boot sector. ReadNTFSGeometry therefore returns VolumeSize = partSize
// and surfaces the BPB-derived figure separately as a cross-check.
package ntfsvol

import (
	"fmt"
	"io"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

// Geometry is the NTFS volume geometry read from the boot sector.
//
// BytesPerSector, SectorsPerCluster, ClusterSize and VolumeSize are the fields
// the FUSE provider and CLI consume. The remaining fields expose the BPB's own
// size claim so the caller can log the (normally one-sector) discrepancy.
type Geometry struct {
	BytesPerSector    int64 // BPB +11
	SectorsPerCluster int64 // BPB +13 (as bytes-per-cluster / bytes-per-sector)
	ClusterSize       int64 // BytesPerSector * SectorsPerCluster
	VolumeSize        int64 // LOAD-BEARING: exact byte length ntfs-3g expects == partSize

	BPBTotalSectors int64  // BPB +40, the volume's sector count (excludes backup boot sector)
	BPBVolumeBytes  int64  // BPBTotalSectors * BytesPerSector
	Note            string // populated when VolumeSize and the BPB figure disagree beyond one sector
}

// ReadNTFSGeometry reads the NTFS boot sector at offset in ra and returns the
// volume geometry. partSize is the partition's byte span (from the partition
// table, or the whole image for a superfloppy) and becomes VolumeSize, the exact
// Getattr size for the exported volume.img.
//
// It fails if the sector at offset is not a valid NTFS boot sector.
func ReadNTFSGeometry(ra io.ReaderAt, offset, partSize int64) (Geometry, error) {
	profile := ntfs.NewNTFSProfile()
	boot := profile.NTFS_BOOT_SECTOR(ra, offset)

	// OEM id "NTFS    " at +3, then go-ntfs's own structural validation (0xAA55
	// magic, sane cluster and sector sizes, non-zero volume).
	if oem := boot.Oemname(); oem != "NTFS    " {
		return Geometry{}, fmt.Errorf("not an NTFS boot sector at offset %d (OEM id %q)", offset, oem)
	}
	if err := boot.IsValid(); err != nil {
		return Geometry{}, fmt.Errorf("invalid NTFS boot sector at offset %d: %w", offset, err)
	}

	bytesPerSector := int64(boot.Sector_size())
	clusterSize := boot.ClusterSize() // bytes per cluster
	if bytesPerSector <= 0 || clusterSize <= 0 {
		return Geometry{}, fmt.Errorf("degenerate NTFS geometry (sector=%d cluster=%d)", bytesPerSector, clusterSize)
	}
	// go-ntfs's VolumeSize() returns the BPB "total sectors" field, a sector
	// COUNT (its name notwithstanding), not a byte length.
	bpbTotalSectors := boot.VolumeSize()
	bpbVolumeBytes := bpbTotalSectors * bytesPerSector

	g := Geometry{
		BytesPerSector:    bytesPerSector,
		SectorsPerCluster: clusterSize / bytesPerSector,
		ClusterSize:       clusterSize,
		VolumeSize:        partSize, // <- the exact size ntfs-3g will fstat
		BPBTotalSectors:   bpbTotalSectors,
		BPBVolumeBytes:    bpbVolumeBytes,
	}

	// Expected: partSize == bpbVolumeBytes + one backup-boot-sector. Anything
	// beyond that one sector is worth noting (truncated image, wrong partSize,
	// or a resized volume) but does not change VolumeSize — the device length
	// still governs.
	if diff := partSize - bpbVolumeBytes; diff < 0 || diff > bytesPerSector {
		g.Note = fmt.Sprintf("partSize %d vs BPB volume %d bytes (delta %d, expected +%d for the backup boot sector)",
			partSize, bpbVolumeBytes, diff, bytesPerSector)
	}
	return g, nil
}

// VolumeReader returns a read-only io.ReaderAt bounded to exactly [offset,
// offset+geom.VolumeSize) of the image, the reader the single-file FUSE provider
// exports as volume.img. *io.SectionReader reports that exact length via Size(),
// which is the value Getattr must return, and enforces io.EOF at the bound
// (neutralising go-ewf's lenient short-read-at-EOF behaviour).
func VolumeReader(ra io.ReaderAt, offset int64, geom Geometry) *io.SectionReader {
	return io.NewSectionReader(ra, offset, geom.VolumeSize)
}
