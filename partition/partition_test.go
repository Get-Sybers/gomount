package partition

// Crafted-table tests for the evidence-asset identity the origin records
// key on: the MBR disk signature, and the GPT disk GUID + per-partition
// unique GUID. Each builds a minimal valid table over a bytes.Reader — no
// fixtures, no privilege.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMBRDiskSignature(t *testing.T) {
	img := make([]byte, 4096)
	binary.LittleEndian.PutUint32(img[440:444], 0x1a2b3c4d) // disk signature
	e := img[446:462]                                        // one primary entry
	e[4] = 0x83                                              // Linux
	binary.LittleEndian.PutUint32(e[8:12], 1)               // startLBA
	binary.LittleEndian.PutUint32(e[12:16], 1)              // sectors
	img[510], img[511] = 0x55, 0xAA

	parts, err := Partitions(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Fatalf("parts = %d, want 1: %+v", len(parts), parts)
	}
	if parts[0].DiskID != "1a2b3c4d" {
		t.Errorf("disk_id = %q, want 1a2b3c4d (the LE disk signature, hex)", parts[0].DiskID)
	}
	if parts[0].PartGUID != "" {
		t.Errorf("MBR part_guid = %q, want none (MBR has no per-partition GUID)", parts[0].PartGUID)
	}
}

func TestMBRZeroSignatureIsNull(t *testing.T) {
	img := make([]byte, 4096) // signature bytes left zero
	e := img[446:462]
	e[4] = 0x83
	binary.LittleEndian.PutUint32(e[8:12], 1)
	binary.LittleEndian.PutUint32(e[12:16], 1)
	img[510], img[511] = 0x55, 0xAA

	parts, err := Partitions(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0].DiskID != "" {
		t.Fatalf("zero signature disk_id = %q, want empty (honest null)", parts[0].DiskID)
	}
}

func TestGPTDiskAndPartitionGUID(t *testing.T) {
	img := make([]byte, 16*512)
	img[510], img[511] = 0x55, 0xAA // protective MBR signature

	h := img[512 : 512+92] // GPT header at LBA1
	copy(h[0:8], "EFI PART")
	// disk GUID -> canonical "12345678-9abc-def0-1122-334455667788"
	copy(h[56:72], []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	binary.LittleEndian.PutUint64(h[72:80], 2) // entry array at LBA2
	binary.LittleEndian.PutUint32(h[80:84], 2) // 2 entries
	binary.LittleEndian.PutUint32(h[84:88], 128)

	e0 := img[1024 : 1024+128]
	// a non-zero type GUID so the slot is used (Microsoft basic data)
	copy(e0[0:16], []byte{0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7})
	// unique partition GUID -> canonical "aabbccdd-eeff-0011-2233-445566778899"
	copy(e0[16:32], []byte{0xdd, 0xcc, 0xbb, 0xaa, 0xff, 0xee, 0x11, 0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	binary.LittleEndian.PutUint64(e0[32:40], 6) // firstLBA
	binary.LittleEndian.PutUint64(e0[40:48], 6) // lastLBA (inclusive: one sector)

	parts, err := Partitions(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Fatalf("parts = %d, want 1: %+v", len(parts), parts)
	}
	if parts[0].DiskID != "12345678-9abc-def0-1122-334455667788" {
		t.Errorf("disk_id = %q, want the GPT disk GUID", parts[0].DiskID)
	}
	if parts[0].PartGUID != "aabbccdd-eeff-0011-2233-445566778899" {
		t.Errorf("part_guid = %q, want the unique partition GUID", parts[0].PartGUID)
	}
	if parts[0].Offset != 6*512 {
		t.Errorf("offset = %d, want 3072", parts[0].Offset)
	}
}
