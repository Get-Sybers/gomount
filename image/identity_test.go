package image

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Get-Sybers/gomount/image/imagetest"
)

// TestDiskSerialVMDK: a VMDK's disk_serial is its descriptor content id when
// no ddb.uuid.image is present (the default imagetest descriptor).
func TestDiskSerialVMDK(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk.vmdk")
	if err := imagetest.WriteSparseVMDK(p, rawDisk(t, 16*3), imagetest.VMDKOptions{}); err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if got := DiskSerial(ra); got != "fffffffe" {
		t.Errorf("VMDK disk_serial = %q, want the CID fffffffe", got)
	}
}

// TestDiskSerialVMDKUUIDImage: ddb.uuid.image (16 space-separated hex bytes)
// is preferred over CID and rendered as a canonical UUID.
func TestDiskSerialVMDKUUIDImage(t *testing.T) {
	desc := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n" +
		"createType=\"monolithicSparse\"\n\nRW 48 SPARSE \"u.vmdk\"\n\n" +
		"ddb.uuid.image = \"60 00 c2 9a 11 22 33 44 55 66 77 88 99 aa bb cc\"\n"
	p := filepath.Join(t.TempDir(), "u.vmdk")
	if err := imagetest.WriteSparseVMDK(p, rawDisk(t, 48), imagetest.VMDKOptions{Descriptor: desc}); err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if got := DiskSerial(ra); got != "6000c29a-1122-3344-5566-778899aabbcc" {
		t.Errorf("VMDK disk_serial = %q, want the ddb.uuid.image UUID", got)
	}
}

// TestDiskSerialVHD: the footer "Unique Id" (offset 68) is the VHD's
// disk_serial, rendered straight (big-endian, no byte-swap).
func TestDiskSerialVHD(t *testing.T) {
	raw := rawDisk(t, 16*4)
	p := filepath.Join(t.TempDir(), "fixed.vhd")
	if err := imagetest.WriteFixedVHD(p, raw); err != nil {
		t.Fatal(err)
	}
	// plant a known Unique Id into the footer (footer begins at len(raw))
	id := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(id, int64(len(raw))+68); err != nil {
		t.Fatal(err)
	}
	f.Close()

	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if got := DiskSerial(ra); got != "01020304-0506-0708-090a-0b0c0d0e0f10" {
		t.Errorf("VHD disk_serial = %q", got)
	}
}

// TestDiskSerialRawIsEmpty: a raw image carries no serial (honest null).
func TestDiskSerialRawIsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(p, rawDisk(t, 8), 0o600); err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if got := DiskSerial(ra); got != "" {
		t.Errorf("raw disk_serial = %q, want empty", got)
	}
}

// TestHashContainer: the hash is of the container file bytes as delivered,
// not the decoded media — equal to sha256 of the file on disk.
func TestHashContainer(t *testing.T) {
	raw := rawDisk(t, 20)
	p := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := HashContainer(p)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("HashContainer = %q, want %q", got, hex.EncodeToString(want[:]))
	}
}

func TestGUIDRenderers(t *testing.T) {
	// MS GUID: first three fields little-endian, last two as-is.
	ms := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if got := guidString(ms); got != "12345678-9abc-def0-1122-334455667788" {
		t.Errorf("guidString = %q", got)
	}
	if got := uuidStraight(ms); got != "78563412-bc9a-f0de-1122-334455667788" {
		t.Errorf("uuidStraight = %q", got)
	}
	zero := make([]byte, 16)
	if guidString(zero) != "" || uuidStraight(zero) != "" {
		t.Error("all-zero GUID must render as empty")
	}
	if got := canonicalVMDKUUID("60 00 c2 9a 11 22 33 44 55 66 77 88 99 aa bb cc"); got != "6000c29a-1122-3344-5566-778899aabbcc" {
		t.Errorf("canonicalVMDKUUID = %q", got)
	}
	if canonicalVMDKUUID("not hex") != "" || canonicalVMDKUUID("60 00 c2") != "" {
		t.Error("a non-16-byte ddb.uuid.image must normalize to empty")
	}
	if nonZeroGUID("00000000-0000-0000-0000-000000000000") != "" {
		t.Error("the nil VDI uuid must render as empty")
	}
}
