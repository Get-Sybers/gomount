package image

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/Get-Sybers/gomount/image/imagetest"
)

// rawDisk is a deterministic sector-aligned byte pattern with an all-zero
// grain in the middle (so the sparse encoders really leave a hole) and a
// partial last grain.
func rawDisk(t *testing.T, sectors int) []byte {
	t.Helper()
	r := rand.New(rand.NewSource(7))
	raw := make([]byte, sectors*512)
	r.Read(raw)
	// grain 2 (16 sectors of 8 KiB each with the default test grain) is zeros
	for i := 2 * 16 * 512; i < 3*16*512 && i < len(raw); i++ {
		raw[i] = 0
	}
	return raw
}

func readAll(t *testing.T, path string, want []byte) {
	t.Helper()
	ra, size, closer, err := OpenImage(path)
	if err != nil {
		t.Fatalf("OpenImage(%s): %v", filepath.Base(path), err)
	}
	defer closer()
	if size != int64(len(want)) {
		t.Fatalf("%s: size %d, want %d", filepath.Base(path), size, len(want))
	}
	got := make([]byte, len(want))
	if _, err := ra.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatalf("%s: ReadAt: %v", filepath.Base(path), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: bytes differ", filepath.Base(path))
	}
	// unaligned reads that straddle grain/block boundaries
	for _, off := range []int64{1, 511, 8191, 8192, 8193, 16384 + 300, int64(len(want)) - 700} {
		if off < 0 || off >= int64(len(want)) {
			continue
		}
		buf := make([]byte, 1000)
		n, err := ra.ReadAt(buf, off)
		end := off + int64(n)
		if err != nil && err != io.EOF {
			t.Fatalf("%s: ReadAt(%d): %v", filepath.Base(path), off, err)
		}
		if !bytes.Equal(buf[:n], want[off:end]) {
			t.Fatalf("%s: ReadAt(%d) bytes differ", filepath.Base(path), off)
		}
	}
	// past the end is EOF, not a panic
	if _, err := ra.ReadAt(make([]byte, 16), int64(len(want))+4096); err != io.EOF {
		t.Fatalf("%s: read past end: err=%v, want EOF", filepath.Base(path), err)
	}
}

func TestVMDKSparse(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 16*7+5) // 7 full grains + a partial one
	p := filepath.Join(dir, "disk.vmdk")
	if err := imagetest.WriteSparseVMDK(p, raw, imagetest.VMDKOptions{}); err != nil {
		t.Fatal(err)
	}
	readAll(t, p, raw)
	if f := Format(p); f != "vmdk" {
		t.Fatalf("sniffFormat: %q", f)
	}
}

func TestVMDKStreamOptimized(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 16*5)
	p := filepath.Join(dir, "stream.vmdk")
	if err := imagetest.WriteSparseVMDK(p, raw, imagetest.VMDKOptions{Compressed: true}); err != nil {
		t.Fatal(err)
	}
	readAll(t, p, raw)
}

func TestVMDKUnallocatedGrainReadsZero(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 16*4)
	p := filepath.Join(dir, "holes.vmdk")
	if err := imagetest.WriteSparseVMDK(p, raw, imagetest.VMDKOptions{ZeroGrains: map[int]bool{1: true}}); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), raw...)
	for i := 16 * 512; i < 2*16*512; i++ {
		want[i] = 0
	}
	readAll(t, p, want)
}

func TestVMDKDescriptorFlatAndZero(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 40)
	p := filepath.Join(dir, "flat disk.vmdk") // a space in the name, as VM exports have
	if err := imagetest.WriteFlatVMDK(p, raw, 8); err != nil {
		t.Fatal(err)
	}
	want := append(make([]byte, 8*512), raw...)
	readAll(t, p, want)
	if f := Format(p); f != "vmdk" {
		t.Fatalf("Format(descriptor): %q", f)
	}
}

func TestVMDKSnapshotDelta(t *testing.T) {
	dir := t.TempDir()
	base := rawDisk(t, 16*4)
	if err := imagetest.WriteSparseVMDK(filepath.Join(dir, "base.vmdk"), base, imagetest.VMDKOptions{}); err != nil {
		t.Fatal(err)
	}
	// the delta rewrites grain 3 and leaves the rest to the parent
	delta := make([]byte, len(base))
	for i := 3 * 16 * 512; i < len(delta); i++ {
		delta[i] = 0xAB
	}
	desc := "# Disk DescriptorFile\nversion=1\nCID=11111111\nparentCID=22222222\ncreateType=\"monolithicSparse\"\nparentFileNameHint=\"base.vmdk\"\n\nRW 64 SPARSE \"base-000001.vmdk\"\n"
	p := filepath.Join(dir, "base-000001.vmdk")
	if err := imagetest.WriteSparseVMDK(p, delta, imagetest.VMDKOptions{Descriptor: desc}); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), base...)
	copy(want[3*16*512:], delta[3*16*512:])
	readAll(t, p, want)
}

func TestVMDKSplitExtentsWithoutDescriptor(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 16*6)
	// two extents of 3 grains each, no descriptor file at all
	half := len(raw) / 2
	for i, part := range [][]byte{raw[:half], raw[half:]} {
		name := filepath.Join(dir, "split-s00"+string(rune('1'+i))+".vmdk")
		if err := imagetest.WriteSparseVMDK(name, part, imagetest.VMDKOptions{Descriptor: "# Disk DescriptorFile\nversion=1\n"}); err != nil {
			t.Fatal(err)
		}
	}
	readAll(t, filepath.Join(dir, "split-s001.vmdk"), raw)
}

func TestVHDFixedAndDynamic(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 16*9)
	fixed := filepath.Join(dir, "fixed.vhd")
	if err := imagetest.WriteFixedVHD(fixed, raw); err != nil {
		t.Fatal(err)
	}
	readAll(t, fixed, raw)
	if f := Format(fixed); f != "vhd" {
		t.Fatalf("Format(vhd): %q", f)
	}
	dyn := filepath.Join(dir, "dynamic.vhd")
	if err := imagetest.WriteDynamicVHD(dyn, raw, 16*512*2); err != nil {
		t.Fatal(err)
	}
	readAll(t, dyn, raw)
}

func TestRawStillRaw(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 20)
	p := filepath.Join(dir, "plain.vmdk") // mislabelled: no KDMV, no descriptor
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	readAll(t, p, raw)
	if f := Format(p); f != "raw" {
		t.Fatalf("Format(mislabelled): %q", f)
	}
	// a name never decides: a raw file called .E01 is still raw
	e := filepath.Join(dir, "plain.E01")
	if err := os.WriteFile(e, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	readAll(t, e, raw)
	if f := Format(e); f != "raw" {
		t.Fatalf("Format(mislabelled .E01): %q", f)
	}
}

func TestVMDKCompressedGrainShortReadAndCorruption(t *testing.T) {
	dir := t.TempDir()
	raw := rawDisk(t, 16*4)
	p := filepath.Join(dir, "cut.vmdk")
	if err := imagetest.WriteSparseVMDK(p, raw, imagetest.VMDKOptions{Compressed: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	ext := ra.(*vmdkDisk).extents[0].ra.(*sparseExtent)
	gte, err := ext.grainOffset(3 * 16 * 512)
	closer()
	if err != nil || gte == 0 {
		t.Fatalf("grain 3 offset: %d %v", gte, err)
	}
	marker := int(gte) * 512

	// 1. the marker claims more bytes than the file holds past it: ReadAt
	// comes back short, only what was read goes to the inflater, and the
	// intact stream at the front still decodes to the right bytes
	short := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(short[marker+8:marker+12], uint32(16*512*2))
	if err := os.WriteFile(p, short, 0o644); err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err = OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16*512)
	if _, err := ra.ReadAt(got, 3*16*512); err != nil && err != io.EOF {
		t.Fatalf("short read of a compressed grain must not fail: %v", err)
	}
	closer()
	if !bytes.Equal(got, raw[3*16*512:4*16*512]) {
		t.Fatalf("short read: the intact stream must decode to the raw bytes")
	}

	// 2. the payload itself is corrupt (zeros over the stream): that is an
	// error, never garbage handed back as evidence
	corrupt := append([]byte(nil), b...)
	for i := marker + 12; i < marker+12+64; i++ {
		corrupt[i] = 0
	}
	if err := os.WriteFile(p, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err = OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if _, err := ra.ReadAt(got, 3*16*512); err == nil {
		t.Fatalf("a corrupt compressed grain must surface an error")
	}
	// the grains before it are untouched
	if _, err := ra.ReadAt(got, 0); err != nil || !bytes.Equal(got, raw[:len(got)]) {
		t.Fatalf("intact grain corrupted: %v", err)
	}
}
