package lvm

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/get-sybers/gomount/fsx"
	"github.com/get-sybers/gomount/fsx/ext4"
	"github.com/get-sybers/gomount/fsx/fsxtest"
	"github.com/get-sybers/gomount/partition"
)

const mib = 1 << 20

func assembleFixture(t *testing.T) *VG {
	t.Helper()
	ra, size := fsxtest.Open(t, "../fsx/testdata", "lvm")
	parts, err := partition.Partitions(ra, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("partitions: %d", len(parts))
	}
	var pvs []*PV
	for _, p := range parts {
		sec := io.NewSectionReader(ra, p.Offset, p.Size)
		if !IsPV(sec, p.Size) {
			t.Fatalf("partition at %#x not detected as PV", p.Offset)
		}
		pv, err := ProbePV(sec, p.Size, p.Offset)
		if err != nil {
			t.Fatalf("probe pv at %#x: %v", p.Offset, err)
		}
		pvs = append(pvs, pv)
	}
	vgs, err := Assemble(pvs)
	if err != nil {
		t.Fatal(err)
	}
	if len(vgs) != 1 {
		t.Fatalf("vgs: %d", len(vgs))
	}
	return vgs[0]
}

func TestAssembleAndMetadata(t *testing.T) {
	vg := assembleFixture(t)
	if vg.Name != "vg0" || vg.ExtentSize != 1*mib || len(vg.LVs) != 2 || len(vg.Missing) != 0 {
		t.Fatalf("vg: %+v", vg)
	}
	if vg.LVs[0].Name != "root" || vg.LVs[1].Name != "stripey" {
		t.Fatalf("lvs: %+v", vg.LVs)
	}
	if vg.LVs[0].Extents != 6 || vg.LVs[1].Extents != 4 {
		t.Fatalf("extents: %+v", vg.LVs)
	}
}

// TestLinearLVHoldsRealExt4 descends the whole stack: partition -> PV ->
// vg0/root -> the fsx probe -> a file inside the mke2fs-built ext4.
func TestLinearLVHoldsRealExt4(t *testing.T) {
	vg := assembleFixture(t)
	ra, size, err := vg.Reader(vg.LVs[0])
	if err != nil {
		t.Fatal(err)
	}
	if size != 6*mib {
		t.Fatalf("lv size: %d", size)
	}
	if got := fsx.Probe(ra, size); got != "ext4" {
		t.Fatalf("probe inside lv: %q", got)
	}
	f, err := ext4.Open(ra, size)
	if err != nil {
		t.Fatal(err)
	}
	if info := f.Info(); info.Label != "lvroot" {
		t.Fatalf("inner fs: %+v", info)
	}
	r, err := f.Open("/inside-lv.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	if string(b) != "hello from inside the lv\n" {
		t.Fatalf("content: %q", b)
	}
}

// TestStripedLV reads the round-robin layout back through the segment
// mapping and checks every byte of the generator's pattern.
func TestStripedLV(t *testing.T) {
	vg := assembleFixture(t)
	ra, size, err := vg.Reader(vg.LVs[1])
	if err != nil {
		t.Fatal(err)
	}
	if size != 4*mib {
		t.Fatalf("lv size: %d", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(ra, 0, size), b); err != nil {
		t.Fatal(err)
	}
	for i, c := range b {
		if c != byte(i*11%256) {
			t.Fatalf("striped content wrong at %d: %#x", i, c)
		}
	}
}

// TestMissingPV: an LV touching an absent PV reports it, and does not
// silently read garbage.
func TestMissingPV(t *testing.T) {
	ra, size := fsxtest.Open(t, "../fsx/testdata", "lvm")
	parts, err := partition.Partitions(ra, size)
	if err != nil {
		t.Fatal(err)
	}
	sec := io.NewSectionReader(ra, parts[0].Offset, parts[0].Size)
	pv, err := ProbePV(sec, parts[0].Size, parts[0].Offset)
	if err != nil {
		t.Fatal(err)
	}
	vgs, err := Assemble([]*PV{pv})
	if err != nil {
		t.Fatal(err)
	}
	vg := vgs[0]
	if len(vg.Missing) != 1 || vg.Missing[0] != "pv1" {
		t.Fatalf("missing: %+v", vg.Missing)
	}
	if _, _, err := vg.Reader(vg.LVs[1]); err == nil ||
		!strings.Contains(err.Error(), "pv1") {
		t.Fatalf("striped lv on missing pv: %v", err)
	}
	// the linear lv lives wholly on pv0 and still assembles
	if _, _, err := vg.Reader(vg.LVs[0]); err != nil {
		t.Fatalf("linear lv should still read: %v", err)
	}
}

// TestBuildVGCorruptMetadata pins the PR #70 review fix: metadata missing
// a byte-placing field (pv id, pe_start, segment geometry) fails fast
// instead of assembling zero-value mappings that would read the wrong
// offsets.
func TestBuildVGCorruptMetadata(t *testing.T) {
	base := `vg0 {
id = "V"
seqno = 1
extent_size = 2048
physical_volumes { pv0 { %s } }
logical_volumes { root { id = "L"
%s
} }
}`
	cases := map[string][2]string{
		"pv missing id":        {`pe_start = 2048 pe_count = 4`, `segment_count = 1 segment1 { start_extent = 0 extent_count = 1 type = "striped" stripe_count = 1 stripes = [ "pv0", 0 ] }`},
		"pv missing pe_start":  {`id = "AAAAAA-1111-2222-3333-4444-5555-66666B"`, `segment_count = 1 segment1 { start_extent = 0 extent_count = 1 type = "striped" stripe_count = 1 stripes = [ "pv0", 0 ] }`},
		"lv no segment_count":  {`id = "AAAAAA-1111-2222-3333-4444-5555-66666B" pe_start = 2048`, `segment1 { start_extent = 0 extent_count = 1 type = "striped" stripes = [ "pv0", 0 ] }`},
		"segment no extents":   {`id = "AAAAAA-1111-2222-3333-4444-5555-66666B" pe_start = 2048`, `segment_count = 1 segment1 { start_extent = 0 type = "striped" stripes = [ "pv0", 0 ] }`},
		"segment missing type": {`id = "AAAAAA-1111-2222-3333-4444-5555-66666B" pe_start = 2048`, `segment_count = 1 segment1 { start_extent = 0 extent_count = 1 stripes = [ "pv0", 0 ] }`},
	}
	for name, c := range cases {
		text := fmt.Sprintf(base, c[0], c[1])
		if _, err := buildVG("vg0", text, nil); err == nil {
			t.Fatalf("%s: corrupt metadata assembled without error", name)
		}
	}
	// the well-formed control still assembles
	good := fmt.Sprintf(base,
		`id = "AAAAAA-1111-2222-3333-4444-5555-66666B" pe_start = 2048 pe_count = 4`,
		`segment_count = 1 segment1 { start_extent = 0 extent_count = 1 type = "striped" stripe_count = 1 stripes = [ "pv0", 0 ] }`)
	vg, err := buildVG("vg0", good, nil)
	if err != nil || len(vg.LVs) != 1 || len(vg.Missing) != 1 {
		t.Fatalf("control: %+v %v", vg, err)
	}
}
