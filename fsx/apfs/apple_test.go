package apfs

// apple_test: an APFS container Apple's own tools wrote — the raw disk of
// Homebrew's container-apfs.dmg test fixture (BSD-2-Clause; the UDIF
// container unpacked and its zlib chunks reassembled), a GPT with one
// Apple_APFS partition at 20480 — so the backend is proven against a
// canonical implementation in every test run, not only against the
// evidence image the env-gated tests need.

import (
	"io"
	"testing"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/fsxtest"
	"github.com/Get-Sybers/gomount/partition"
)

func TestAppleWrittenContainer(t *testing.T) {
	ra, size := fsxtest.Open(t, "../testdata", "apfs-container")
	parts, err := partition.Partitions(ra, size)
	if err != nil || len(parts) != 1 || parts[0].TypeName != "Apple APFS" || parts[0].Offset != 20480 {
		t.Fatalf("partitions: %+v %v", parts, err)
	}
	vol := io.NewSectionReader(ra, parts[0].Offset, parts[0].Size)
	if got := fsx.Probe(vol, parts[0].Size); got != "apfs" {
		t.Fatalf("probe: %q", got)
	}
	c, err := OpenContainer(vol, parts[0].Size)
	if err != nil {
		t.Fatal(err)
	}
	vols := c.Volumes()
	if len(vols) != 1 || vols[0].Name != "container-apfs" || vols[0].UUID != "a7d3a58b-c580-49cf-92c2-54059e9792ed" || vols[0].Encrypted || vols[0].Sealed {
		t.Fatalf("volumes: %+v", vols)
	}
	v, err := c.OpenVolume(1)
	if err != nil {
		t.Fatal(err)
	}
	root, err := v.ReadDir("/")
	if err != nil || len(root) != 1 || root[0].Name != "container" || root[0].Size != 17 {
		t.Fatalf("root: %+v %v", root, err)
	}
	r, err := v.Open("/container")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if len(b) != 17 {
		t.Fatalf("content: %q", b)
	}
	if e, err := v.Stat("/container"); err != nil || e.Mtime.Year() != 2021 || e.Btime.IsZero() {
		t.Fatalf("stat: %+v %v", e, err)
	}
}
