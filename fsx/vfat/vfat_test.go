package vfat

import (
	"io"
	"strings"
	"testing"

	"github.com/get-sybers/gomount/fsx"
	"github.com/get-sybers/gomount/fsx/fsxtest"
)

func openFixture(t *testing.T, name string) *FS {
	t.Helper()
	ra, size := fsxtest.Open(t, "../testdata", name)
	f, err := Open(ra, size)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	return f
}

func TestFAT12(t *testing.T) {
	f := openFixture(t, "fat12")
	if f.fatType != 12 {
		t.Fatalf("fat type %d", f.fatType)
	}
	info := f.Info()
	if info.Type != "vfat" || info.Label != "EFIBOOT" || info.UUID != "CAFE-1234" {
		t.Fatalf("info: %+v", info)
	}

	// 8.3 name
	r, err := f.Open("/HOSTNAME.TXT")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	if string(b) != "web01\n" {
		t.Fatalf("hostname content %q", b)
	}

	// LFN name, spaces preserved, lookup case-insensitive
	e, err := f.Stat("/a long file name.LOG")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "A Long File Name.log" || e.Btime.IsZero() || e.Mtime.IsZero() {
		t.Fatalf("lfn stat: %+v", e)
	}

	// nested dir + LFN
	sub, err := f.ReadDir("/EFI")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 1 || sub[0].Name != "grub configuration.cfg" {
		t.Fatalf("nested: %+v", sub)
	}

	// walk sees the three files
	names := map[string]bool{}
	if err := f.Walk(func(e fsx.Entry, _ func() (io.ReadCloser, error)) error {
		if !e.IsDir {
			names[e.Path] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 || !names["/EFI/grub configuration.cfg"] {
		t.Fatalf("walk: %v", names)
	}
}

func TestFAT12DeletedResidue(t *testing.T) {
	f := openFixture(t, "fat12")
	byName := map[string]string{}
	err := f.Residues(func(r fsx.Residue, open func() (io.ReadCloser, error)) error {
		if r.Kind != "deleted_dirent" || r.Entry.Allocated {
			t.Fatalf("bad residue row: %+v", r)
		}
		content := ""
		if open != nil {
			rc, err := open()
			if err == nil {
				b, _ := io.ReadAll(rc)
				rc.Close()
				content = string(b)
			}
		}
		byName[r.Entry.Name] = content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byName) != 2 {
		t.Fatalf("residue rows: %v", byName)
	}
	// A pure-8.3 deletion loses its first byte to the 0xE5 marker; "_"
	// stands in for the lost character.
	if c, ok := byName["_ELETEME.TXT"]; !ok || !strings.Contains(c, "PRETTY_NAME") {
		t.Fatalf("8.3 deletion: %v", byName)
	}
	// A deleted LFN file keeps its full name in the 0xE5 LFN slots.
	if c, ok := byName["deleted long name.txt"]; !ok || !strings.Contains(c, "systemd[1]") {
		t.Fatalf("LFN deletion: %v", byName)
	}
}

func TestFAT32(t *testing.T) {
	f := openFixture(t, "fat32")
	if f.fatType != 32 {
		t.Fatalf("fat type %d", f.fatType)
	}
	if info := f.Info(); info.Label != "BIGDATA" || info.UUID != "DEAD-0001" {
		t.Fatalf("info: %+v", info)
	}
	e, err := f.Stat("/BIG.BIN")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != 256*400 {
		t.Fatalf("size: %d", e.Size)
	}
	r, err := f.Open("/BIG.BIN")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil || len(b) != 256*400 {
		t.Fatalf("read: %d %v", len(b), err)
	}
	for i, c := range b {
		if c != byte(i%256) {
			t.Fatalf("BIG.BIN corrupt at %d", i)
		}
	}
	if _, err := f.Stat("/nested name with spaces.txt"); err != nil {
		t.Fatalf("fat32 lfn: %v", err)
	}
}

// TestDirRegionCap pins the PR #70 review hardening: a crafted directory
// chain claiming an implausible size errors instead of allocating it.
func TestDirRegionCap(t *testing.T) {
	f := &FS{secPerCluster: 1, bytesPerSec: 512}
	long := region{chain: make([]uint32, (maxDirRegion/512)+2)}
	if _, err := f.regionBytes(long); err == nil {
		t.Fatal("oversized directory chain must error")
	}
	wide := region{fixedLen: maxDirRegion + 1}
	if _, err := f.regionBytes(wide); err == nil {
		t.Fatal("oversized fixed root region must error")
	}
}
