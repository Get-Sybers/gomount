package hfsplus

// apple_test: an HFS+ volume Apple's own tools wrote — the raw disk of
// Homebrew's transmission-2.61.dmg test fixture (BSD-2-Clause; the UDIF
// container unpacked and its zlib chunks reassembled), a GPT with one
// Apple_HFS partition at 20480 — proving the clean-room backend against
// a canonical implementation, not only against hfstest's encoder.

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/fsxtest"
	"github.com/Get-Sybers/gomount/partition"
)

func TestAppleWrittenVolume(t *testing.T) {
	ra, size := fsxtest.Open(t, "../testdata", "hfsplus-transmission")
	parts, err := partition.Partitions(ra, size)
	if err != nil || len(parts) != 1 || parts[0].TypeName != "Apple HFS+" || parts[0].Offset != 20480 {
		t.Fatalf("partitions: %+v %v", parts, err)
	}
	vol := io.NewSectionReader(ra, parts[0].Offset, parts[0].Size)
	if got := fsx.Probe(vol, parts[0].Size); got != "hfsplus" {
		t.Fatalf("probe: %q", got)
	}
	f, err := Open(vol, parts[0].Size)
	if err != nil {
		t.Fatal(err)
	}
	info := f.Info()
	if info.Label != "Transmission" || info.UUID != "89936734-09d3-3820-ac70-c19dd6a4d6b2" || info.BlockSize != 4096 || f.HFSX() {
		t.Fatalf("info: %+v hfsx=%v", info, f.HFSX())
	}
	if !f.journaled {
		t.Fatal("the volume is journaled")
	}
	root, err := f.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range root {
		names = append(names, e.Name)
	}
	want := ".HFS+ Private Directory Data\r .journal .journal_info_block Transmission.app ␀␀␀␀HFS+ Private Data"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("root:\n got %q\nwant %q", got, want)
	}
	// content through Apple's extents, looked up case-folded as HFS+ does
	r, err := f.Open("/transmission.app/contents/info.plist")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Contains(b, []byte("org.m0k.transmission")) {
		t.Fatalf("Info.plist: %q", b)
	}
	j, err := f.Stat("/.journal")
	if err != nil || j.Size != 524288 || j.Btime.IsZero() || j.Mtime.Year() != 2016 {
		t.Fatalf(".journal: %+v %v", j, err)
	}
	if e, err := f.Stat("/Transmission.app"); err != nil || !e.IsDir || e.Mtime.Year() != 2012 {
		t.Fatalf("Transmission.app: %+v %v", e, err)
	}
	count, files := 0, 0
	err = f.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		count++
		if open != nil {
			files++
			r, err := open()
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
			r.Close()
		}
		return nil
	})
	if err != nil || count != 12 || files != 6 {
		t.Fatalf("walk: %d entries, %d files, %v", count, files, err)
	}
}
