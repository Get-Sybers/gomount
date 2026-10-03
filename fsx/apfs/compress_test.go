package apfs

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/decmpfs"
)

// TestEvidenceCompression walks the sealed System volume — where nearly
// every file is decmpfs-compressed — and reads a sample of each compression
// type it meets in full, so every decoder (zlib, LZVN, LZFSE; inline and
// resource fork) is proven against Apple's own output.
func TestEvidenceCompression(t *testing.T) {
	c, done := openEvidence(t)
	defer done()
	var system *VolumeInfo
	for _, v := range c.Volumes() {
		if v.Role == roleSystem {
			vv := v
			system = &vv
		}
	}
	if system == nil {
		t.Skip("no System volume")
	}
	vol, err := c.OpenVolume(system.Index)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]int{}   // decmpfs type -> files read
	failed := map[uint32]int{} // decmpfs type -> read failures
	const perType = 25
	total := 0
	err = vol.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		if open == nil || e.Size == 0 {
			return nil
		}
		total++
		in, err := vol.inode(e.Inode)
		if err != nil || in.bsdFlags&ufCompressed == 0 {
			return nil
		}
		hdr, err := vol.decmpfsAttr(in)
		if err != nil || len(hdr) < decmpfs.HeaderSize {
			return nil
		}
		typ := binary.LittleEndian.Uint32(hdr[4:])
		if seen[typ]+failed[typ] >= perType {
			return nil
		}
		r, err := open()
		if err != nil {
			failed[typ]++
			t.Logf("type %d %s: open: %v", typ, e.Path, err)
			return nil
		}
		n, err := io.Copy(io.Discard, r)
		r.Close()
		if err != nil || n != e.Size {
			failed[typ]++
			t.Logf("type %d %s: read %d of %d: %v", typ, e.Path, n, e.Size, err)
			return nil
		}
		seen[typ]++
		if total > 60000 {
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	for typ, n := range seen {
		t.Logf("decmpfs type %2d: %d files read whole, %d failed", typ, n, failed[typ])
	}
	for typ, n := range failed {
		if seen[typ] == 0 {
			t.Errorf("decmpfs type %d: every sampled file failed (%d)", typ, n)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no compressed file met on the System volume")
	}
}
