package ext4

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/fsxtest"
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

func readAll(t *testing.T, f *FS, p string) []byte {
	t.Helper()
	r, err := f.Open(p)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func TestExt4InfoAndStat(t *testing.T) {
	f := openFixture(t, "ext4")
	info := f.Info()
	if info.Type != "ext4" || info.Label != "rootfs" ||
		info.UUID != "21111111-2222-3333-4444-555555555555" || info.BlockSize != 1024 {
		t.Fatalf("info: %+v", info)
	}

	e, err := f.Stat("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	// The generator pins these with debugfs sif (times are debugfs-local,
	// written as UTC wall-clock strings on the build host = UTC).
	if !e.Mtime.Equal(time.Date(2026, 1, 10, 22, 14, 2, 0, time.UTC)) ||
		!e.Btime.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("pinned times: mtime=%v btime=%v", e.Mtime, e.Btime)
	}
	if e.IsDir || e.Size != 6 || e.Nlink != 1 || e.Mode&0xFFF != 0o644 {
		t.Fatalf("stat: %+v", e)
	}
	if string(readAll(t, f, "/etc/hostname")) != "web01\n" {
		t.Fatal("content mismatch")
	}

	owned, err := f.Stat("/home/alice/.bash_history")
	if err != nil {
		t.Fatal(err)
	}
	if owned.UID != 1000 || owned.GID != 1000 {
		t.Fatalf("uid/gid: %+v", owned)
	}
}

func TestExt4SymlinksAndDirs(t *testing.T) {
	f := openFixture(t, "ext4")
	link, err := f.Stat("/etc/localtime")
	if err != nil {
		t.Fatal(err)
	}
	if link.LinkTarget != "../usr/share/zoneinfo/Europe/Berlin" {
		t.Fatalf("fast symlink: %+v", link)
	}
	long, err := f.Stat("/etc/longlink")
	if err != nil {
		t.Fatal(err)
	}
	if long.LinkTarget != strings.Repeat("t", 80) {
		t.Fatalf("slow symlink: %q", long.LinkTarget)
	}

	// htree directory: 120 entries via the linear-scan-of-blocks path
	ents, err := f.ReadDir("/bigdir")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 120 {
		t.Fatalf("htree dir entries: %d", len(ents))
	}
	if ents[0].Name != "file-001.txt" || ents[119].Name != "file-120.txt" {
		t.Fatalf("ordering: %s .. %s", ents[0].Name, ents[119].Name)
	}
}

func TestExt4MultiBlockContent(t *testing.T) {
	f := openFixture(t, "ext4")
	got := readAll(t, f, "/big.bin")
	want := bytes.Repeat(byteRange(), 400)
	if !bytes.Equal(got, want) {
		t.Fatalf("big.bin: %d bytes, equal=%v", len(got), bytes.Equal(got, want))
	}
}

func byteRange() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestExt4Walk(t *testing.T) {
	f := openFixture(t, "ext4")
	files, dirs := 0, 0
	err := f.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		if e.IsDir {
			dirs++
			return nil
		}
		if !e.Allocated {
			t.Fatalf("walk yielded unallocated entry: %+v", e)
		}
		files++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 120 bigdir + hostname + os-release + localtime + longlink + syslog +
	// .bash_history + big.bin + lost+found/#12 = 128 non-dir entries
	if files != 128 {
		t.Fatalf("walk files: %d", files)
	}
	if dirs < 6 { // etc, var, var/log, home, home/alice, bigdir, lost+found
		t.Fatalf("walk dirs: %d", dirs)
	}
}

func TestExt4Residue(t *testing.T) {
	f := openFixture(t, "ext4")
	byKind := map[string][]fsx.Residue{}
	contents := map[string]string{}
	err := f.Residues(func(r fsx.Residue, open func() (io.ReadCloser, error)) error {
		byKind[r.Kind] = append(byKind[r.Kind], r)
		if open != nil {
			rc, err := open()
			if err == nil {
				b, _ := io.ReadAll(rc)
				rc.Close()
				contents[r.ID] = string(b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	lf := byKind["lost_found"]
	if len(lf) != 1 || lf[0].Entry.Name != "#12" || contents[lf[0].ID] != "recovered by fsck\n" {
		t.Fatalf("lost_found: %+v", lf)
	}

	// Two orphans: the bitmap-sweep one (unlink only) and the chain one
	// (links 0 + s_last_orphan) — deduped whichever path finds them first.
	orph := byKind["orphan_inode"]
	if len(orph) != 2 {
		t.Fatalf("orphan_inode count: %d (%+v)", len(orph), orph)
	}
	var got []string
	for _, r := range orph {
		if r.Entry.Allocated {
			t.Fatalf("orphan marked allocated: %+v", r)
		}
		got = append(got, contents[r.ID])
	}
	want := map[string]bool{"sweep orphan content\n": false, "chain orphan content\n": false}
	for _, c := range got {
		if _, ok := want[c]; !ok {
			t.Fatalf("unexpected orphan content %q", c)
		}
		want[c] = true
	}
	for c, seen := range want {
		if !seen {
			t.Fatalf("orphan %q not recovered", c)
		}
	}

	dd := byKind["deleted_dirent"]
	found := false
	for _, r := range dd {
		if r.Entry.Name == "todelete.txt" {
			found = true
			if r.Entry.Allocated {
				t.Fatalf("deleted dirent marked allocated: %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("deleted_dirent todelete.txt not found in %d rows", len(dd))
	}
}

func TestExt2LegacyMaps(t *testing.T) {
	f := openFixture(t, "ext2")
	if info := f.Info(); info.Type != "ext2" || info.Label != "classic" {
		t.Fatalf("info: %+v", info)
	}
	e, err := f.Stat("/indirect.bin")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != 300*1024 {
		t.Fatalf("size: %d", e.Size)
	}
	if !e.Btime.IsZero() {
		t.Fatalf("128-byte inodes have no crtime, got %v", e.Btime)
	}
	got := readAll(t, f, "/indirect.bin")
	for i, b := range got {
		if b != byte((i*7)%256) {
			t.Fatalf("indirect.bin corrupt at %d", i)
		}
	}
	l, err := f.Stat("/link")
	if err != nil || l.LinkTarget != "README" {
		t.Fatalf("ext2 symlink: %+v %v", l, err)
	}
}

// TestExtentReaderHoles pins hole semantics synthetically: unmapped file
// blocks read as zeros.
func TestExtentReaderHoles(t *testing.T) {
	disk := make([]byte, 8192)
	copy(disk[4096:], bytes.Repeat([]byte{0xAB}, 1024))
	f := &FS{ra: bytes.NewReader(disk), size: int64(len(disk)), blockSize: 1024}
	r := &extentReader{f: f, extents: []extent{{lblock: 2, pblock: 4, count: 1}}, size: 4096}
	got := make([]byte, 4096)
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, 4096), got); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2048; i++ {
		if got[i] != 0 {
			t.Fatalf("hole byte %d = %#x", i, got[i])
		}
	}
	if !bytes.Equal(got[2048:3072], bytes.Repeat([]byte{0xAB}, 1024)) {
		t.Fatal("mapped block content wrong")
	}
	for i := 3072; i < 4096; i++ {
		if got[i] != 0 {
			t.Fatalf("tail hole byte %d = %#x", i, got[i])
		}
	}
}

// TestInlineDataPrefix pins the PR #70 review point: an inline-data
// inode whose recorded size exceeds the in-inode capacity serves its
// addressable 60-byte prefix as the reader's length, so reads succeed
// over exactly what exists (Stat keeps reporting the true size).
func TestInlineDataPrefix(t *testing.T) {
	in := &inode{size: 70, flags: flagInline}
	for i := range in.blocks {
		in.blocks[i] = byte('a' + i%26)
	}
	ra, size, err := (&FS{}).blockReader(in)
	if err != nil {
		t.Fatal(err)
	}
	if size != 60 {
		t.Fatalf("inline readable length = %d, want 60", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(ra, 0, size), b); err != nil {
		t.Fatalf("prefix read: %v", err)
	}
	if b[0] != 'a' || b[59] != byte('a'+59%26) {
		t.Fatalf("prefix content: %q", b)
	}
}
