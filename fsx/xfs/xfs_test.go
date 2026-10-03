package xfs

import (
	"io"
	"strings"
	"testing"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/fsxtest"
)

func openFixture(t *testing.T) *FS {
	t.Helper()
	ra, size := fsxtest.Open(t, "../testdata", "xfs")
	f, err := Open(ra, size)
	if err != nil {
		t.Fatalf("open xfs: %v", err)
	}
	return f
}

func TestXFSInfoAndStat(t *testing.T) {
	f := openFixture(t)
	info := f.Info()
	if info.Type != "xfs" || info.Label != "xfsroot" ||
		info.UUID != "33333333-2222-3333-4444-555555555555" || info.BlockSize != 4096 {
		t.Fatalf("info: %+v", info)
	}

	e, err := f.Stat("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if e.IsDir || e.Size != 6 || e.Mode&0xFFF != 0o644 || e.Nlink != 1 {
		t.Fatalf("stat: %+v", e)
	}
	// v5 inodes always carry crtime (bigtime on this mkfs).
	if e.Btime.IsZero() || e.Mtime.IsZero() {
		t.Fatalf("times: %+v", e)
	}
	if e.Btime.Year() < 2024 || e.Btime.Year() > 2100 {
		t.Fatalf("bigtime decode off: %v", e.Btime)
	}

	owned, err := f.Stat("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if owned.UID != 1000 || owned.GID != 1000 || owned.Size != 256*400 {
		t.Fatalf("big.bin: %+v", owned)
	}

	syslog, err := f.Stat("/var/log/syslog")
	if err != nil {
		t.Fatal(err)
	}
	if syslog.GID != 4 || syslog.Mode&0xFFF != 0o640 {
		t.Fatalf("proto mode/gid: %+v", syslog)
	}
}

func TestXFSContentAndSymlink(t *testing.T) {
	f := openFixture(t)
	r, err := f.Open("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	if string(b) != "web01\n" {
		t.Fatalf("hostname: %q", b)
	}

	r, err = f.Open("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	big, err := io.ReadAll(r)
	if err != nil || len(big) != 256*400 {
		t.Fatalf("big.bin read: %d %v", len(big), err)
	}
	for i, c := range big {
		if c != byte(i%256) {
			t.Fatalf("big.bin corrupt at %d", i)
		}
	}

	l, err := f.Stat("/etc/localtime")
	if err != nil {
		t.Fatal(err)
	}
	if l.LinkTarget != "../usr/share/zoneinfo/Europe/Berlin" {
		t.Fatalf("symlink: %+v", l)
	}
}

func TestXFSDirForms(t *testing.T) {
	f := openFixture(t)
	// /etc: small (shortform or block form)
	etc, err := f.ReadDir("/etc")
	if err != nil {
		t.Fatal(err)
	}
	if len(etc) != 3 {
		t.Fatalf("/etc entries: %d", len(etc))
	}
	// /bigdir: 300 entries forces the leaf/node form; the data-block walk
	// must see all of them, and none of the leaf-index noise.
	big, err := f.ReadDir("/bigdir")
	if err != nil {
		t.Fatal(err)
	}
	if len(big) != 300 {
		t.Fatalf("/bigdir entries: %d", len(big))
	}
	if big[0].Name != "leaf-001.txt" || big[299].Name != "leaf-300.txt" {
		t.Fatalf("ordering: %s .. %s", big[0].Name, big[299].Name)
	}

	files := 0
	if err := f.Walk(func(e fsx.Entry, _ func() (io.ReadCloser, error)) error {
		if !e.IsDir && !strings.HasPrefix(e.Path, "/bigdir/") {
			files++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// hostname, os-release, localtime, syslog, big.bin
	if files != 5 {
		t.Fatalf("walk non-bigdir files: %d", files)
	}
}
