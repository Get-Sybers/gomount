package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"testing"
	"time"
)

// stubFS is a local, in-memory implementation of the volumeFS contract. The
// userspace verbs test against it with no image, no go-ntfs and no privilege —
// exactly the "test-compile against local stubs of the ntfsfs contract" path.
type stubFS struct {
	dirs  map[string][]fileEntry // directory path -> its children (files, dirs)
	files map[string][]byte      // file path (or path:stream) -> its bytes
	stats map[string]fileEntry   // path -> Stat result
}

func (s *stubFS) ReadDir(dir string) ([]fileEntry, error) {
	return s.dirs[dir], nil
}

func (s *stubFS) Stat(p string) (fileEntry, error) {
	if e, ok := s.stats[p]; ok {
		return e, nil
	}
	return fileEntry{}, fmt.Errorf("stub: %q not found", p)
}

func (s *stubFS) Open(p string) (io.ReadCloser, error) {
	b, ok := s.files[p]
	if !ok {
		return nil, fmt.Errorf("stub: %q not found", p)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// Walk delivers each live regular file with a lazy opener, recursing into
// directories — mirroring ntfsfs.FS.Walk (files only, no directories to fn).
func (s *stubFS) Walk(fn func(e fileEntry, open func() (io.ReadCloser, error)) error) error {
	return s.walk("/", fn)
}

func (s *stubFS) walk(dir string, fn func(fileEntry, func() (io.ReadCloser, error)) error) error {
	for _, e := range s.dirs[dir] {
		if e.Deleted {
			continue
		}
		child := path.Join(dir, e.Name)
		e.Path = child
		if e.IsDir {
			if err := s.walk(child, fn); err != nil {
				return err
			}
			continue
		}
		open := func() (io.ReadCloser, error) { return s.Open(child) }
		if err := fn(e, open); err != nil {
			return err
		}
	}
	return nil
}

var mtime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func sampleFS() *stubFS {
	return &stubFS{
		dirs: map[string][]fileEntry{
			"/": {
				{Name: "Windows", IsDir: true, MFTID: "44"},
				{Name: "Folder A", IsDir: true, MFTID: "41"}, // spaced name
				{Name: "note.txt", Size: 5, Mtime: mtime, MFTID: "70", Streams: []string{"secret"}},
				{Name: "ghost.txt", Size: 9, Deleted: true, MFTID: "80"},
			},
			"/Windows": {
				{Name: "System32", IsDir: true, MFTID: "45"},
			},
			"/Windows/System32": {
				{Name: "cmd.exe", Size: 4, Mtime: mtime, MFTID: "90"},
			},
			"/Folder A": {
				{Name: "read me.txt", Size: 2, Mtime: mtime, MFTID: "42"},
			},
		},
		files: map[string][]byte{
			"/note.txt":                 []byte("hello"),
			"/note.txt:secret":          []byte("ads"),
			"/Windows/System32/cmd.exe": []byte("MZ\x00\x00"),
			"/Folder A/read me.txt":     []byte("ok"),
		},
		stats: map[string]fileEntry{
			"/note.txt": {Name: "note.txt", Path: "/note.txt", Size: 5, Mtime: mtime, MFTID: "70", Streams: []string{"secret"}},
			"/Windows":  {Name: "Windows", Path: "/Windows", IsDir: true, MFTID: "44"},
			"/Folder A": {Name: "Folder A", Path: "/Folder A", IsDir: true, MFTID: "41"},
		},
	}
}

func TestListDirLongAndADS(t *testing.T) {
	var buf bytes.Buffer
	if err := listDir(&buf, sampleFS(), "/", true, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "note.txt:secret") {
		t.Errorf("ADS not shown as name:stream:\n%s", out)
	}
	if strings.Contains(out, "ghost.txt") {
		t.Errorf("deleted entry shown without --deleted:\n%s", out)
	}
	if !strings.Contains(out, "d ") || !strings.Contains(out, "2026-01-02T03:04:05Z") {
		t.Errorf("long listing missing type/mtime columns:\n%s", out)
	}
}

func TestListDirDeleted(t *testing.T) {
	var buf bytes.Buffer
	if err := listDir(&buf, sampleFS(), "/", false, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ghost.txt  (deleted)") {
		t.Errorf("deleted entry not marked with --deleted:\n%s", buf.String())
	}
}

func TestCatAndADS(t *testing.T) {
	var buf bytes.Buffer
	if err := catFile(&buf, sampleFS(), "/note.txt"); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello" {
		t.Errorf("cat = %q, want hello", buf.String())
	}
	buf.Reset()
	if err := catFile(&buf, sampleFS(), "/note.txt:secret"); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "ads" {
		t.Errorf("cat ADS = %q, want ads", buf.String())
	}
}

func TestStatStreams(t *testing.T) {
	var buf bytes.Buffer
	e, err := sampleFS().Stat("/note.txt")
	if err != nil {
		t.Fatal(err)
	}
	printStat(&buf, e)
	out := buf.String()
	for _, want := range []string{"Size:       5", "MFTId:      70", "Streams:    secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("stat missing %q:\n%s", want, out)
		}
	}
}

func TestTreeDepth(t *testing.T) {
	var buf bytes.Buffer
	if err := treeDir(&buf, sampleFS(), "/", 0, 1, ""); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Windows") || !strings.Contains(out, "  System32") {
		t.Errorf("tree missing nested entry:\n%s", out)
	}
	if strings.Contains(out, "cmd.exe") {
		t.Errorf("tree exceeded --depth 1:\n%s", out)
	}
}

func TestStreamJSONL(t *testing.T) {
	var out, errBuf bytes.Buffer
	sum, err := streamVolume(&out, &errBuf, sampleFS(), "*.exe", true)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Files != 1 {
		t.Errorf("files = %d, want 1", sum.Files)
	}
	var rec streamRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &rec); err != nil {
		t.Fatalf("bad jsonl %q: %v", out.String(), err)
	}
	if rec.Path != "/Windows/System32/cmd.exe" || rec.MFTID != "90" {
		t.Errorf("record = %+v", rec)
	}
}

func TestStreamTar(t *testing.T) {
	var out, errBuf bytes.Buffer
	sum, err := streamVolume(&out, &errBuf, sampleFS(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&out)
	names := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[hdr.Name] = hdr.Size
	}
	if names["note.txt"] != 5 || names["Windows/System32/cmd.exe"] != 4 || names["Folder A/read me.txt"] != 2 {
		t.Errorf("tar names = %v", names)
	}
	if sum.Files != len(names) {
		t.Errorf("summary files %d != tar entries %d", sum.Files, len(names))
	}
}

func TestStreamPartial(t *testing.T) {
	// A walkPartial from the backend folds into Errors, not a hard failure.
	fsys := &partialFS{stubFS: sampleFS(), skipped: 3}
	var out, errBuf bytes.Buffer
	sum, err := streamVolume(&out, &errBuf, fsys, "", true)
	if err != nil {
		t.Fatalf("partial walk should not be fatal: %v", err)
	}
	if sum.Errors != 3 {
		t.Errorf("errors = %d, want 3", sum.Errors)
	}
}

// partialFS wraps stubFS to return a walkPartial after a clean walk.
type partialFS struct {
	*stubFS
	skipped int
}

func (p *partialFS) Walk(fn func(e fileEntry, open func() (io.ReadCloser, error)) error) error {
	if err := p.stubFS.Walk(fn); err != nil {
		return err
	}
	return &walkPartial{count: p.skipped, msg: "3 entries skipped"}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		filter, path string
		want         bool
	}{
		{"", "/a/b.txt", true},
		{"*.txt", "/a/b.txt", true},
		{"*.txt", "/a/b.exe", false},
		{"Windows/*", "/Windows/x", true},
		{"Windows/*", "/other/x", false},
	}
	for _, c := range cases {
		if got := matchGlob(c.filter, c.path); got != c.want {
			t.Errorf("matchGlob(%q,%q) = %v, want %v", c.filter, c.path, got, c.want)
		}
	}
}

func TestResolvePath(t *testing.T) {
	cases := []struct{ cwd, arg, want string }{
		{"/Windows", "System32", "/Windows/System32"},
		{"/Windows/System32", "..", "/Windows"},
		{"/Windows", "/Users", "/Users"},
		{"/", "note.txt", "/note.txt"},
	}
	for _, c := range cases {
		if got := resolvePath(c.cwd, c.arg); got != c.want {
			t.Errorf("resolvePath(%q,%q) = %q, want %q", c.cwd, c.arg, got, c.want)
		}
	}
}

func TestSplitFirst(t *testing.T) {
	cases := []struct{ line, cmd, rest string }{
		{"ls", "ls", ""},
		{"cd Folder A", "cd", "Folder A"},
		{"  cat  a b.txt ", "cat", "a b.txt"},
		{"", "", ""},
	}
	for _, c := range cases {
		cmd, rest := splitFirst(c.line)
		if cmd != c.cmd || rest != c.rest {
			t.Errorf("splitFirst(%q) = (%q,%q), want (%q,%q)", c.line, cmd, rest, c.cmd, c.rest)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs(`"Folder A/read me.txt" /tmp/out.txt`)
	want := []string{"Folder A/read me.txt", "/tmp/out.txt"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("splitArgs = %q, want %q", got, want)
	}
}

func TestBrowseSession(t *testing.T) {
	// "cd Folder A" exercises a path with a space (no quoting needed).
	in := strings.NewReader("pwd\ncd Folder A\nls\ncat read me.txt\ncd /\ncat /note.txt\nquit\n")
	var out, errBuf bytes.Buffer
	if rc := browse(sampleFS(), in, &out, &errBuf); rc != 0 {
		t.Fatalf("browse rc = %d", rc)
	}
	o := out.String()
	if !strings.Contains(o, "/Folder A> ") {
		t.Errorf("prompt did not follow `cd Folder A`:\n%s\nstderr:%s", o, errBuf.String())
	}
	if !strings.Contains(o, "read me.txt") || !strings.Contains(o, "ok") || !strings.Contains(o, "hello") {
		t.Errorf("browse ls/cat output missing:\n%s", o)
	}
}
