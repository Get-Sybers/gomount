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
	sum, err := streamVolume(&out, &errBuf, sampleFS(), "*.exe", true, false)
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
	sum, err := streamVolume(&out, &errBuf, sampleFS(), "", false, false)
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
	sum, err := streamVolume(&out, &errBuf, fsys, "", true, false)
	if err != nil {
		t.Fatalf("partial walk should not be fatal: %v", err)
	}
	if sum.Errors != 3 {
		t.Errorf("errors = %d, want 3", sum.Errors)
	}
}

// treeFS wraps stubFS with the treeWalker seam: WalkAll hands out every
// directory and symlink too, with a POSIX identity on each, the way the
// fsx backends do.
type treeFS struct{ *stubFS }

func (f *treeFS) WalkAll(fn func(e fileEntry, open func() (io.ReadCloser, error)) error) error {
	return f.walkAll("/", fn)
}

func (f *treeFS) walkAll(dir string, fn func(fileEntry, func() (io.ReadCloser, error)) error) error {
	for _, e := range f.dirs[dir] {
		if e.Deleted {
			continue
		}
		child := path.Join(dir, e.Name)
		e.Path = child
		if e.IsDir || e.LinkTarget != "" {
			if err := fn(e, nil); err != nil {
				return err
			}
			if e.IsDir {
				if err := f.walkAll(child, fn); err != nil {
					return err
				}
			}
			continue
		}
		open := func() (io.ReadCloser, error) { return f.Open(child) }
		if err := fn(e, open); err != nil {
			return err
		}
	}
	return nil
}

// posixFS is sampleFS with a Linux shape: owners, modes, a symlink.
func posixFS() *treeFS {
	s := sampleFS()
	s.dirs["/"] = append(s.dirs["/"],
		fileEntry{Name: "etc", IsDir: true, Mode: 0o40755, UID: 0, GID: 0, Mtime: mtime, MFTID: "100"},
		// type bits, no permission bits: a directory a UAC collection only implies
		fileEntry{Name: "var", IsDir: true, Mode: 0o40000, Mtime: mtime, MFTID: "105"},
	)
	s.dirs["/var"] = []fileEntry{
		{Name: "log", IsDir: true, Mode: 0o40000, Mtime: mtime, MFTID: "106"},
	}
	s.dirs["/etc"] = []fileEntry{
		{Name: "passwd", Size: 6, Mode: 0o100644, UID: 0, GID: 0, Mtime: mtime, Atime: mtime.Add(time.Hour), Ctime: mtime, MFTID: "101"},
		{Name: "localtime", Mode: 0o120777, LinkTarget: "/usr/share/zoneinfo/UTC", Mtime: mtime, MFTID: "102"},
		{Name: "secret", Size: 3, Mode: 0o100600, UID: 1000, GID: 1000, Mtime: mtime, MFTID: "103"},
		{Name: "null", Mode: 0o20666, MFTID: "104"}, // a device node: never streamed
	}
	s.files["/etc/passwd"] = []byte("root:x")
	s.files["/etc/secret"] = []byte("key")
	return &treeFS{s}
}

// TestStreamAll: --all carries the whole tree — directories, symlinks and
// the identity on each entry — where the default stream carries read-only
// regular files alone.
func TestStreamAll(t *testing.T) {
	var out, errBuf bytes.Buffer
	sum, err := streamVolume(&out, &errBuf, posixFS(), "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*tar.Header{}
	tr := tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		h := *hdr
		got[hdr.Name] = &h
	}
	cases := []struct {
		name     string
		typeflag byte
		mode     int64
		uid      int
		link     string
	}{
		{"etc/", tar.TypeDir, 0o755, 0, ""},
		{"etc/passwd", tar.TypeReg, 0o644, 0, ""},
		{"etc/secret", tar.TypeReg, 0o600, 1000, ""},
		{"etc/localtime", tar.TypeSymlink, 0o777, 0, "/usr/share/zoneinfo/UTC"},
		{"Windows/", tar.TypeDir, 0o755, 0, ""}, // no mode on the entry: the enterable default
		{"var/", tar.TypeDir, 0o755, 0, ""},     // type bits alone (an implied directory): the enterable default
		{"var/log/", tar.TypeDir, 0o755, 0, ""},
		{"note.txt", tar.TypeReg, 0o400, 0, ""}, // no mode on the entry: the read-only default
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, ok := got[c.name]
			if !ok {
				t.Fatalf("entry missing; have %v", keys(got))
			}
			if h.Typeflag != c.typeflag || h.Mode != c.mode || h.Uid != c.uid || h.Linkname != c.link {
				t.Errorf("header = type %q mode %o uid %d link %q, want type %q mode %o uid %d link %q",
					h.Typeflag, h.Mode, h.Uid, h.Linkname, c.typeflag, c.mode, c.uid, c.link)
			}
		})
	}
	if _, ok := got["etc/null"]; ok {
		t.Error("a device node was streamed")
	}
	if h := got["etc/passwd"]; h.AccessTime.IsZero() || h.Format != tar.FormatPAX {
		t.Errorf("the access time did not ride a PAX header: %+v", h)
	}
	// the summary counts files alone — the tree around them is structure
	if sum.Files != 5 {
		t.Errorf("files = %d, want 5", sum.Files)
	}
	// the default stream is unchanged: no directory, no symlink, mode 0400
	out.Reset()
	if _, err := streamVolume(&out, &errBuf, posixFS(), "", false, false); err != nil {
		t.Fatal(err)
	}
	tr = tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Mode != 0o400 || hdr.Uid != 0 {
			t.Errorf("default stream entry %s: type %q mode %o uid %d", hdr.Name, hdr.Typeflag, hdr.Mode, hdr.Uid)
		}
	}
}

// TestStreamAllFilterKeepsTheTree: a filter narrows the files, never the
// directories they hang in, so the extract still lands in place.
func TestStreamAllFilterKeepsTheTree(t *testing.T) {
	var out, errBuf bytes.Buffer
	sum, err := streamVolume(&out, &errBuf, posixFS(), "passwd", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Files != 1 {
		t.Errorf("files = %d, want 1", sum.Files)
	}
	var kinds []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var rec streamRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, rec.Path+":"+rec.Type)
		if rec.Path == "/etc/localtime" && rec.LinkTarget != "/usr/share/zoneinfo/UTC" {
			t.Errorf("symlink row lost its target: %+v", rec)
		}
	}
	want := "/Windows:dir"
	if !strings.Contains(strings.Join(kinds, " "), want) || !strings.Contains(strings.Join(kinds, " "), "/etc/passwd:") {
		t.Errorf("rows = %v", kinds)
	}
	for _, k := range kinds {
		if strings.HasSuffix(k, "cmd.exe:") {
			t.Errorf("a filtered-out file was streamed: %v", kinds)
		}
	}
}

// TestStreamAllNeedsTheTreeSeam: a backend without WalkAll (NTFS) refuses
// --all instead of silently streaming files alone.
func TestStreamAllNeedsTheTreeSeam(t *testing.T) {
	var out, errBuf bytes.Buffer
	if _, err := streamVolume(&out, &errBuf, sampleFS(), "", false, true); err == nil {
		t.Fatal("--all accepted on a files-only backend")
	}
}

func keys(m map[string]*tar.Header) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
