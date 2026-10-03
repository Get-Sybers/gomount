package hfsplus

// hfsplus_test: the backend over volumes built by hfstest — an HFSX and an
// HFS+ variant, and the HFS-wrapped form — covering the catalog with a real
// index level, fragmented forks through the overflow tree, links, extended
// attributes and every decmpfs shape the encoder writes; then a mutation
// pass proving that a corrupt header or node is an error, never a panic.

import (
	"bytes"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/hfsplus/hfstest"
)

var (
	bigData   = hfstest.BigData
	zlibData  = hfstest.ZlibData
	rawData   = hfstest.RawData
	inlineTxt = hfstest.InlineTxt
)

func fixture(t *testing.T, caseSensitive, wrapper bool) (*FS, []byte) {
	t.Helper()
	root := hfstest.Fixture()
	img := hfstest.Build(root, hfstest.Options{
		CaseSensitive: caseSensitive, Wrapper: wrapper, Label: "Macintosh HD",
		Inodes: map[uint32]hfstest.File{500: {Data: []byte("shared by two links\n"), UID: 501}},
	})
	// the linked inode's link count lives in its special field; the encoder
	// leaves it 0 (the backend then reports 1) — fine for these tests
	ra := bytes.NewReader(img)
	if got := fsx.Probe(ra, int64(len(img))); got != "hfsplus" {
		t.Fatalf("probe: %q", got)
	}
	f, err := Open(ra, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	return f, img
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

func TestInfoAndRoot(t *testing.T) {
	f, _ := fixture(t, true, false)
	info := f.Info()
	if info.Type != "hfsplus" || info.Label != "Macintosh HD" || info.BlockSize != 4096 {
		t.Fatalf("info: %+v", info)
	}
	if len(info.UUID) != 36 || info.UUID[14] != '3' {
		t.Fatalf("uuid %q is not a version-3 uuid", info.UUID)
	}
	if !f.HFSX() {
		t.Fatal("HFSX expected")
	}
	root, err := f.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range root {
		names = append(names, e.Name)
	}
	want := "System Users big.bin hard-a hard-b hosts link-to-hosts many raw-rsrc.bin tagged.txt zeros.bin zlib-inline.plist zlib-rsrc.txt ␀␀␀␀HFS+ Private Data"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("root:\n got %s\nwant %s", got, want)
	}
	st, err := f.Stat("/")
	if err != nil || !st.IsDir || st.Inode != 2 {
		t.Fatalf("stat /: %+v %v", st, err)
	}
}

func TestStatAndContent(t *testing.T) {
	f, _ := fixture(t, true, false)
	e, err := f.Stat("/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != 20 || e.Mode != 0x8000|0o644 || e.UID != 0 || e.IsDir || e.Inode < 16 {
		t.Fatalf("hosts: %+v", e)
	}
	if !e.Mtime.Equal(time.Date(2019, 7, 4, 9, 30, 0, 0, time.UTC)) || e.Btime.IsZero() || e.Ctime.IsZero() {
		t.Fatalf("hosts times: %s %s %s", e.Btime, e.Mtime, e.Ctime)
	}
	if got := readAll(t, f, "/hosts"); string(got) != "127.0.0.1 localhost\n" {
		t.Fatalf("hosts: %q", got)
	}
	// a fragmented fork through the overflow tree
	e, err = f.Stat("/big.bin")
	if err != nil || e.Size != int64(len(bigData)) || e.UID != 501 || e.GID != 20 {
		t.Fatalf("big.bin: %+v %v", e, err)
	}
	if got := readAll(t, f, "/big.bin"); !bytes.Equal(got, bigData) {
		t.Fatalf("big.bin: %d bytes, sha %x vs %x", len(got), sha256.Sum256(got), sha256.Sum256(bigData))
	}
	// nested paths
	if got := readAll(t, f, "/Users/alice/.zsh_history"); string(got) != "ls\n" {
		t.Fatalf("zsh_history: %q", got)
	}
	if _, err := f.Stat("/System/Library/CoreServices/SystemVersion.plist"); err != nil {
		t.Fatal(err)
	}
	// errors
	if _, err := f.Stat("/nope"); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("missing: %v", err)
	}
	if _, err := f.Stat("/hosts/x"); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file as dir: %v", err)
	}
	if _, err := f.Open("/Users"); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("open dir: %v", err)
	}
	if _, err := f.Stat("/HOSTS"); err == nil {
		t.Fatal("HFSX is case-sensitive: /HOSTS must not resolve")
	}
}

func TestLinks(t *testing.T) {
	f, _ := fixture(t, true, false)
	e, err := f.Stat("/link-to-hosts")
	if err != nil || e.LinkTarget != "/private/etc/hosts" || e.Mode&sIFMT != sIFLNK {
		t.Fatalf("symlink: %+v %v", e, err)
	}
	if got := readAll(t, f, "/link-to-hosts"); string(got) != "/private/etc/hosts" {
		t.Fatalf("symlink content: %q", got)
	}
	var inodes []uint64
	for _, p := range []string{"/hard-a", "/hard-b"} {
		e, err := f.Stat(p)
		if err != nil || e.Size != 20 || e.Mode != 0x8000|0o600 || e.IsDir {
			t.Fatalf("%s: %+v %v", p, e, err)
		}
		inodes = append(inodes, e.Inode)
		if got := readAll(t, f, p); string(got) != "shared by two links\n" {
			t.Fatalf("%s: %q", p, got)
		}
	}
	// the private directory and its indirect node are listed, honestly —
	// and both links carry the indirect node's identity
	ents, err := f.ReadDir("/␀␀␀␀HFS+ Private Data")
	if err != nil || len(ents) != 1 || ents[0].Name != "iNode500" {
		t.Fatalf("private dir: %+v %v", ents, err)
	}
	if inodes[0] != inodes[1] || inodes[0] != ents[0].Inode {
		t.Fatalf("hard links must share the indirect node's inode: %v vs %d", inodes, ents[0].Inode)
	}
}

func TestXattrsAndDecmpfs(t *testing.T) {
	f, _ := fixture(t, true, false)
	e, err := f.Stat("/tagged.txt")
	if err != nil {
		t.Fatal(err)
	}
	xs, err := f.xattrs(uint32(e.Inode))
	if err != nil || len(xs) != 2 || xs[0].name != "com.apple.quarantine" || string(xs[1].data) != "a note" {
		t.Fatalf("xattrs: %+v %v", xs, err)
	}
	if got := readAll(t, f, "/tagged.txt"); string(got) != "tagged\n" {
		t.Fatalf("tagged: %q", got)
	}
	cases := map[string][]byte{
		"/zlib-inline.plist": inlineTxt,
		"/zlib-rsrc.txt":     zlibData,
		"/raw-rsrc.bin":      rawData,
		"/zeros.bin":         make([]byte, 100000),
	}
	for p, want := range cases {
		e, err := f.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if e.Size != int64(len(want)) {
			t.Errorf("%s: size %d, want %d (the decmpfs header's)", p, e.Size, len(want))
		}
		if got := readAll(t, f, p); !bytes.Equal(got, want) {
			t.Errorf("%s: %d bytes, mismatch (first differing byte %d)", p, len(got), firstDiff(got, want))
		}
	}
}

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func TestWalkAndIndexNodes(t *testing.T) {
	f, _ := fixture(t, true, false)
	if f.catalog.root == f.catalog.firstLeaf {
		t.Fatal("the fixture's catalog should have an index level")
	}
	count, files, opened := 0, 0, 0
	var sawMany int
	err := f.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		count++
		if e.Path == "" || !strings.HasPrefix(e.Path, "/") || e.Name == "" {
			t.Fatalf("entry without a path: %+v", e)
		}
		if strings.HasPrefix(e.Path, "/many/") {
			sawMany++
		}
		if open != nil {
			files++
			if strings.HasPrefix(e.Path, "/many/file-1") {
				r, err := open()
				if err != nil {
					return err
				}
				b, _ := io.ReadAll(r)
				r.Close()
				if !strings.HasPrefix(string(b), "content 1") {
					t.Fatalf("%s: %q", e.Path, b)
				}
				opened++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sawMany != 300 || opened != 100 || files < 310 || count < 320 {
		t.Fatalf("walk: %d entries, %d files, %d under many, %d opened", count, files, sawMany, opened)
	}
	// ReadDir over the index level lists every record in key order
	ents, err := f.ReadDir("/many")
	if err != nil || len(ents) != 300 || ents[0].Name != "file-000.txt" || ents[299].Name != "file-299.txt" {
		t.Fatalf("many: %d entries %v", len(ents), err)
	}
}

func TestCaseInsensitiveAndWrapper(t *testing.T) {
	f, _ := fixture(t, false, true)
	if f.HFSX() {
		t.Fatal("HFS+ expected")
	}
	if got := readAll(t, f, "/HOSTS"); string(got) != "127.0.0.1 localhost\n" {
		t.Fatalf("case-insensitive lookup: %q", got)
	}
	if got := readAll(t, f, "/users/ALICE/.ZSH_HISTORY"); string(got) != "ls\n" {
		t.Fatalf("case-insensitive nested lookup: %q", got)
	}
	if got := readAll(t, f, "/big.bin"); !bytes.Equal(got, bigData) {
		t.Fatal("big.bin through the wrapper")
	}
	if got := readAll(t, f, "/zlib-rsrc.txt"); !bytes.Equal(got, zlibData) {
		t.Fatal("zlib rsrc through the wrapper")
	}
}

// A corrupt volume is an error, never a panic: flip bytes across the
// header and the catalog's first nodes and drive every verb.
func TestCorruptionNeverPanics(t *testing.T) {
	_, img := fixture(t, true, false)
	drive := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		ra := bytes.NewReader(b)
		f, err := Open(ra, int64(len(b)))
		if err != nil {
			return
		}
		f.ReadDir("/")
		f.Stat("/big.bin")
		f.Stat("/many/file-150.txt")
		if r, err := f.Open("/zlib-rsrc.txt"); err == nil {
			io.Copy(io.Discard, r)
			r.Close()
		}
		f.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
			if open != nil {
				if r, err := open(); err == nil {
					io.CopyN(io.Discard, r, 4096)
					r.Close()
				}
			}
			return nil
		})
	}
	// the volume header, then every 64th byte of the first 64 KiB of the
	// catalog file (its header node and first leaves)
	catStart := int64(be32(img[1024+272+16:])) * 4096
	for off := int64(1024); off < 1024+512; off += 4 {
		m := append([]byte(nil), img...)
		m[off] ^= 0xff
		drive(m)
	}
	for off := catStart; off < catStart+65536 && off < int64(len(img)); off += 64 {
		m := append([]byte(nil), img...)
		m[off] ^= 0x55
		drive(m)
	}
	// truncated
	drive(img[:len(img)/3])
	drive(img[:2000])
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func TestHFSTime(t *testing.T) {
	if !hfsTime(0).IsZero() {
		t.Fatal("0 must be an honest null")
	}
	if got := hfsTime(3061152000); !got.Equal(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("2001-01-01: %s", got)
	}
}
