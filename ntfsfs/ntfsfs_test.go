package ntfsfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/get-sybers/gomount/image"
	"github.com/get-sybers/gomount/ntfsvol"
	"github.com/get-sybers/gomount/partition"
)

// ---- pure unit tests (run anywhere, no ntfs-3g needed) ----------------------

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"/":                    "",
		".":                    "",
		"\\":                   "",
		"/Users/test":          "Users/test",
		"Users/test/":          "Users/test",
		"\\Users\\test\\f.txt": "Users/test/f.txt",
		"/f.txt:zone":          "f.txt",
		"dir/f:$stream":        "dir/f",
	}
	for in, want := range cases {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdsFromPath(t *testing.T) {
	cases := map[string]string{
		"f.txt":              "",
		"/dir/f.txt":         "",
		"/dir/f.txt:Zone.Id": "Zone.Id",
		"f:secret":           "secret",
	}
	for in, want := range cases {
		if got := adsFromPath(in); got != want {
			t.Errorf("adsFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	if got := joinPath("", "f.txt"); got != "/f.txt" {
		t.Errorf(`joinPath("","f.txt") = %q`, got)
	}
	if got := joinPath("Users/test", "f.txt"); got != "/Users/test/f.txt" {
		t.Errorf("joinPath = %q", got)
	}
}

// ---- end-to-end tests over a real mkntfs image ------------------------------

// pattern fills n bytes with a deterministic, position-dependent value so a
// mis-offset or truncated read is detectable.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

// seed is one file (or named ADS) written into the image with ntfscp. dest is the
// in-image path; attr is a named alternate data stream ("" = default $DATA).
type seed struct {
	dest string
	attr string
	data []byte
}

// The fixture: three root files (resident, small, and large/non-resident), one
// file nested in the pre-existing $Extend directory, and a file carrying a named
// ADS. Order matters — the ADS base file is written before its stream.
var (
	alpha  = seed{dest: "alpha.txt", data: []byte("hello ntfs world\n")} // 17, resident
	beta   = seed{dest: "beta.bin", data: pattern(5000)}
	gamma  = seed{dest: "gamma.dat", data: pattern(200000)} // non-resident
	nested = seed{dest: "$Extend/nested.bin", data: pattern(1234)}
	hostBS = seed{dest: "host.txt", data: []byte("base-content")}                    // 12
	hostAD = seed{dest: "host.txt", attr: "secret", data: []byte("ADS-SECRET-DATA")} // 15
)

func fixture() []seed { return []seed{alpha, beta, gamma, nested, hostBS, hostAD} }

// buildImage formats a fresh superfloppy NTFS image with mkntfs and copies each
// seed into it with ntfscp (-N for a named ADS). It skips the test when the
// ntfs-3g tools are absent, so `go test` still passes in a bare environment while
// the golang:trixie container (with ntfs-3g) runs it for real.
func buildImage(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"mkntfs", "ntfscp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found (install ntfs-3g to run this test): %v", tool, err)
		}
	}

	dir := t.TempDir()
	img := filepath.Join(dir, "vol.img")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Truncate(img, 24<<20); err != nil { // 24 MiB backing file
		t.Fatal(err)
	}

	run := func(name string, args ...string) {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("mkntfs", "-F", "-Q", "-L", "TESTVOL", img)
	for i, s := range fixture() {
		src := filepath.Join(dir, fmt.Sprintf("src%d.bin", i))
		if err := os.WriteFile(src, s.data, 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{}
		if s.attr != "" {
			args = append(args, "-N", s.attr)
		}
		args = append(args, img, src, s.dest)
		run("ntfscp", args...)
	}
	return img
}

// openImageFS drives the real gomount pipeline (open image -> pick NTFS volume
// -> read geometry -> bounded volume reader) and returns an ntfsfs.FS over it.
func openImageFS(t *testing.T, img string) (*FS, func()) {
	t.Helper()
	ra, size, closeImage, err := image.OpenImage(img)
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	parts, err := partition.Partitions(ra, size)
	if err != nil {
		closeImage()
		t.Fatalf("Partitions: %v", err)
	}
	sel, _, err := partition.SelectNTFSVolume(parts, -1)
	if err != nil {
		closeImage()
		t.Fatalf("SelectNTFSVolume: %v", err)
	}
	geom, err := ntfsvol.ReadNTFSGeometry(ra, sel.Offset, sel.Size)
	if err != nil {
		closeImage()
		t.Fatalf("ReadNTFSGeometry: %v", err)
	}
	fs, err := Open(ntfsvol.VolumeReader(ra, sel.Offset, geom), 0)
	if err != nil {
		closeImage()
		t.Fatalf("ntfsfs.Open: %v", err)
	}
	return fs, func() { fs.Close(); closeImage() }
}

func TestReadDirAndStat(t *testing.T) {
	fs, done := openImageFS(t, buildImage(t))
	defer done()

	entries, err := fs.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}

	for _, s := range []seed{alpha, beta, gamma} {
		e, ok := byName[s.dest]
		if !ok {
			t.Fatalf("seeded file %q missing from root listing", s.dest)
		}
		if e.IsDir {
			t.Errorf("%q reported as directory", s.dest)
		}
		if e.Deleted {
			t.Errorf("%q reported as deleted", s.dest)
		}
		if e.Size != int64(len(s.data)) {
			t.Errorf("%q size = %d, want %d", s.dest, e.Size, len(s.data))
		}
		if e.Path != "/"+s.dest {
			t.Errorf("%q path = %q, want %q", s.dest, e.Path, "/"+s.dest)
		}
		if e.MFTID <= 0 {
			t.Errorf("%q MFTID = %d, want > 0", s.dest, e.MFTID)
		}
		if e.Mtime.IsZero() {
			t.Errorf("%q has zero Mtime", s.dest)
		}
	}

	// mkntfs always creates the $Extend system directory: proves directory
	// detection and that system metafiles are surfaced (a raw forensic view).
	ext, ok := byName["$Extend"]
	if !ok {
		t.Fatal("$Extend system directory missing from root listing")
	}
	if !ext.IsDir {
		t.Error("$Extend not reported as a directory")
	}

	st, err := fs.Stat("/beta.bin")
	if err != nil {
		t.Fatalf("Stat(/beta.bin): %v", err)
	}
	if st.Size != 5000 || st.IsDir || st.Path != "/beta.bin" {
		t.Errorf("Stat(/beta.bin) = %+v", st)
	}

	root, err := fs.Stat("/")
	if err != nil {
		t.Fatalf("Stat(/): %v", err)
	}
	if !root.IsDir || root.Path != "/" || root.MFTID != rootMFT {
		t.Errorf("Stat(/) = %+v, want dir at MFT 5", root)
	}
}

// TestADS proves the named alternate data stream is reported in the base file's
// Streams and read back independently of the default $DATA, via both the
// "path:stream" syntax and OpenStream.
func TestADS(t *testing.T) {
	fs, done := openImageFS(t, buildImage(t))
	defer done()

	st, err := fs.Stat("/host.txt")
	if err != nil {
		t.Fatalf("Stat(/host.txt): %v", err)
	}
	if st.Size != int64(len(hostBS.data)) {
		t.Errorf("host.txt default size = %d, want %d", st.Size, len(hostBS.data))
	}
	if len(st.Streams) != 1 || st.Streams[0] != "secret" {
		t.Fatalf("host.txt Streams = %v, want [secret]", st.Streams)
	}

	// Default stream.
	rc, err := fs.Open("/host.txt")
	if err != nil {
		t.Fatalf("Open(/host.txt): %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, hostBS.data) {
		t.Errorf("host.txt default = %q, want %q", got, hostBS.data)
	}

	// Named ADS via the "path:stream" syntax and via OpenStream.
	for _, open := range []func() (io.ReadCloser, error){
		func() (io.ReadCloser, error) { return fs.Open("/host.txt:secret") },
		func() (io.ReadCloser, error) { return fs.OpenStream("/host.txt", "secret") },
	} {
		rc, err := open()
		if err != nil {
			t.Fatalf("open ADS: %v", err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, hostAD.data) {
			t.Errorf("host.txt:secret = %q, want %q", got, hostAD.data)
		}
	}
}

func TestNestedReadDir(t *testing.T) {
	fs, done := openImageFS(t, buildImage(t))
	defer done()

	entries, err := fs.ReadDir("/$Extend")
	if err != nil {
		t.Fatalf("ReadDir(/$Extend): %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	nb, ok := byName["nested.bin"]
	if !ok {
		t.Fatal("nested.bin missing from /$Extend listing")
	}
	if nb.Size != int64(len(nested.data)) || nb.Path != "/$Extend/nested.bin" {
		t.Errorf("nested.bin = %+v", nb)
	}
	for _, name := range []string{"$ObjId", "$Quota", "$Reparse"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("expected /$Extend/%s in nested listing", name)
		}
	}
}

func TestReadBackByteIdentical(t *testing.T) {
	fs, done := openImageFS(t, buildImage(t))
	defer done()

	for _, s := range []seed{alpha, beta, gamma} {
		rc, err := fs.Open("/" + s.dest)
		if err != nil {
			t.Fatalf("Open(/%s): %v", s.dest, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read /%s: %v", s.dest, err)
		}
		if !bytes.Equal(got, s.data) {
			t.Fatalf("/%s content mismatch: got %d bytes, want %d", s.dest, len(got), len(s.data))
		}
	}
}

func TestWalk(t *testing.T) {
	fs, done := openImageFS(t, buildImage(t))
	defer done()

	type walked struct {
		size    int64
		content []byte
	}
	files := map[string]walked{}
	err := fs.Walk(func(e Entry, open func() (io.ReadCloser, error)) error {
		if e.IsDir {
			t.Errorf("Walk yielded a directory: %q", e.Path)
		}
		var content []byte
		if e.Path == "/beta.bin" {
			rc, oerr := open()
			if oerr != nil {
				return oerr
			}
			content, _ = io.ReadAll(rc)
			rc.Close()
		}
		files[e.Path] = walked{size: e.Size, content: content}
		return nil
	})
	if we, ok := err.(*WalkErrors); ok {
		t.Logf("walk skipped %d entr(y/ies) (tolerated): %v", we.Count, we.Error())
	} else if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// Root files (default streams) are all reached at their full paths.
	for _, s := range []seed{alpha, beta, gamma, hostBS} {
		w, ok := files["/"+s.dest]
		if !ok {
			t.Errorf("Walk did not visit /%s", s.dest)
			continue
		}
		if w.size != int64(len(s.data)) {
			t.Errorf("/%s walk size = %d, want %d", s.dest, w.size, len(s.data))
		}
	}
	if got := files["/beta.bin"].content; !bytes.Equal(got, beta.data) {
		t.Errorf("/beta.bin content via Walk opener mismatch (%d bytes)", len(got))
	}

	// Recursion into a subdirectory: the file seeded under $Extend is reached at
	// its nested full path (proves descent + GetFullPath, not just a flat root).
	if w, ok := files["/$Extend/nested.bin"]; !ok {
		t.Error("Walk did not descend into /$Extend (nested.bin not visited)")
	} else if w.size != int64(len(nested.data)) {
		t.Errorf("/$Extend/nested.bin size = %d, want %d", w.size, len(nested.data))
	}
}

// TestOffsetFolding proves Open honours a non-zero volume offset: opening the
// whole-image reader at the partition's byte offset lists the same root as
// opening the already-bounded volume reader at offset 0.
func TestOffsetFolding(t *testing.T) {
	img := buildImage(t)

	ra, size, closeImage, err := image.OpenImage(img)
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	defer closeImage()
	parts, err := partition.Partitions(ra, size)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	sel, _, err := partition.SelectNTFSVolume(parts, -1)
	if err != nil {
		t.Fatalf("SelectNTFSVolume: %v", err)
	}

	fs, err := Open(ra, sel.Offset)
	if err != nil {
		t.Fatalf("Open(image, offset=%d): %v", sel.Offset, err)
	}
	defer fs.Close()

	entries, err := fs.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "alpha.txt" && e.Size == 17 {
			found = true
		}
	}
	if !found {
		t.Fatalf("alpha.txt not found via offset=%d open", sel.Offset)
	}
}
