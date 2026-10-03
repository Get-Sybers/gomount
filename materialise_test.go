package main

// Tests for the `materialise` verb.
//
// The end-to-end tests format a superfloppy NTFS image with mkntfs and seed it
// with ntfscp, exactly as ntfsfs_test.go does — so they run with only ntfs-3g
// (mkntfs/ntfscp), no FUSE, no /dev/fuse, no privilege. A fresh mkntfs volume
// exposes only the root and the system $Extend directory, and ntfscp can create
// FILES but not DIRECTORIES, so the fixture is seeded at the volume root and
// inside the pre-existing $Extend directory. That is enough to drive every
// materialise code path over a REAL parsed volume: the whole runMaterialise
// pipeline (open -> resolve -> copy -> manifest -> summary/exit) via --select,
// and the artefact-set primary/sibling resolution (matchPrimaries, resolveSet)
// that the deep Windows sets rely on — the only thing that differs for a real
// \Windows\System32\config\SYSTEM set is the fixed path prefix.
//
// When mkntfs/ntfscp are absent the end-to-end tests skip cleanly, so `go test`
// still passes in a bare environment while a golang:trixie container with
// ntfs-3g runs them for real. The catalogue test needs no image and runs always.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---- catalogue (pure, runs anywhere) ----------------------------------------

// TestMaterialiseCatalogue decodes the embedded materialise-sets.yml and asserts
// the go:embed + YAML parse yields the eight named sets with their primaries and
// sibling suffixes intact — the data file the verb reads instead of hardcoding.
func TestMaterialiseCatalogue(t *testing.T) {
	sets, err := loadArtefactSets()
	if err != nil {
		t.Fatalf("loadArtefactSets: %v", err)
	}
	want := []string{"amcache", "linux-core", "macos-core", "macos-system", "mft", "ntuser", "prefetch", "recent", "recyclebin", "registry-core", "shimcache", "srum", "sum", "timeline", "usrclass", "windows-core", "winevt"}
	got := sortedSetNames(sets)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("set names = %v, want %v", got, want)
	}

	if n := len(sets["registry-core"].Primaries); n != 4 {
		t.Errorf("registry-core primaries = %d, want 4", n)
	}
	if s := sets["registry-core"].Siblings; len(s) != 2 || s[0] != ".LOG1" || s[1] != ".LOG2" {
		t.Errorf("registry-core siblings = %v, want [.LOG1 .LOG2]", s)
	}
	if s := sets["srum"].Siblings; len(s) != 0 {
		t.Errorf("srum siblings = %v, want none", s)
	}
	if s := sets["timeline"].Siblings; len(s) != 2 || s[0] != "-wal" || s[1] != "-shm" {
		t.Errorf("timeline siblings = %v, want [-wal -shm]", s)
	}
	if p := sets["sum"].Primaries; len(p) != 1 || !strings.HasSuffix(p[0], `SUM\*.mdb`) {
		t.Errorf("sum primaries = %v, want a ...SUM\\*.mdb glob", p)
	}
}

// ---- end-to-end over a real mkntfs image (mkntfs/ntfscp, no FUSE) -----------

// matSeed is one file written into the image: its in-image path (/-separated,
// no leading slash) and its bytes.
type matSeed struct {
	dest string
	data []byte
}

// matFixture seeds, at the volume root, a SYSTEM primary hive with its .LOG1 /
// .LOG2 transaction-log siblings, and, inside the pre-existing $Extend system
// directory, an NTUSER.DAT primary with its two siblings. Root + $Extend are the
// only locations ntfscp can write into on a fresh mkntfs volume, and together
// they exercise both a root selection and a nested-directory resolution.
func matFixture() []matSeed {
	return []matSeed{
		{"SYSTEM", []byte("SYSTEM-hive-primary")},
		{"SYSTEM.LOG1", []byte("SYSTEM-transaction-log-1")},
		{"SYSTEM.LOG2", []byte("SYSTEM-transaction-log-2")},
		{"$Extend/NTUSER.DAT", []byte("NTUSER-hive-primary")},
		{"$Extend/NTUSER.DAT.LOG1", []byte("NTUSER-transaction-log-1")},
		{"$Extend/NTUSER.DAT.LOG2", []byte("NTUSER-transaction-log-2")},
	}
}

// buildMatImage formats a superfloppy NTFS image and seeds the fixture with
// ntfscp. It skips the test when mkntfs or ntfscp is absent.
func buildMatImage(t *testing.T) string {
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
	matRun(t, "mkntfs", "-F", "-Q", "-L", "MATVOL", img)
	for i, s := range matFixture() {
		src := filepath.Join(dir, fmt.Sprintf("seed%d.bin", i))
		if err := os.WriteFile(src, s.data, 0o600); err != nil {
			t.Fatal(err)
		}
		matRun(t, "ntfscp", img, src, s.dest)
	}
	return img
}

func matRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// openMatFS drives the real gomount open pipeline (the same openVolumeFS the
// verb uses) and returns the volumeFS over the seeded image.
func openMatFS(t *testing.T, img string) (volumeFS, func() error) {
	t.Helper()
	fsys, closer, err := openVolumeFS(img, 0, "")
	if err != nil {
		t.Fatalf("openVolumeFS: %v", err)
	}
	return fsys, closer
}

// TestMaterialiseSelectEndToEnd drives the whole runMaterialise verb through an
// ad-hoc --select over a real parsed volume: it copies the SYSTEM* root files to
// <out>/<volume-path> at mode 0o400, byte-for-byte, writes the manifest, leaves
// the source image untouched, and exits 0.
func TestMaterialiseSelectEndToEnd(t *testing.T) {
	img := buildMatImage(t)
	before := sha256File(t, img)
	out := t.TempDir()

	rc := runMaterialise([]string{"--select", "SYSTEM*", "--out", out, "--manifest", img})
	if rc != 0 {
		t.Fatalf("runMaterialise rc = %d, want 0", rc)
	}

	want := map[string][]byte{}
	for _, s := range matFixture() {
		if !strings.Contains(s.dest, "/") { // root SYSTEM* files
			want[s.dest] = s.data
		}
	}
	if len(want) != 3 {
		t.Fatalf("fixture sanity: %d root SYSTEM files, want 3", len(want))
	}
	for rel, data := range want {
		dest := filepath.Join(out, rel)
		info, err := os.Stat(dest)
		if err != nil {
			t.Errorf("expected %s pulled: %v", rel, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o400 {
			t.Errorf("%s mode = %#o, want 0400", rel, perm)
		}
		got, err := os.ReadFile(dest) // a 0o400 file is readable by its owner
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s content = %q, want %q", rel, got, data)
		}
	}

	// The source image is byte-for-byte unchanged: read-only end to end.
	if after := sha256File(t, img); after != before {
		t.Errorf("source image mutated: sha256 %s -> %s", before, after)
	}

	// The manifest lists exactly the three pulled files, keyed by canonical
	// volume path (leading slash), and nothing else.
	manifest := readManifest(t, filepath.Join(out, "materialise.jsonl"))
	for rel := range want {
		rec, ok := manifest["/"+rel]
		if !ok {
			t.Errorf("manifest missing /%s (have %v)", rel, manifestKeys(manifest))
			continue
		}
		if rec.Size != int64(len(want[rel])) {
			t.Errorf("manifest /%s size = %d, want %d", rel, rec.Size, len(want[rel]))
		}
		if rec.MFTID == "" {
			t.Errorf("manifest /%s has empty mftid", rel)
		}
	}
	if len(manifest) != 3 {
		t.Errorf("manifest has %d entries, want 3 (%v)", len(manifest), manifestKeys(manifest))
	}
}

// TestMaterialiseSetSiblings proves the artefact-set primary + sibling
// resolution the deep Windows sets rely on: a primary resolves to its file and,
// with siblings on, co-pulls the .LOG1/.LOG2 from the same directory; with
// siblings off it pulls the primary alone. It uses the SYSTEM* root fixture via
// an artefactSet built in the test (the resolution code is identical for a real
// \Windows\System32\config\SYSTEM primary — only the path prefix differs).
func TestMaterialiseSetSiblings(t *testing.T) {
	fsys, closer := openMatFS(t, buildMatImage(t))
	defer closer()

	set := artefactSet{Primaries: []string{"/SYSTEM"}, Siblings: []string{".LOG1", ".LOG2"}}

	on := newTargetSet()
	resolveSet(fsys, set, true, on)
	if got := sortedPaths(on); strings.Join(got, ",") != "/SYSTEM,/SYSTEM.LOG1,/SYSTEM.LOG2" {
		t.Errorf("resolveSet siblings=on = %v, want SYSTEM + .LOG1 + .LOG2", got)
	}

	off := newTargetSet()
	resolveSet(fsys, set, false, off)
	if got := sortedPaths(off); strings.Join(got, ",") != "/SYSTEM" {
		t.Errorf("resolveSet siblings=off = %v, want just /SYSTEM", got)
	}
}

// TestMaterialisePrimaryGlob proves a glob path component is expanded by
// directory enumeration (as \Users\*\NTUSER.DAT and ...\SUM\*.mdb are): a
// literal nested primary resolves to one file, and a "*" leaf under $Extend
// enumerates the directory's files.
func TestMaterialisePrimaryGlob(t *testing.T) {
	fsys, closer := openMatFS(t, buildMatImage(t))
	defer closer()

	lit := matchPrimaries(fsys, `$Extend\NTUSER.DAT`)
	if len(lit) != 1 || lit[0].Path != "/$Extend/NTUSER.DAT" {
		t.Errorf("matchPrimaries literal = %v, want one /$Extend/NTUSER.DAT", pathsOf(lit))
	}

	glob := matchPrimaries(fsys, `$Extend\*`)
	names := map[string]bool{}
	for _, e := range glob {
		names[e.Path] = true
	}
	for _, p := range []string{"/$Extend/NTUSER.DAT", "/$Extend/NTUSER.DAT.LOG1", "/$Extend/NTUSER.DAT.LOG2"} {
		if !names[p] {
			t.Errorf("matchPrimaries glob missing %s (got %v)", p, pathsOf(glob))
		}
	}
}

// TestMaterialiseMatchlessOK proves a selector that matches nothing is not an
// error: the run copies zero files and still exits 0 (a real image legitimately
// lacks some artefacts).
func TestMaterialiseMatchlessOK(t *testing.T) {
	img := buildMatImage(t)
	out := t.TempDir()
	// nothing pulled is the batch table's exit 1 ("nothing"), never a failure
	rc := runMaterialise([]string{"--select", "NO-SUCH-FILE*", "--out", out, img})
	if rc != 1 {
		t.Fatalf("runMaterialise matchless rc = %d, want 0", rc)
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 0 {
		t.Errorf("matchless run wrote %d entries into --out, want 0", len(entries))
	}
}

// TestMaterialiseUnknownSet proves an unknown --set name is rejected up front
// (exit 1) before the image is touched.
func TestMaterialiseUnknownSet(t *testing.T) {
	img := buildMatImage(t)
	out := t.TempDir()
	if rc := runMaterialise([]string{"--set", "not-a-set", "--out", out, img}); rc != 2 {
		t.Errorf("unknown --set rc = %d, want 1", rc)
	}
}

// TestMaterialiseContainmentGuard proves a crafted volume path that would escape
// --out is refused and nothing is written outside the output directory. It calls
// materialiseFile directly with a hostile entry, since a real parsed volume
// cannot produce such a path.
func TestMaterialiseContainmentGuard(t *testing.T) {
	fsys, closer := openMatFS(t, buildMatImage(t))
	defer closer()

	out := t.TempDir()
	evil := fileEntry{Path: "/../../evil", Name: "evil"}
	if _, err := materialiseFile(fsys, evil, out); err == nil {
		t.Error("materialiseFile accepted an out-of-tree path, want refusal")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(out), "evil")); err == nil {
		t.Error("containment guard breached: an evil file was written outside --out")
	}
}

// ---- helpers ----------------------------------------------------------------

func sortedPaths(t *targetSet) []string {
	out := make([]string, 0, len(t.byPath))
	for _, e := range t.sorted() {
		out = append(out, e.Path)
	}
	return out
}

func pathsOf(es []fileEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readManifest(t *testing.T, path string) map[string]materialiseRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	out := map[string]materialiseRecord{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r materialiseRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad manifest line %q: %v", line, err)
		}
		out[r.Path] = r
	}
	return out
}

func manifestKeys(m map[string]materialiseRecord) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// cyclicFS is a stub whose root always contains one subdirectory and one
// file — an unbounded tree — to pin the "**" depth guard.
type cyclicFS struct{}

func (cyclicFS) ReadDir(dir string) ([]fileEntry, error) {
	return []fileEntry{
		{Name: "loop", Path: dir + "/loop", IsDir: true},
		{Name: "f.txt", Path: dir + "/f.txt", Size: 1},
	}, nil
}
func (c cyclicFS) Stat(p string) (fileEntry, error) {
	if strings.HasSuffix(p, "f.txt") {
		return fileEntry{Name: "f.txt", Path: p, Size: 1}, nil
	}
	return fileEntry{Name: "loop", Path: p, IsDir: true}, nil
}
func (cyclicFS) Open(string) (io.ReadCloser, error) { return nil, errors.New("stub") }
func (cyclicFS) Walk(func(fileEntry, func() (io.ReadCloser, error)) error) error {
	return nil
}

// TestDoubleStarDepthBound: a pathologically deep (here: endless) tree
// terminates instead of recursing without bound (PR #70 review).
func TestDoubleStarDepthBound(t *testing.T) {
	got := matchPrimaries(cyclicFS{}, "start/**/f.txt")
	if len(got) == 0 || len(got) > 70 {
		t.Fatalf("depth-bounded expansion returned %d entries", len(got))
	}
}

// TestSanitizeComponent pins that residue ids can never inject path
// syntax into the staged layout (PR #70 review).
func TestSanitizeComponent(t *testing.T) {
	for in, want := range map[string]string{
		".":          "_",
		"..":         "_",
		"":           "_",
		"a/../b":     "a_.._b", // separators die before the dots can act
		"inode-42":   "inode-42",
		"file.txt":   "file.txt",
		"we ird\x00": "we_ird_",
	} {
		if got := sanitizeComponent(in); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
