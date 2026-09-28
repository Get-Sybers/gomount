package main

// timeline + identify tests over the committed fixtures: the identify
// document's stack view, and timeline rows with pinned times, allocation
// state, residue rows and content hashes.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sybers/gomount/image"
)

func TestIdentifyLVMStack(t *testing.T) {
	doc, err := identifyImageFile(fixturePath(t, "lvm"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Image.Format != "raw" || len(doc.Partitions) != 2 {
		t.Fatalf("image/partitions: %+v", doc)
	}
	if doc.LVM == nil || len(doc.LVM.VGs) != 1 || doc.LVM.VGs[0].Name != "vg0" ||
		len(doc.LVM.VGs[0].LVs) != 2 {
		t.Fatalf("lvm: %+v", doc.LVM)
	}
	if doc.LVM.VGs[0].LVs[1].Segments[0] != "striped2x65536(pv0,pv1)" {
		t.Fatalf("segments: %+v", doc.LVM.VGs[0].LVs[1])
	}
	var root *identifyVolume
	for i := range doc.Volumes {
		if doc.Volumes[i].Source == "vg0/root" {
			root = &doc.Volumes[i]
		}
	}
	if root == nil || root.FSType != "ext4" || root.Label != "lvroot" ||
		root.UUID != "44444444-2222-3333-4444-555555555555" {
		t.Fatalf("root lv volume: %+v", root)
	}
	if len(doc.Snapshots) != 0 {
		t.Fatalf("snapshot inventory is P3, must be empty: %+v", doc.Snapshots)
	}
}

func TestIdentifyOSGuess(t *testing.T) {
	doc, err := identifyImageFile(fixturePath(t, "ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Volumes) != 1 || doc.Volumes[0].OS != "linux (debian)" ||
		doc.Volumes[0].UUID != "21111111-2222-3333-4444-555555555555" {
		t.Fatalf("volumes: %+v", doc.Volumes)
	}
}

func timelineRows(t *testing.T, img string, residue, hash bool) []timelineRow {
	t.Helper()
	ra, size, closeImage, err := image.OpenImage(img)
	if err != nil {
		t.Fatal(err)
	}
	defer closeImage()
	vols, _, err := resolveVolumes(ra, size)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	var sum timelineSummary
	for _, v := range vols {
		if v.FSType == "" || v.FSType == "lvm2-pv" || v.FSType == "ntfs" {
			continue
		}
		if err := timelineVolume(enc, v, residue, hash, &sum); err != nil {
			t.Fatal(err)
		}
	}
	var rows []timelineRow
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var r timelineRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}

func TestTimelineRows(t *testing.T) {
	rows := timelineRows(t, fixturePath(t, "ext4"), false, true)
	byKey := map[string]timelineRow{}
	for _, r := range rows {
		if !r.Allocated {
			t.Fatalf("live walk emitted unallocated row: %+v", r)
		}
		if r.Volume != "disk" || r.FSType != "ext4" || r.FSUUID == "" {
			t.Fatalf("row identity: %+v", r)
		}
		byKey[r.Path+"|"+r.TimeKind] = r
	}
	// the generator pins birth + modify on /etc/hostname
	b, ok := byKey["/etc/hostname|birth"]
	if !ok || b.EventTime != "2026-01-01T00:00:00.000000Z" {
		t.Fatalf("pinned birth row: %+v", b)
	}
	m := byKey["/etc/hostname|modify"]
	if m.EventTime != "2026-01-10T22:14:02.000000Z" || m.Mode != "100644" ||
		m.UID == nil || *m.UID != 0 || m.Nlink != 1 || m.Inode == 0 {
		t.Fatalf("pinned modify row: %+v", m)
	}
	want := sha256.Sum256([]byte("web01\n"))
	if m.SHA256 != hex.EncodeToString(want[:]) || m.MD5 == "" || m.SHA1 == "" {
		t.Fatalf("hashes: %+v", m)
	}
	// the symlink row carries its target, unfollowed
	l := byKey["/etc/localtime|modify"]
	if l.LinkTarget != "../usr/share/zoneinfo/Europe/Berlin" {
		t.Fatalf("symlink row: %+v", l)
	}
}

func TestTimelineResidueRows(t *testing.T) {
	rows := timelineRows(t, fixturePath(t, "ext4"), true, false)
	kinds := map[string]int{}
	for _, r := range rows {
		if r.Residue == nil {
			continue
		}
		kinds[r.Residue.Kind]++
		if r.Residue.Kind != "lost_found" && r.Allocated {
			t.Fatalf("recovered row marked allocated: %+v", r)
		}
	}
	if kinds["orphan_inode"] == 0 || kinds["deleted_dirent"] == 0 || kinds["lost_found"] == 0 {
		t.Fatalf("residue kinds on the timeline: %v", kinds)
	}
}

// TestMaterialiseLinuxCore drives the upgraded materialise end-to-end
// over the real ext4 fixture: the linux-core set with ** globs, the
// origin-record manifest, a --max-file-size skip row, and residue
// staging under residue/<kind>/<id>/.
func TestMaterialiseLinuxCore(t *testing.T) {
	img := fixturePath(t, "ext4")
	out := t.TempDir()
	code := runMaterialise([]string{
		"--out", out, "--set", "linux-core", "--select", "big.bin",
		"--manifest", "--residue", "--max-file-size", "50000", img,
	})
	if code != 0 {
		t.Fatalf("materialise exit %d", code)
	}
	for _, p := range []string{
		"etc/hostname", "etc/os-release", "var/log/syslog",
		"home/alice/.bash_history", "lost+found/#12",
	} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Fatalf("%s not staged: %v", p, err)
		}
	}

	mf, err := os.ReadFile(filepath.Join(out, "materialise.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []materialiseRecord
	for _, line := range strings.Split(strings.TrimSpace(string(mf)), "\n") {
		var r materialiseRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	byPath := map[string]materialiseRecord{}
	for _, r := range rows {
		byPath[r.Path] = r
	}

	h := byPath["/etc/hostname"]
	if h.FSUUID != "21111111-2222-3333-4444-555555555555" || h.Volume != "disk" ||
		h.Inode == 0 || h.Image == "" || h.Mtime != "2026-01-10T22:14:02Z" {
		t.Fatalf("origin record: %+v", h)
	}
	if b := byPath["/big.bin"]; !strings.Contains(b.Skip, "max-file-size") {
		t.Fatalf("max-file-size skip row: %+v", b)
	}
	if _, err := os.Stat(filepath.Join(out, "big.bin")); err == nil {
		t.Fatal("big.bin staged despite --max-file-size")
	}

	staged := 0
	for _, r := range rows {
		if r.Res == nil || r.Staged == "" {
			continue
		}
		staged++
		if !strings.HasPrefix(r.Staged, "residue/"+r.Res.Kind+"/") {
			t.Fatalf("staged layout: %+v", r)
		}
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(r.Staged)))
		if err != nil {
			t.Fatalf("staged residue unreadable: %+v: %v", r, err)
		}
		if r.Res.Kind == "orphan_inode" && !strings.Contains(string(b), "orphan content") {
			t.Fatalf("orphan content: %q", b)
		}
	}
	if staged < 3 { // lost+found #12 + two orphans at minimum
		t.Fatalf("residue staged: %d", staged)
	}
}
