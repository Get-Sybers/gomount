package main

// uac_test proves a UAC collection reads as an image through the whole
// verb surface: identify names the collection and its two volumes,
// auto-select lands on the host's files, materialise pulls the linux-core
// set out of [root]/ with origin rows naming the archive, timeline walks
// its members, and stream --all re-emits the tree.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCollection writes a minimal UAC-shaped tar.gz: uac.log first, then
// the host's files under [root]/ (no directory members, as UAC writes).
func writeCollection(t *testing.T) string {
	t.Helper()
	when := time.Date(2026, 10, 14, 11, 39, 3, 0, time.UTC)
	members := []struct {
		name, body, link string
		typ              byte
		mode             int64
		uid              int
	}{
		{"uac.log", "2026-10-14 11:39:03 +0000 INF Unix-like Artifacts Collector 3.4.0\n2026-10-14 11:39:03 +0000 INF Operating system: linux\n2026-10-14 11:39:03 +0000 INF Hostname: web01\n2026-10-14 11:40:00 +0000 INF Artifacts collection completed in 57 seconds\n", "", tar.TypeReg, 0o644, 0},
		{"bodyfile/bodyfile.txt", "0|/etc/passwd|131|-rw-r--r--|0|0|73|1|2|3|0\n", "", tar.TypeReg, 0o644, 0},
		{"[root]/etc/hostname", "web01\n", "", tar.TypeReg, 0o644, 0},
		{"[root]/etc/os-release", "", "../usr/lib/os-release", tar.TypeSymlink, 0o777, 0},
		{"[root]/usr/lib/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n", "", tar.TypeReg, 0o644, 0},
		{"[root]/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n", "", tar.TypeReg, 0o644, 0},
		{"[root]/var/log/auth.log", "Oct 14 11:00:01 web01 sshd[100]: Accepted publickey for alice from 10.0.0.5 port 4000 ssh2\n", "", tar.TypeReg, 0o640, 0},
		{"[root]/home/alice/.bash_history", "ls\n", "", tar.TypeReg, 0o600, 1000},
		{"[root]/home/alice/notes.txt", "not an artefact\n", "", tar.TypeReg, 0o644, 1000},
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		hdr := &tar.Header{Name: m.name, Typeflag: m.typ, Mode: m.mode, Uid: m.uid, Gid: m.uid, ModTime: when, Linkname: m.link, Format: tar.FormatGNU}
		if m.typ == tar.TypeReg {
			hdr.Size = int64(len(m.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "uac-web01-linux-20261014113903.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIdentifyCollection(t *testing.T) {
	doc, err := identifyImageFile(writeCollection(t))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Image.Format != "gzip" {
		t.Errorf("format = %q, want gzip", doc.Image.Format)
	}
	c := doc.Collection
	if c == nil || c.Tool != "uac" || c.Version != "3.4.0" || c.Hostname != "web01" || c.OS != "linux" || c.Container != "tar.gz" {
		t.Fatalf("collection = %+v", c)
	}
	if c.RootMembers != 7 || c.MetaMembers != 2 || c.Started != "2026-10-14T11:39:03.000000Z" {
		t.Errorf("collection counts/times = %+v", c)
	}
	if len(doc.Volumes) != 2 || doc.Volumes[0].Source != "[root]" || doc.Volumes[0].FSType != "uac" || doc.Volumes[0].OS != "linux (debian)" {
		t.Errorf("volumes = %+v", doc.Volumes)
	}
	if doc.Volumes[1].Source != "uac" || doc.Volumes[1].FSType != "uac-meta" {
		t.Errorf("meta volume = %+v", doc.Volumes[1])
	}
	if len(doc.Partitions) != 0 || doc.LVM != nil {
		t.Errorf("an archive grew partitions or LVM: %+v", doc)
	}
}

func TestCollectionAutoSelectsTheHost(t *testing.T) {
	fsys, closer, err := openVolumeFS(writeCollection(t), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	var out bytes.Buffer
	if err := catFile(&out, fsys, "/etc/hostname"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "web01\n" {
		t.Errorf("cat /etc/hostname = %q", out.String())
	}
	// volume 2 is the collector's output
	meta, closer2, err := openVolumeFS(writeCollection(t), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closer2()
	if _, err := meta.Stat("/uac.log"); err != nil {
		t.Errorf("uac.log not on volume 2: %v", err)
	}
}

func TestMaterialiseCollectionLinuxCore(t *testing.T) {
	archive := writeCollection(t)
	out := t.TempDir()
	stdout := captureStdout(t, func() {
		if code := runMaterialise([]string{"--out", out, "--set", "linux-core", "--manifest", archive}); code != 0 {
			t.Errorf("materialise exit %d", code)
		}
	})
	var sum map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &sum); err != nil {
		t.Fatalf("summary %q: %v", stdout, err)
	}
	if sum["status"] != "ok" || sum["records"] != float64(6) {
		t.Errorf("summary = %v", sum)
	}
	for _, rel := range []string{"etc/hostname", "etc/passwd", "etc/os-release", "usr/lib/os-release", "var/log/auth.log", "home/alice/.bash_history"} {
		if _, err := os.Stat(filepath.Join(out, rel)); err != nil {
			t.Errorf("%s not staged: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "home/alice/notes.txt")); err == nil {
		t.Error("a file outside linux-core was staged")
	}
	f, err := os.Open(filepath.Join(out, "materialise.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row map[string]any
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows++
		if row["image"] != "uac-web01-linux-20261014113903.tar.gz" || row["volume"] != "[root]" {
			t.Errorf("origin row = %v", row)
		}
		if _, has := row["mftid"]; has {
			t.Errorf("an archive member grew an mftid: %v", row)
		}
	}
	if rows != 6 {
		t.Errorf("manifest rows = %d, want 6 (the symlink included)", rows)
	}
}

func TestTimelineAndStreamAllOverCollection(t *testing.T) {
	archive := writeCollection(t)
	stdout := captureStdout(t, func() {
		if code := runTimeline([]string{archive}); code != 0 {
			t.Errorf("timeline exit %d", code)
		}
	})
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var row timelineRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, row.Volume+":"+row.Path+":"+row.TimeKind)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{"[root]:/etc/passwd:modify", "[root]:/etc:none", "uac:/uac.log:modify"} {
		if !strings.Contains(joined, want) {
			t.Errorf("timeline lacks %s:\n%s", want, joined)
		}
	}

	fsys, closer, err := openVolumeFS(archive, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	var tarOut, errOut bytes.Buffer
	sum, err := streamVolume(&tarOut, &errOut, fsys, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Files != 6 {
		t.Errorf("stream --all files = %d, want 6 (the symlink is not a file)", sum.Files)
	}
	tr := tar.NewReader(&tarOut)
	kinds := map[string]byte{}
	modes := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		kinds[hdr.Name] = hdr.Typeflag
		modes[hdr.Name] = hdr.Mode
	}
	if kinds["etc/"] != tar.TypeDir || kinds["etc/os-release"] != tar.TypeSymlink || kinds["etc/passwd"] != tar.TypeReg {
		t.Errorf("stream --all entries = %v", kinds)
	}
	// UAC lists files, never directories: the implied ones must still extract
	// enterable, or `stream --all | tar -x` yields a tree nobody can browse
	if modes["etc/"] != 0o755 || modes["etc/passwd"] != 0o644 {
		t.Errorf("stream --all modes: etc/ %o (want 755), etc/passwd %o (want 644)", modes["etc/"], modes["etc/passwd"])
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}
