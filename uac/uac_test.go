package uac

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
)

// The fixture is the shape UAC 3.4.0 writes (`-p offline_ir_triage
// --mount-point /mnt/image`): uac.log first, the collector's own output,
// then the host's files under [root]/ — regular files with their owners
// and modes, symlinks, and the hard links GNU tar emits for a path it has
// already stored (merged-usr /bin → /usr/bin). Directories are implied: UAC
// lists files, never directories.
type fixture struct {
	name    string
	typ     byte // tar type flag
	mode    int64
	uid     int
	link    string
	body    []byte
	modTime time.Time
}

var fixtureTime = time.Date(2026, 10, 14, 11, 39, 3, 0, time.UTC)

const fixtureLog = `2026-10-14 11:39:03 +0000 INF Unix-like Artifacts Collector 3.4.0
2026-10-14 11:39:03 +0000 INF UAC directory: /uac
2026-10-14 11:39:03 +0000 INF Command line: ./uac -p offline_ir_triage --mount-point /mnt/image --operating-system linux -f tar /out
2026-10-14 11:39:03 +0000 INF Operating system: linux
2026-10-14 11:39:03 +0000 INF System architecture: x86_64
2026-10-14 11:39:03 +0000 INF Hostname: web01
2026-10-14 11:39:03 +0000 INF Time zone: Etc/UTC
2026-10-14 11:39:03 +0000 INF Mount point: /mnt/image
2026-10-14 11:39:03 +0000 INF Running as: root
2026-10-14 11:39:03 +0000 INF Output format: tar
2026-10-14 11:39:04 +0000 INF Parsing bodyfile/bodyfile.yaml
2026-10-14 11:42:44 +0000 CMD find /"mnt/image"/"/root"/.xsession-errors -print 2> find: No such file or directory
2026-10-14 11:42:44 +0000 INF Artifacts collection completed in 221 seconds
`

func fixtures(bigLog []byte) []fixture {
	t := fixtureTime
	return []fixture{
		{name: "uac.log", typ: tar.TypeReg, mode: 0o644, body: []byte(fixtureLog), modTime: t},
		{name: "bodyfile/bodyfile.txt", typ: tar.TypeReg, mode: 0o644, body: []byte("0|/etc/passwd|131|-rw-r--r--|0|0|1852|1|2|3|0\n"), modTime: t},
		{name: "hash_executables/hash_executables.md5", typ: tar.TypeReg, mode: 0o644, body: []byte("d41d8cd98f00b204e9800998ecf8427e  /usr/bin/tool\n"), modTime: t},
		{name: "[root]/etc/hostname", typ: tar.TypeReg, mode: 0o644, body: []byte("web01\n"), modTime: t.Add(-time.Hour)},
		{name: "[root]/etc/os-release", typ: tar.TypeSymlink, mode: 0o777, link: "../usr/lib/os-release", modTime: t.Add(-time.Hour)},
		{name: "[root]/usr/lib/os-release", typ: tar.TypeReg, mode: 0o644, body: []byte("PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nID=ubuntu\n"), modTime: t.Add(-time.Hour)},
		{name: "[root]/etc/passwd", typ: tar.TypeReg, mode: 0o644, body: []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"), modTime: t.Add(-time.Hour)},
		{name: "[root]/etc/sudoers", typ: tar.TypeReg, mode: 0o440, body: []byte("root ALL=(ALL) ALL\n"), modTime: t.Add(-time.Hour)},
		{name: "[root]/usr/bin/tool", typ: tar.TypeReg, mode: 0o755, body: []byte("#!/bin/sh\n"), modTime: t.Add(-time.Hour)},
		{name: "[root]/bin/tool", typ: tar.TypeLink, mode: 0o755, link: "[root]/usr/bin/tool", modTime: t.Add(-time.Hour)},
		{name: "[root]/home/alice/.bash_history", typ: tar.TypeReg, mode: 0o600, uid: 1000, body: []byte("ls\nsudo -i\n"), modTime: t.Add(-time.Minute)},
		{name: "[root]/var/log/syslog", typ: tar.TypeReg, mode: 0o640, body: bigLog, modTime: t.Add(-time.Minute)},
	}
}

// incompressible bytes, so a cut of the gzip stream cuts members, not just
// the deflate window
func noisyLog(n int) []byte {
	r := rand.New(rand.NewSource(7))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func writeTar(t *testing.T, fx []fixture, gz bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&buf)
		w = zw
	}
	tw := tar.NewWriter(w)
	for _, f := range fx {
		hdr := &tar.Header{Name: f.name, Typeflag: f.typ, Mode: f.mode, Uid: f.uid, Gid: f.uid, ModTime: f.modTime, Format: tar.FormatGNU}
		switch f.typ {
		case tar.TypeSymlink, tar.TypeLink:
			hdr.Linkname = f.link
		default:
			hdr.Size = int64(len(f.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(f.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// writeZip is `zip -r out -@ < list` on Linux: unix modes in the external
// attributes, the owner in Info-ZIP's "ux" extra field, a symlink stored
// as its target text, a hard link stored twice.
func writeZip(t *testing.T, fx []fixture) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range fx {
		hdr := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: f.modTime}
		mode := os.FileMode(f.mode)
		if f.typ == tar.TypeSymlink {
			mode |= os.ModeSymlink
		}
		hdr.SetMode(mode)
		ux := make([]byte, 4+11)
		binary.LittleEndian.PutUint16(ux, 0x7875)
		binary.LittleEndian.PutUint16(ux[2:], 11)
		ux[4], ux[5] = 1, 4
		binary.LittleEndian.PutUint32(ux[6:], uint32(f.uid))
		ux[10] = 4
		binary.LittleEndian.PutUint32(ux[11:], uint32(f.uid))
		hdr.Extra = ux
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		switch f.typ {
		case tar.TypeSymlink:
			io.WriteString(w, f.link)
		case tar.TypeLink:
			// zip has no hard links: the second path carries the bytes again
			for _, g := range fx {
				if g.name == f.link {
					w.Write(g.body)
				}
			}
		default:
			w.Write(f.body)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type container struct {
	kind  Kind
	build func(t *testing.T, fx []fixture) []byte
}

var containers = []container{
	{KindTarGz, func(t *testing.T, fx []fixture) []byte { return writeTar(t, fx, true) }},
	{KindTar, func(t *testing.T, fx []fixture) []byte { return writeTar(t, fx, false) }},
	{KindZip, writeZip},
}

func openFixture(t *testing.T, c container) *Archive {
	t.Helper()
	b := c.build(t, fixtures(noisyLog(4096)))
	a, err := Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("%s: Open: %v", c.kind, err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestDetect(t *testing.T) {
	for _, c := range containers {
		t.Run(string(c.kind), func(t *testing.T) {
			b := c.build(t, fixtures(noisyLog(64)))
			kind, ok := Detect(bytes.NewReader(b), int64(len(b)))
			if !ok || kind != c.kind {
				t.Fatalf("Detect = %q, %v; want %q, true", kind, ok, c.kind)
			}
		})
	}
	// the same containers without the layout, and things that are no archive
	other := []fixture{
		{name: "notes/readme.txt", typ: tar.TypeReg, mode: 0o644, body: []byte("hi"), modTime: fixtureTime},
		{name: "etc/passwd", typ: tar.TypeReg, mode: 0o644, body: []byte("root:x:0:0"), modTime: fixtureTime},
	}
	// `tar czf x.tgz .`: the root directory "./" first, then "./"-prefixed members
	dotTar := append([]fixture{
		{name: "./", typ: tar.TypeDir, mode: 0o755, modTime: fixtureTime},
		{name: "./notes/", typ: tar.TypeDir, mode: 0o755, modTime: fixtureTime},
	}, other...)
	for i := range dotTar[2:] {
		dotTar[2+i].name = "./" + dotTar[2+i].name
	}
	cases := map[string][]byte{
		"plain tar.gz": writeTar(t, other, true),
		"plain tar":    writeTar(t, other, false),
		"plain zip":    writeZip(t, other),
		"tar czf .":    writeTar(t, dotTar, true),
		"zip -r .":     writeZip(t, dotTar),
		"text":         bytes.Repeat([]byte("not an archive at all\n"), 64),
		"short":        []byte("PK\x03\x04"),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if kind, ok := Detect(bytes.NewReader(b), int64(len(b))); ok {
				t.Fatalf("Detect = %q, true on %s", kind, name)
			}
			if _, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				t.Fatalf("Open accepted %s", name)
			}
		})
	}
}

func TestRootTree(t *testing.T) {
	for _, c := range containers {
		t.Run(string(c.kind), func(t *testing.T) {
			a := openFixture(t, c)
			root := a.Root()
			if a.Kind() != c.kind {
				t.Errorf("Kind = %q", a.Kind())
			}

			pw, err := root.Stat("/etc/passwd")
			if err != nil {
				t.Fatal(err)
			}
			if pw.IsDir || pw.Size != 73 || pw.Mode != modeRegular|0o644 || pw.UID != 0 || !pw.Allocated || !pw.Mtime.Equal(fixtureTime.Add(-time.Hour)) {
				t.Errorf("passwd = %+v", pw)
			}
			if su, _ := root.Stat("/etc/sudoers"); su.Mode != modeRegular|0o440 {
				t.Errorf("sudoers mode = %o", su.Mode)
			}
			if h, _ := root.Stat("/home/alice/.bash_history"); h.UID != 1000 || h.GID != 1000 || h.Mode != modeRegular|0o600 {
				t.Errorf("history owner/mode = %d/%d %o", h.UID, h.GID, h.Mode)
			}

			// the symlink, unfollowed on Stat, its target on Open (icat)
			ln, err := root.Stat("/etc/os-release")
			if err != nil {
				t.Fatal(err)
			}
			if ln.LinkTarget != "../usr/lib/os-release" || ln.Mode&modeSymlink != modeSymlink || ln.IsDir {
				t.Errorf("os-release = %+v", ln)
			}
			if got := readAll(t, root, "/etc/os-release"); got != "../usr/lib/os-release" {
				t.Errorf("Open(symlink) = %q", got)
			}
			if got := readAll(t, root, "/usr/lib/os-release"); !strings.Contains(got, "ID=ubuntu") {
				t.Errorf("os-release target = %q", got)
			}

			// the hard link reads its target's bytes
			if got := readAll(t, root, "/bin/tool"); got != "#!/bin/sh\n" {
				t.Errorf("hard link content = %q", got)
			}

			// implied directories: there, typed, and honest about the rest
			etc, err := root.Stat("/etc")
			if err != nil {
				t.Fatal(err)
			}
			if !etc.IsDir || etc.Mode != modeDir || !etc.Mtime.IsZero() {
				t.Errorf("implied /etc = %+v", etc)
			}
			names := childNames(t, root, "/etc")
			if strings.Join(names, " ") != "hostname os-release passwd sudoers" {
				t.Errorf("ReadDir /etc = %v", names)
			}
			if _, err := root.Open("/etc"); err == nil {
				t.Error("Open on a directory succeeded")
			}
			if _, err := root.Stat("/uac.log"); err == nil {
				t.Error("the collector's log leaked into the root tree")
			}
			if _, err := root.Stat("/etc/shadow"); err == nil {
				t.Error("a missing path stat'd")
			}

			// Walk: every entry, files with an opener
			var files, dirs, links int
			err = root.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
				switch {
				case e.IsDir:
					dirs++
					if open != nil {
						t.Errorf("%s: a directory with an opener", e.Path)
					}
				case e.LinkTarget != "":
					links++
					if open != nil {
						t.Errorf("%s: a symlink with an opener", e.Path)
					}
				default:
					files++
					if open == nil {
						t.Errorf("%s: a file without an opener", e.Path)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// etc, usr, usr/lib, usr/bin, bin, home, home/alice, var, var/log
			if files != 8 || dirs != 9 || links != 1 {
				t.Errorf("walk = %d files, %d dirs, %d links", files, dirs, links)
			}
			if root.Members() != 9 {
				t.Errorf("Members = %d", root.Members())
			}
			if root.Info().Type != "uac" {
				t.Errorf("Info = %+v", root.Info())
			}
		})
	}
}

func TestMetaTreeAndLog(t *testing.T) {
	for _, c := range containers {
		t.Run(string(c.kind), func(t *testing.T) {
			a := openFixture(t, c)
			meta := a.Meta()
			if names := childNames(t, meta, "/"); strings.Join(names, " ") != "bodyfile hash_executables uac.log" {
				t.Errorf("ReadDir / = %v", names)
			}
			if got := readAll(t, meta, "/bodyfile/bodyfile.txt"); !strings.HasPrefix(got, "0|/etc/passwd|") {
				t.Errorf("bodyfile = %q", got)
			}
			if _, err := meta.Stat("/etc/passwd"); err == nil {
				t.Error("a host file leaked into the meta tree")
			}
			lg := a.Log()
			want := Log{
				Version: "3.4.0", Hostname: "web01", OS: "linux", Arch: "x86_64", Timezone: "Etc/UTC",
				MountPoint: "/mnt/image", OutputFormat: "tar",
				CommandLine: "./uac -p offline_ir_triage --mount-point /mnt/image --operating-system linux -f tar /out",
				Started:     time.Date(2026, 10, 14, 11, 39, 3, 0, time.UTC),
				Finished:    time.Date(2026, 10, 14, 11, 42, 44, 0, time.UTC),
			}
			if lg.Version != want.Version || lg.Hostname != want.Hostname || lg.OS != want.OS || lg.Arch != want.Arch ||
				lg.Timezone != want.Timezone || lg.MountPoint != want.MountPoint || lg.OutputFormat != want.OutputFormat ||
				lg.CommandLine != want.CommandLine || !lg.Started.Equal(want.Started) || !lg.Finished.Equal(want.Finished) {
				t.Errorf("Log = %+v\nwant %+v", lg, want)
			}
			if a.Truncated() != nil {
				t.Errorf("Truncated = %v on a whole archive", a.Truncated())
			}
		})
	}
}

// TestTruncatedTarGz: an interrupted collection indexes as far as it goes
// and says so, instead of refusing the evidence that did land.
func TestTruncatedTarGz(t *testing.T) {
	whole := writeTar(t, fixtures(noisyLog(256<<10)), true)
	cut := whole[:len(whole)/2]
	a, err := Open(bytes.NewReader(cut), int64(len(cut)))
	if err != nil {
		t.Fatalf("Open(truncated): %v", err)
	}
	defer a.Close()
	if a.Truncated() == nil {
		t.Fatal("Truncated = nil on a cut archive")
	}
	if a.Log().Hostname != "web01" {
		t.Errorf("the members before the cut were lost: %+v", a.Log())
	}
	if _, err := a.Root().Stat("/etc/passwd"); err != nil {
		t.Errorf("passwd (before the cut) missing: %v", err)
	}
}

// TestSpoolIsReleased: the gunzipped tar lives in an unlinked temp file
// under TMPDIR and nothing stays behind after Close.
func TestSpoolIsReleased(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	b := writeTar(t, fixtures(noisyLog(64)), true)
	a, err := Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, a.Root(), "/etc/hostname"); got != "web01\n" {
		t.Errorf("hostname through the spool = %q", got)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(tmp, "gomount-uac-*"))
	if len(left) != 0 {
		t.Errorf("spool left behind: %v", left)
	}
}

func TestCleanName(t *testing.T) {
	cases := map[string]string{
		"uac.log":              "uac.log",
		"./uac.log":            "uac.log",
		"/[root]/etc/passwd":   "[root]/etc/passwd",
		"[root]/etc//passwd":   "[root]/etc/passwd",
		"[root]/":              "[root]",
		"[root]\\etc\\passwd":  "[root]/etc/passwd",
		"[root]/etc/../passwd": "[root]/passwd",
		// names that reduce to the root: the empty string, never a panic
		"":     "",
		"/":    "",
		"./":   "",
		"//":   "",
		".":    "",
		"a/..": "",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			if got := cleanName(in); got != want {
				t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
			}
		})
	}
	// a member that climbs out is dropped, never placed
	tr := newTree()
	tr.add("../../etc/passwd", &member{typ: typeFile})
	if tr.n != 0 || len(tr.root.children) != 0 {
		t.Errorf("a climbing member was placed: %d members", tr.n)
	}
}

func readAll(t *testing.T, fsys *FS, p string) string {
	t.Helper()
	rc, err := fsys.Open(p)
	if err != nil {
		t.Fatalf("Open %s: %v", p, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func childNames(t *testing.T, fsys *FS, dir string) []string {
	t.Helper()
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}
