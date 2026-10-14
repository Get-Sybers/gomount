package uac

import (
	"archive/tar"
	"bytes"
	"testing"
)

// TestHardLinkToSymlinkIsASymlink: on a merged-usr host /usr/lib/systemd/
// system/x.service and /lib/systemd/system/x.service are one symlink inode;
// GNU tar stores the first and links the second, so the collection carries
// a hard link whose target is a symlink (89 of the 400 hard links in a real
// LS24 collection). It must come out as that symlink — target text and
// Type — not as an empty regular file.
func TestHardLinkToSymlinkIsASymlink(t *testing.T) {
	fx := append(fixtures(noisyLog(64)),
		fixture{name: "[root]/lib/systemd/system/autovt@.service", typ: tar.TypeSymlink, mode: 0o777, link: "getty@.service", modTime: fixtureTime},
		fixture{name: "[root]/usr/lib/systemd/system/autovt@.service", typ: tar.TypeLink, mode: 0o777, link: "[root]/lib/systemd/system/autovt@.service", modTime: fixtureTime},
	)
	for _, c := range containers {
		t.Run(string(c.kind), func(t *testing.T) {
			b := c.build(t, fx)
			a, err := Open(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			root := a.Root()
			for _, p := range []string{"/lib/systemd/system/autovt@.service", "/usr/lib/systemd/system/autovt@.service"} {
				e, err := root.Stat(p)
				if err != nil {
					t.Fatalf("Stat %s: %v", p, err)
				}
				if e.LinkTarget != "getty@.service" || e.IsDir || e.Mode&modeSymlink == 0 {
					t.Errorf("%s: LinkTarget=%q IsDir=%v Mode=%o, want a symlink to getty@.service", p, e.LinkTarget, e.IsDir, e.Mode)
				}
				if got := readAll(t, root, p); got != "getty@.service" {
					t.Errorf("%s: Open = %q, want the target text", p, got)
				}
			}
			// the hard link to a regular file still reads its target's bytes
			if got := readAll(t, root, "/bin/tool"); got != "#!/bin/sh\n" {
				t.Errorf("hard link to a file = %q", got)
			}
		})
	}
}
