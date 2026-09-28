package main

// volumes_test drives the resolved stack end-to-end over the committed
// fixtures: a partitionless ext4 image through the generic verbs, the
// LVM image down to a file inside its linear LV, and the stack listing
// itself.

import (
	"io"
	"testing"

	"github.com/get-sybers/gomount/fsx/fsxtest"
	"github.com/get-sybers/gomount/image"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	f, _ := fsxtest.Open(t, "fsx/testdata", name)
	p := f.Name()
	f.Close()
	return p
}

func TestOpenVolumeFSWholeDiskExt4(t *testing.T) {
	img := fixturePath(t, "ext4")
	fsys, closer, err := openVolumeFS(img, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	e, err := fsys.Stat("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != 6 || e.Inode == 0 || e.MFTID == "" {
		t.Fatalf("stat through the stack: %+v", e)
	}
	r, err := fsys.Open("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "web01\n" {
		t.Fatalf("content: %q", b)
	}
}

func TestOpenVolumeFSLVMByName(t *testing.T) {
	img := fixturePath(t, "lvm")
	fsys, closer, err := openVolumeFS(img, 0, "vg0/root")
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	r, err := fsys.Open("/inside-lv.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "hello from inside the lv\n" {
		t.Fatalf("lv content: %q", b)
	}

	// auto-select on the same image lands on the recognised LV too
	auto, closer2, err := openVolumeFS(img, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closer2()
	if _, err := auto.Stat("/inside-lv.txt"); err != nil {
		t.Fatalf("auto-select did not reach vg0/root: %v", err)
	}
}

func TestResolveVolumesStack(t *testing.T) {
	img := fixturePath(t, "lvm")
	ra, size, closeImage, err := image.OpenImage(img)
	if err != nil {
		t.Fatal(err)
	}
	defer closeImage()
	vols, vgs, err := resolveVolumes(ra, size)
	if err != nil {
		t.Fatal(err)
	}
	// p1 + p2 (PVs) + vg0/root + vg0/stripey
	if len(vols) != 4 || len(vgs) != 1 {
		t.Fatalf("stack: %d vols %d vgs: %+v", len(vols), len(vgs), vols)
	}
	if vols[0].FSType != "lvm2-pv" || vols[1].FSType != "lvm2-pv" {
		t.Fatalf("pv volumes: %+v", vols[:2])
	}
	if vols[2].Source != "vg0/root" || vols[2].FSType != "ext4" {
		t.Fatalf("lv volume: %+v", vols[2])
	}
	if vols[3].Source != "vg0/stripey" || vols[3].FSType != "" {
		t.Fatalf("stripey (patterned, no fs): %+v", vols[3])
	}
	// --volume indexing counts through the same order
	if _, err := selectVolume(vols, 3, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := selectVolume(vols, 9, ""); err == nil {
		t.Fatal("out-of-range volume accepted")
	}
	// a PV itself is not openable, with a pointed error
	if _, _, _, err := openRef(vols[0]); err == nil {
		t.Fatal("opening a bare PV must fail")
	}
}

func TestOpenVolumeFSXFSAndVfat(t *testing.T) {
	for name, probe := range map[string]string{
		"xfs":   "/etc/hostname",
		"fat12": "/HOSTNAME.TXT",
	} {
		fsys, closer, err := openVolumeFS(fixturePath(t, name), 0, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r, err := fsys.Open(probe)
		if err != nil {
			closer()
			t.Fatalf("%s open: %v", name, err)
		}
		b, _ := io.ReadAll(r)
		r.Close()
		closer()
		if string(b) != "web01\n" {
			t.Fatalf("%s content: %q", name, b)
		}
	}
}
