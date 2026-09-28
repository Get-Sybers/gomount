//go:build ignore

// gen-lvm crafts the LVM fixture: an MBR image with two LVM (0x8E)
// partitions, each a PV of vg0, holding a LINEAR lv (a real mke2fs ext4
// image, passed in) and a STRIPED lv (a deterministic pattern laid out
// here with plain round-robin arithmetic, independent of the reader
// under test). No lvm2 tooling exists without a device-mapper kernel,
// so the label, pv_header, mda header and metadata text are written per
// the LVM2 on-disk format; checksum fields are left zero (the reader is
// structural and read-only).
//
//	go run gen-lvm.go lvm.img lvroot.img
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

const (
	mib     = 1 << 20
	sector  = 512
	imgSize = 64 * mib

	p1Off = 1 * mib
	p2Off = 26 * mib
	pvLen = 24 * mib

	mdaOff  = 4096      // per PV
	peStart = 1 * mib   // per PV, sectors 2048 in the text
	extSize = 1 * mib   // extent_size 2048 sectors
	rootExt = 6         // linear lv extents (pv0 pe 0..5)
	strExt  = 4         // striped lv extents (2 per leg)
	chunk   = 64 * 1024 // stripe_size 128 sectors
	pv0UUID = "AAAAAA111122223333444455556666BB"
	pv1UUID = "CCCCCC111122223333444455556666DD"
)

func dashed(u string) string {
	return u[0:6] + "-" + u[6:10] + "-" + u[10:14] + "-" + u[14:18] + "-" + u[18:22] + "-" + u[22:26] + "-" + u[26:32]
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gen-lvm <out.img> <ext4-for-root-lv.img>")
		os.Exit(1)
	}
	rootFS, err := os.ReadFile(os.Args[2])
	must(err)
	if len(rootFS) > rootExt*extSize {
		panic("root fs larger than the lv")
	}
	img := make([]byte, imgSize)
	le := binary.LittleEndian

	// MBR: two primary type-0x8E partitions.
	part := func(i int, offBytes, lenBytes int64) {
		e := img[446+i*16:]
		e[4] = 0x8E
		le.PutUint32(e[8:], uint32(offBytes/sector))
		le.PutUint32(e[12:], uint32(lenBytes/sector))
	}
	part(0, p1Off, pvLen)
	part(1, p2Off, pvLen)
	img[510], img[511] = 0x55, 0xAA

	text := metadataText()
	writePV(img[p1Off:p1Off+pvLen], pv0UUID, text)
	writePV(img[p2Off:p2Off+pvLen], pv1UUID, text)

	// root lv: linear on pv0 extents 0..5 -> the real ext4 image.
	copy(img[p1Off+peStart:], rootFS)

	// stripey lv: chunks round-robin pv0/pv1; leg areas start at pv0 pe 6
	// and pv1 pe 0. Plain forward arithmetic, nothing shared with lvm.go.
	total := strExt * extSize
	for c := 0; c*chunk < total; c++ {
		legChunk := c / 2
		var base int
		if c%2 == 0 {
			base = p1Off + peStart + rootExt*extSize + legChunk*chunk
		} else {
			base = p2Off + peStart + legChunk*chunk
		}
		for i := 0; i < chunk; i++ {
			img[base+i] = byte((c*chunk + i) * 11 % 256)
		}
	}

	must(os.WriteFile(os.Args[1], img, 0o644))
}

// writePV lays down label sector 1, pv_header, mda header and the text.
func writePV(pv []byte, uuid, text string) {
	le := binary.LittleEndian
	lb := pv[sector : 2*sector]
	copy(lb[0:8], "LABELONE")
	le.PutUint64(lb[8:], 1)   // this sector number
	le.PutUint32(lb[20:], 32) // pv_header offset within the sector
	copy(lb[24:32], "LVM2 001")

	ph := lb[32:]
	copy(ph[0:32], uuid)
	le.PutUint64(ph[32:], uint64(len(pv))) // device_size
	pos := 40
	// data areas: {peStart, 0=to-end}, terminator
	le.PutUint64(ph[pos:], peStart)
	le.PutUint64(ph[pos+8:], 0)
	pos += 16
	le.PutUint64(ph[pos:], 0)
	le.PutUint64(ph[pos+8:], 0)
	pos += 16
	// metadata areas: {mdaOff, peStart-mdaOff}, terminator
	le.PutUint64(ph[pos:], mdaOff)
	le.PutUint64(ph[pos+8:], peStart-mdaOff)
	pos += 16
	le.PutUint64(ph[pos:], 0)
	le.PutUint64(ph[pos+8:], 0)

	mh := pv[mdaOff : mdaOff+sector]
	copy(mh[4:20], " LVM2 x[5A%r0N*>")
	le.PutUint32(mh[20:], 1) // version
	le.PutUint64(mh[24:], mdaOff)
	le.PutUint64(mh[32:], peStart-mdaOff)
	// raw_locn[0]: text at mda+512
	le.PutUint64(mh[40:], 512)
	le.PutUint64(mh[48:], uint64(len(text)))
	copy(pv[mdaOff+512:], text)
}

func metadataText() string {
	return fmt.Sprintf(`vg0 {
id = "VGVGVG-0000-1111-2222-3333-4444-555555"
seqno = 3
format = "lvm2"
status = ["RESIZEABLE", "READ", "WRITE"]
extent_size = %d
max_lv = 0
max_pv = 0

physical_volumes {

pv0 {
id = %q
device = "/dev/sda1"
status = ["ALLOCATABLE"]
dev_size = %d
pe_start = %d
pe_count = 23
}

pv1 {
id = %q
device = "/dev/sda2"
status = ["ALLOCATABLE"]
dev_size = %d
pe_start = %d
pe_count = 23
}
}

logical_volumes {

root {
id = "ROOTLV-0000-1111-2222-3333-4444-555555"
status = ["READ", "WRITE", "VISIBLE"]
segment_count = 1

segment1 {
start_extent = 0
extent_count = %d
type = "striped"
stripe_count = 1
stripes = [
"pv0", 0
]
}
}

stripey {
id = "STRIPE-0000-1111-2222-3333-4444-555555"
status = ["READ", "WRITE", "VISIBLE"]
segment_count = 1

segment1 {
start_extent = 0
extent_count = %d
type = "striped"
stripe_count = 2
stripe_size = %d
stripes = [
"pv0", %d,
"pv1", 0
]
}
}
}
}
`, extSize/sector, dashed(pv0UUID), pvLen/sector, peStart/sector, dashed(pv1UUID), pvLen/sector, peStart/sector,
		rootExt, strExt, chunk/sector, rootExt)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
