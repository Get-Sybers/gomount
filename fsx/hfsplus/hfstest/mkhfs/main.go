// mkhfs writes the hfstest fixture volume to a file for smoke tests and
// operators: an HFS+ (or HFSX) volume with the same content the backend's
// tests read — a Mac-shaped tree with SystemVersion.plist, a fragmented
// file, links, xattrs and decmpfs files — optionally inside an HFS wrapper
// or an Apple Partition Map image.
//
//	go run ./fsx/hfsplus/hfstest/mkhfs -o /tmp/hfs.img [-hfsx] [-wrapper] [-apm]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/get-sybers/gomount/fsx/hfsplus/hfstest"
)

func main() {
	out := flag.String("o", "", "output image path")
	hfsx := flag.Bool("hfsx", false, "case-sensitive HFSX instead of HFS+")
	wrapper := flag.Bool("wrapper", false, "embed the volume in a classic HFS wrapper")
	apm := flag.Bool("apm", false, "place the volume in an Apple Partition Map image")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "mkhfs: -o is required")
		os.Exit(2)
	}
	img := hfstest.Build(hfstest.Fixture(), hfstest.Options{
		CaseSensitive: *hfsx, Wrapper: *wrapper, Label: "Macintosh HD",
		Inodes: map[uint32]hfstest.File{500: {Data: []byte("shared by two links\n"), UID: 501}},
	})
	if *apm {
		typ := "Apple_HFS"
		if *hfsx {
			typ = "Apple_HFSX"
		}
		img = hfstest.WrapAPM(img, typ, "Macintosh HD")
	}
	if err := os.WriteFile(*out, img, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "mkhfs:", err)
		os.Exit(1)
	}
	fmt.Printf("%s: %d bytes\n", *out, len(img))
}
