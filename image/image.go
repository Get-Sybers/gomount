// Package image opens a forensic disk image read-only and presents it as a
// byte-addressable io.ReaderAt of an exact length, hiding whether the on-disk
// container is a raw dd/img or an EWF/E01 expert-witness set.
//
// A raw image (.raw/.dd/.img, or any file with no EWF signature) is its own
// media: os.Open gives the io.ReaderAt and the file length is the size. An
// EWF/E01 set is decoded by the permissive pure-Go Velocidex/go-ewf reader
// (Apache-2.0), which stitches the segmented, zlib-compressed chunks behind an
// io.ReaderAt and reports the acquired media size. Both paths open O_RDONLY;
// nothing in gomount writes to evidence.
package image

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	ewf "github.com/Velocidex/go-ewf/parser"
)

// EWF first-segment signatures at byte 0. EVF ("EVF\t\r\n\xff\x00") is EnCase
// E01; EVF2 ("EVF2...") is EnCase v2 (.Ex01). LVF ("LVF...") is a *logical*
// evidence file (L01), not a disk image, and is intentionally not opened here.
var (
	sigEVF  = []byte{0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00}
	sigEVF2 = []byte{0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00}
)

// ewfSegmentExt matches an EWF segment extension: .E01..E99 / .EAA..EZZ and the
// SMART .s01 family, plus EnCase v2 .Ex01. Logical (.L01/.Lx01) is excluded.
var ewfSegmentExt = regexp.MustCompile(`(?i)^\.(e|s)x?[0-9a-z]{2}$`)

// OpenImage opens the disk image at path read-only and returns a reader over the
// raw media, the exact media size in bytes, and a closer that releases every
// underlying file. The container is auto-detected by content (a mislabelled
// name never decides):
//
//   - RAW/dd/img: ra is the *os.File, size is its on-disk length.
//   - EWF/E01:    every segment (.E01, .E02…, or .Ex01…) is opened and handed to
//     go-ewf; ra is the decoding *ewf.EWFFile, size is its TotalImageSize.
//   - VMDK:       a sparse extent (KDMV) or a text descriptor — vmdk.go.
//   - VHDX/VHD:   vhdxfile at 0 / conectix footer — vhdx.go, vhd.go.
//   - QCOW2/VDI:  QFIû at 0 / the VDI magic at 0x40 — qcow2.go, vdi.go.
//   - DMG (UDIF): the koly trailer in the last 512 bytes — dmg.go; ra is
//     the virtual raw disk, its chunks decoded on demand.
//   - .sparseimage ("sprs" at 0) and .sparsebundle (a directory whose
//     Info.plist names the bundle type) — sparse.go. An encrypted Apple
//     image ("encrcdsa") is recognised and refused.
//
// The returned ReaderAt must be read within [0,size); the callers in this tool
// (partition table scan, boot-sector/BPB read, and the FUSE Read passthrough)
// only ever issue bounded, in-range reads.
func OpenImage(path string) (ra io.ReaderAt, size int64, closer func() error, err error) {
	f, err := os.Open(path) // O_RDONLY
	if err != nil {
		return nil, 0, nil, err
	}

	switch Format(path) {
	case "sparsebundle":
		f.Close()
		b, err := openSparseBundle(path)
		if err != nil {
			return nil, 0, nil, err
		}
		return b, b.size, b.Close, nil
	case "sparseimage":
		f.Close()
		s, err := openSparseImage(path)
		if err != nil {
			return nil, 0, nil, err
		}
		return s, s.size, s.Close, nil
	case "encrypted-dmg":
		f.Close()
		return nil, 0, nil, errors.New("encrypted Apple disk image (encrcdsa): decryption is not supported")
	case "vmdk":
		f.Close()
		d, err := openVMDK(path, 0)
		if err != nil {
			return nil, 0, nil, err
		}
		return d, d.size, d.Close, nil
	case "vhdx":
		f.Close()
		d, err := openVHDX(path, 0)
		if err != nil {
			return nil, 0, nil, err
		}
		return d, d.size, d.Close, nil
	case "vhd":
		f.Close()
		d, err := openVHD(path, 0)
		if err != nil {
			return nil, 0, nil, err
		}
		return d, d.size, d.Close, nil
	case "qcow2":
		f.Close()
		d, err := openQCOW2(path, 0)
		if err != nil {
			return nil, 0, nil, err
		}
		return d, d.size, d.Close, nil
	case "vdi":
		f.Close()
		d, err := openVDI(path, 0)
		if err != nil {
			return nil, 0, nil, err
		}
		return d, d.hdr.size, d.Close, nil
	case "dmg":
		f.Close()
		d, err := openDMG(path)
		if err != nil {
			return nil, 0, nil, err
		}
		return d, d.size, d.Close, nil
	}

	isEWF, err := looksLikeEWF(f, path)
	if err != nil {
		f.Close()
		return nil, 0, nil, err
	}

	if !isEWF {
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, nil, err
		}
		return f, st.Size(), f.Close, nil
	}

	// EWF: the first file we opened is only used for detection; open the whole
	// ordered segment set and let go-ewf reassemble the media.
	f.Close()
	segs, err := ewfSegments(path)
	if err != nil {
		return nil, 0, nil, err
	}
	files := make([]*os.File, 0, len(segs))
	readers := make([]io.ReaderAt, 0, len(segs))
	closeAll := func() error {
		var first error
		for _, h := range files {
			if e := h.Close(); e != nil && first == nil {
				first = e
			}
		}
		return first
	}
	for _, p := range segs {
		h, err := os.Open(p) // O_RDONLY
		if err != nil {
			closeAll()
			return nil, 0, nil, fmt.Errorf("open EWF segment %s: %w", p, err)
		}
		files = append(files, h)
		readers = append(readers, h)
	}

	ef, err := ewf.OpenEWFFile(nil, readers...)
	if err != nil {
		closeAll()
		return nil, 0, nil, fmt.Errorf("parse EWF set: %w", err)
	}
	if ef.TotalImageSize <= 0 {
		closeAll()
		return nil, 0, nil, errors.New("EWF set reports non-positive media size")
	}
	return ef, ef.TotalImageSize, closeAll, nil
}

// looksLikeEWF reports whether path is an EWF/E01 set, by the first-segment
// signature alone: every first segment carries it, and a name never decides
// (a mislabelled raw file called .E01 stays raw).
func looksLikeEWF(f io.ReaderAt, _ string) (bool, error) {
	var hdr [8]byte
	n, err := f.ReadAt(hdr[:], 0)
	if err != nil && err != io.EOF {
		return false, err
	}
	return n >= 8 && (bytes.Equal(hdr[:], sigEVF) || bytes.Equal(hdr[:], sigEVF2)), nil
}

// ewfSegments returns every segment file of the EWF set that path belongs to, in
// sorted (segment) order. go-ewf re-sorts by the segment number in each header,
// so lexical order here only needs to enumerate the set completely.
func ewfSegments(path string) ([]string, error) {
	dir := filepath.Dir(path)
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var segs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		if strings.TrimSuffix(name, ext) != base {
			continue
		}
		if ewfSegmentExt.MatchString(ext) {
			segs = append(segs, filepath.Join(dir, name))
		}
	}
	if len(segs) == 0 {
		// The path itself did not survive the directory scan (odd name); fall
		// back to just it so a lone, oddly-named segment still opens.
		segs = []string{path}
	}
	sort.Strings(segs)
	return segs, nil
}

// Format labels the image container by its content: "e01", "dmg",
// "sparseimage", "sparsebundle", "encrypted-dmg", "vmdk", "vhdx", "vhd",
// "qcow2", "vdi" or "raw" (anything else, a mislabelled name included — an
// uncompressed .dmg with no koly trailer is a raw image).
func Format(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, statErr := f.Stat()
	if statErr == nil && st.IsDir() {
		if _, ok := bundleInfo(path); ok {
			return "sparsebundle"
		}
		return ""
	}
	var hdr [8]byte
	n, _ := f.ReadAt(hdr[:], 0)
	if n >= 8 && (bytes.Equal(hdr[:], sigEVF) || bytes.Equal(hdr[:], sigEVF2)) {
		return "e01"
	}
	if statErr == nil && looksLikeDMG(f, st.Size()) {
		return "dmg"
	}
	if n >= 4 && bytes.Equal(hdr[:4], sigSprs) {
		return "sparseimage"
	}
	if statErr == nil && looksLikeEncryptedDMG(f, st.Size()) {
		return "encrypted-dmg"
	}
	if sparse, desc := looksLikeVMDK(f); sparse || desc {
		return "vmdk"
	}
	if looksLikeVHDX(f) {
		return "vhdx"
	}
	if n >= 4 && bytes.Equal(hdr[:4], sigQFI) {
		return "qcow2"
	}
	if looksLikeVDI(f) {
		return "vdi"
	}
	if statErr == nil && looksLikeVHD(f, st.Size()) {
		return "vhd"
	}
	return "raw" // a name alone never decides: a mislabelled raw stays raw
}
