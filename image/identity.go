// Evidence-asset identity surfaced from the container, for the origin
// records the model-B tools stamp onto parser output: the drive/device
// serial (or a virtual-disk container uuid) and a sha256 of the container
// bytes as delivered. Both are read-only and additive; a format that has
// no such identifier yields "" (an honest null, never a faked value).
package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	ewf "github.com/Velocidex/go-ewf/parser"
)

// DiskSerial returns the acquisition drive/device serial, or the virtual
// disk's own container uuid, carried by an opened image (the reader
// OpenImage returned). It is read from what the open already parsed — no
// extra I/O — and is "" for the formats that carry no such identifier
// (raw/dd, QCOW2, DMG and the Apple sparse images):
//
//   - EWF/E01:  the acquisition "Serial Number" header ("sn").
//   - VMDK:     ddb.uuid.image (canonical) else the content id (CID).
//   - VHDX:     the "Virtual Disk ID" metadata item.
//   - VHD:      the footer "Unique Id".
//   - VDI:      the image uuid.
func DiskSerial(ra io.ReaderAt) string {
	switch v := ra.(type) {
	case *ewf.EWFFile:
		if v.Metadata == nil {
			return ""
		}
		s, _ := v.Metadata.GetString("Serial Number")
		return strings.TrimSpace(s)
	case *vmdkDisk:
		return v.containerID
	case *vhdxDisk:
		return guidString(v.diskID[:])
	case *vhdDisk:
		return uuidStraight(v.uniqueID[:])
	case *vdiDisk:
		return nonZeroGUID(vdiUUIDString(v.hdr.imageUUID))
	}
	return ""
}

// HashContainer streams sha256 over the image's container bytes AS
// DELIVERED — the on-disk acquisition file(s), not the decoded media. A
// multi-segment EWF set hashes every segment in order through one running
// digest; any other format hashes the single file at path. A container
// with no single hashable file (an Apple .sparsebundle directory) yields
// "" with no error. It opens its own read-only handles and is independent
// of OpenImage, so a caller hashes only when asked (gomount's --hash).
func HashContainer(path string) (string, error) {
	var segs []string
	if Format(path) == "e01" {
		s, err := ewfSegments(path)
		if err != nil {
			return "", err
		}
		segs = s
	} else {
		fi, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if fi.IsDir() { // a .sparsebundle is a directory of bands, not one container file
			return "", nil
		}
		segs = []string{path}
	}
	h := sha256.New()
	for _, p := range segs {
		f, err := os.Open(p) // O_RDONLY
		if err != nil {
			return "", err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// guidString renders a Microsoft GUID (the first three fields little-endian
// on disk, the last two big-endian) in canonical 8-4-4-4-12 form — the
// convention VHDX metadata and the VDI header use. An all-zero GUID is
// "none", returned as "".
func guidString(b []byte) string {
	if len(b) < 16 || allZero(b[:16]) {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

// uuidStraight renders 16 bytes as a UUID with no byte-swapping — the VHD
// footer stores its Unique Id big-endian. An all-zero id is "".
func uuidStraight(b []byte) string {
	if len(b) < 16 || allZero(b[:16]) {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// canonicalVMDKUUID turns a ddb.uuid.image value — 16 space-separated hex
// bytes, as VMware writes it — into a canonical 8-4-4-4-12 uuid, or ""
// when it is not exactly 16 bytes of hex.
func canonicalVMDKUUID(s string) string {
	var h []byte
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			h = append(h, byte(c))
		case c >= 'A' && c <= 'F':
			h = append(h, byte(c-'A'+'a'))
		}
	}
	if len(h) != 32 {
		return ""
	}
	s = string(h)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// nonZeroGUID blanks the all-zero uuid string (VDI's renderer has no zero
// guard of its own).
func nonZeroGUID(s string) string {
	if s == "00000000-0000-0000-0000-000000000000" {
		return ""
	}
	return s
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
