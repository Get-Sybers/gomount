package imagetest

// Apple sparse images around raw bytes, written from libyal's "Mac OS disk
// image types": a .sparseimage (sprs header, band table, bands in the
// order given) and a .sparsebundle directory (Info.plist, bands/<hex>).

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// WriteSparseImage encodes raw as a .sparseimage of bandSectors-sector
// bands at path. order lists the disk bands in the order they are stored
// in the file; bands not listed are never written (read back as zeros).
// nil stores every non-zero band in disk order.
func WriteSparseImage(path string, raw []byte, bandSectors int, order []int) error {
	if len(raw)%sector != 0 {
		return fmt.Errorf("raw length %d is not sector-aligned", len(raw))
	}
	bandBytes := bandSectors * sector
	nBands := (len(raw) + bandBytes - 1) / bandBytes
	if order == nil {
		for b := 0; b < nBands; b++ {
			if !isZero(band(raw, b, bandBytes)) {
				order = append(order, b)
			}
		}
	}
	if 64+4*nBands > 4096 {
		return fmt.Errorf("%d bands do not fit the 4096-byte header", nBands)
	}
	out := make([]byte, 4096, 4096+len(order)*bandBytes)
	copy(out, "sprs")
	binary.BigEndian.PutUint32(out[4:], 3)
	binary.BigEndian.PutUint32(out[8:], uint32(bandSectors))
	binary.BigEndian.PutUint32(out[12:], 1)
	binary.BigEndian.PutUint32(out[16:], uint32(len(raw)/sector))
	binary.BigEndian.PutUint32(out[32:], uint32(len(raw)/sector))
	for i, b := range order {
		binary.BigEndian.PutUint32(out[64+4*i:], uint32(b+1))
		chunk := make([]byte, bandBytes) // a short last band is padded
		copy(chunk, band(raw, b, bandBytes))
		out = append(out, chunk...)
	}
	return os.WriteFile(path, out, 0o644)
}

// WriteSparseBundle encodes raw as a .sparsebundle directory at dir with
// bands of bandBytes. All-zero bands are not written; the last band file is
// cut after its last non-zero byte (as a band file ends where data does).
func WriteSparseBundle(dir string, raw []byte, bandBytes int) error {
	if err := os.MkdirAll(filepath.Join(dir, "bands"), 0o755); err != nil {
		return err
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>band-size</key>
	<integer>%d</integer>
	<key>bundle-backingstore-version</key>
	<integer>1</integer>
	<key>diskimage-bundle-type</key>
	<string>com.apple.diskimage.sparsebundle</string>
	<key>size</key>
	<integer>%d</integer>
</dict>
</plist>
`, bandBytes, len(raw))
	for _, name := range []string{"Info.plist", "Info.bckup"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(plist), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), nil, 0o644); err != nil {
		return err
	}
	nBands := (len(raw) + bandBytes - 1) / bandBytes
	for b := 0; b < nBands; b++ {
		data := band(raw, b, bandBytes)
		if isZero(data) {
			continue
		}
		if b == nBands-1 {
			end := len(data)
			for end > 0 && data[end-1] == 0 {
				end--
			}
			data = data[:end]
		}
		if err := os.WriteFile(filepath.Join(dir, "bands", strconv.FormatInt(int64(b), 16)), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func band(raw []byte, b, bandBytes int) []byte {
	end := min((b+1)*bandBytes, len(raw))
	return raw[b*bandBytes : end]
}
