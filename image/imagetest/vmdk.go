// Package imagetest writes small container images around raw bytes so the
// image package's decoders (and the verbs above them) can be tested without
// real evidence: a monolithicSparse VMDK (plain or streamOptimized), a
// descriptor + flat extent pair, the same raw bytes in a fixed VHD, and a
// UDIF .dmg of any mix of chunk types (dmg.go).
package imagetest

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

const sector = 512

// VMDKOptions shape the sparse extent WriteSparseVMDK emits.
type VMDKOptions struct {
	GrainSectors int  // grain size in sectors (default 16 — 8 KiB, small so tests stay small)
	GTEsPerGT    int  // grain table entries per table (default 512)
	Compressed   bool // streamOptimized: zlib grains behind markers, GD in the footer
	// ZeroGrains lists grain indexes left unallocated (read back as zeros
	// whatever the raw bytes held there).
	ZeroGrains map[int]bool
	// Descriptor overrides the embedded text descriptor ("" = a plain
	// monolithicSparse one naming the file itself).
	Descriptor string
}

// WriteSparseVMDK encodes raw as a KDMV sparse extent at path. Only grains
// whose raw bytes are not all zero are allocated, so the file is a real
// sparse layout; grains in opts.ZeroGrains are left unallocated too.
func WriteSparseVMDK(path string, raw []byte, opts VMDKOptions) error {
	if opts.GrainSectors == 0 {
		opts.GrainSectors = 16
	}
	if opts.GTEsPerGT == 0 {
		opts.GTEsPerGT = 512
	}
	grainBytes := opts.GrainSectors * sector
	if len(raw)%sector != 0 {
		return fmt.Errorf("raw length %d is not sector-aligned", len(raw))
	}
	capacity := len(raw) / sector
	numGrains := (len(raw) + grainBytes - 1) / grainBytes
	numGT := (numGrains + opts.GTEsPerGT - 1) / opts.GTEsPerGT
	gtSectors := (opts.GTEsPerGT*4 + sector - 1) / sector
	gdSectors := (numGT*4 + sector - 1) / sector
	if gdSectors == 0 {
		gdSectors = 1
	}

	descriptor := opts.Descriptor
	if descriptor == "" {
		descriptor = fmt.Sprintf("# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\n# Extent description\nRW %d SPARSE \"%s\"\n\n# The Disk Data Base\n#DDB\n\nddb.virtualHWVersion = \"4\"\n", capacity, filepath.Base(path))
	}
	descSectors := (len(descriptor) + sector - 1) / sector
	if descSectors == 0 {
		descSectors = 1
	}

	// layout: header | descriptor | GD | GTs | grains (| footer for compressed)
	descOff := 1
	gdOff := descOff + descSectors
	gtOff := gdOff + gdSectors
	dataOff := gtOff + numGT*gtSectors
	overhead := dataOff

	var body bytes.Buffer
	gd := make([]uint32, numGT)
	gts := make([][]uint32, numGT)
	for i := range gts {
		gd[i] = uint32(gtOff + i*gtSectors)
		gts[i] = make([]uint32, opts.GTEsPerGT)
	}
	cur := dataOff
	for g := 0; g < numGrains; g++ {
		start := g * grainBytes
		end := start + grainBytes
		if end > len(raw) {
			end = len(raw)
		}
		chunk := make([]byte, grainBytes)
		copy(chunk, raw[start:end])
		if opts.ZeroGrains[g] || bytes.Equal(chunk, make([]byte, grainBytes)) {
			continue
		}
		gts[g/opts.GTEsPerGT][g%opts.GTEsPerGT] = uint32(cur)
		if opts.Compressed {
			var zb bytes.Buffer
			zw := zlib.NewWriter(&zb)
			zw.Write(chunk)
			zw.Close()
			mk := make([]byte, 12)
			binary.LittleEndian.PutUint64(mk[0:8], uint64(g*opts.GrainSectors))
			binary.LittleEndian.PutUint32(mk[8:12], uint32(zb.Len()))
			body.Write(mk)
			body.Write(zb.Bytes())
			pad := (sector - (12+zb.Len())%sector) % sector
			body.Write(make([]byte, pad))
			cur += (12 + zb.Len() + pad) / sector
		} else {
			body.Write(chunk)
			cur += opts.GrainSectors
		}
	}

	hdr := make([]byte, sector)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x564d444b)
	binary.LittleEndian.PutUint32(hdr[4:8], 1)
	flags := uint32(1)
	if opts.Compressed {
		flags |= 1<<16 | 1<<17
	}
	binary.LittleEndian.PutUint32(hdr[8:12], flags)
	binary.LittleEndian.PutUint64(hdr[12:20], uint64(capacity))
	binary.LittleEndian.PutUint64(hdr[20:28], uint64(opts.GrainSectors))
	binary.LittleEndian.PutUint64(hdr[28:36], uint64(descOff))
	binary.LittleEndian.PutUint64(hdr[36:44], uint64(descSectors))
	binary.LittleEndian.PutUint32(hdr[44:48], uint32(opts.GTEsPerGT))
	binary.LittleEndian.PutUint64(hdr[48:56], 0) // no redundant GD
	binary.LittleEndian.PutUint64(hdr[56:64], uint64(gdOff))
	binary.LittleEndian.PutUint64(hdr[64:72], uint64(overhead))
	hdr[73], hdr[74], hdr[75], hdr[76] = '\n', ' ', '\r', '\n'
	if opts.Compressed {
		binary.LittleEndian.PutUint16(hdr[77:79], 1)
	}

	var out bytes.Buffer
	if opts.Compressed {
		// the header at 0 of a streamOptimized extent carries no GD yet
		h0 := append([]byte(nil), hdr...)
		binary.LittleEndian.PutUint64(h0[56:64], ^uint64(0))
		out.Write(h0)
	} else {
		out.Write(hdr)
	}
	d := make([]byte, descSectors*sector)
	copy(d, descriptor)
	out.Write(d)
	gdb := make([]byte, gdSectors*sector)
	for i, v := range gd {
		binary.LittleEndian.PutUint32(gdb[i*4:], v)
	}
	out.Write(gdb)
	for _, gt := range gts {
		b := make([]byte, gtSectors*sector)
		for i, v := range gt {
			binary.LittleEndian.PutUint32(b[i*4:], v)
		}
		out.Write(b)
	}
	out.Write(body.Bytes())
	if opts.Compressed {
		// footer marker (one sector), the header copy, then the EOS marker
		out.Write(make([]byte, sector))
		out.Write(hdr)
		out.Write(make([]byte, sector))
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// WriteFlatVMDK writes raw as <stem>-flat.vmdk beside a text descriptor at
// path that names it (a monolithicFlat pair), with an optional leading ZERO
// extent of zeroSectors.
func WriteFlatVMDK(path string, raw []byte, zeroSectors int) error {
	if len(raw)%sector != 0 {
		return fmt.Errorf("raw length %d is not sector-aligned", len(raw))
	}
	stem := filepath.Base(path[:len(path)-len(filepath.Ext(path))])
	flat := filepath.Join(filepath.Dir(path), stem+"-flat.vmdk")
	if err := os.WriteFile(flat, raw, 0o644); err != nil {
		return err
	}
	desc := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\n\n# Extent description\n"
	if zeroSectors > 0 {
		desc += fmt.Sprintf("RW %d ZERO\n", zeroSectors)
	}
	desc += fmt.Sprintf("RW %d FLAT \"%s\" 0\n\n#DDB\n", len(raw)/sector, stem+"-flat.vmdk")
	return os.WriteFile(path, []byte(desc), 0o644)
}

// WriteFixedVHD writes raw followed by a "conectix" fixed-disk footer.
func WriteFixedVHD(path string, raw []byte) error {
	ft := make([]byte, 512)
	copy(ft[0:8], "conectix")
	binary.BigEndian.PutUint32(ft[8:12], 2)           // features: reserved bit
	binary.BigEndian.PutUint32(ft[12:16], 0x00010000) // version
	binary.BigEndian.PutUint64(ft[16:24], ^uint64(0)) // data offset: none (fixed)
	binary.BigEndian.PutUint64(ft[40:48], uint64(len(raw)))
	binary.BigEndian.PutUint64(ft[48:56], uint64(len(raw)))
	binary.BigEndian.PutUint32(ft[60:64], 2) // fixed
	return os.WriteFile(path, append(append([]byte(nil), raw...), ft...), 0o644)
}

// WriteDynamicVHD writes raw as a dynamic ("cxsparse") VHD with the given
// block size; all-zero blocks are left unallocated.
func WriteDynamicVHD(path string, raw []byte, blockSize int) error {
	if blockSize%512 != 0 || len(raw)%512 != 0 {
		return fmt.Errorf("sizes must be sector-aligned")
	}
	blocks := (len(raw) + blockSize - 1) / blockSize
	sectorsPerBlock := blockSize / 512
	bitmapBytes := (sectorsPerBlock + 7) / 8
	bitmapSectors := (bitmapBytes + 511) / 512

	footer := make([]byte, 512)
	copy(footer[0:8], "conectix")
	binary.BigEndian.PutUint32(footer[8:12], 2)
	binary.BigEndian.PutUint32(footer[12:16], 0x00010000)
	binary.BigEndian.PutUint64(footer[16:24], 512) // dynamic header follows the footer copy
	binary.BigEndian.PutUint64(footer[40:48], uint64(len(raw)))
	binary.BigEndian.PutUint64(footer[48:56], uint64(len(raw)))
	binary.BigEndian.PutUint32(footer[60:64], 3) // dynamic

	dh := make([]byte, 1024)
	copy(dh[0:8], "cxsparse")
	binary.BigEndian.PutUint64(dh[8:16], ^uint64(0))
	batOff := int64(512 + 1024)
	binary.BigEndian.PutUint64(dh[16:24], uint64(batOff))
	binary.BigEndian.PutUint32(dh[24:28], 0x00010000)
	binary.BigEndian.PutUint32(dh[28:32], uint32(blocks))
	binary.BigEndian.PutUint32(dh[32:36], uint32(blockSize))

	batSectors := (blocks*4 + 511) / 512
	bat := make([]byte, batSectors*512)
	for i := range bat {
		bat[i] = 0xff
	}
	var data bytes.Buffer
	cur := int(batOff)/512 + batSectors
	for b := 0; b < blocks; b++ {
		start := b * blockSize
		end := start + blockSize
		if end > len(raw) {
			end = len(raw)
		}
		chunk := make([]byte, blockSize)
		copy(chunk, raw[start:end])
		if bytes.Equal(chunk, make([]byte, blockSize)) {
			continue
		}
		binary.BigEndian.PutUint32(bat[b*4:], uint32(cur))
		bm := make([]byte, bitmapSectors*512)
		for i := range bm[:bitmapBytes] {
			bm[i] = 0xff
		}
		data.Write(bm)
		data.Write(chunk)
		cur += bitmapSectors + sectorsPerBlock
	}
	var out bytes.Buffer
	out.Write(footer) // the leading footer copy
	out.Write(dh)
	out.Write(bat)
	out.Write(data.Bytes())
	out.Write(footer)
	return os.WriteFile(path, out.Bytes(), 0o644)
}
