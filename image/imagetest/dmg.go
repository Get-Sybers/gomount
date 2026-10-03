package imagetest

// UDIF (.dmg) images around raw bytes, written from the format (libyal's
// "Mac OS disk image types"): a data fork of chunk payloads, the block
// tables ("mish") in an XML plist — or a classic resource fork — and the
// 512-byte koly trailer. Plus an ADC encoder, so the reader's ADC decoder
// has streams to decode that it did not write itself.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// UDIF chunk types.
const (
	DMGZero       uint32 = 0x00000000
	DMGRaw        uint32 = 0x00000001
	DMGIgnore     uint32 = 0x00000002
	DMGComment    uint32 = 0x7ffffffe
	DMGADC        uint32 = 0x80000004
	DMGZlib       uint32 = 0x80000005
	DMGBzip2      uint32 = 0x80000006
	DMGLZFSE      uint32 = 0x80000007
	DMGLZMA       uint32 = 0x80000008
	DMGTerminator uint32 = 0xffffffff
)

// DMGTable is one block table: the sectors [Start, End) of the raw disk,
// cut into chunks. Sectors outside every table are left unmapped.
type DMGTable struct{ Start, End int }

// DMGOptions shape the image WriteDMG emits.
type DMGOptions struct {
	ChunkSectors int // sectors per chunk (default 8)
	// Encode picks how chunk i (its raw bytes) is stored: the chunk type and
	// the payload written to the data fork (nil for zero/ignore). nil means
	// zero-fill for an all-zero chunk, zlib otherwise.
	Encode func(i int, chunk []byte) (typ uint32, payload []byte)
	// Prefix is written before the data fork (a data fork offset ≠ 0).
	Prefix []byte
	// Tables splits the disk into several block tables (default: one over
	// the whole disk). The second and later tables carry a non-zero table
	// data offset, their chunk offsets counting from it.
	Tables []DMGTable
	// ResourceFork stores the tables as 'blkx' resources of a classic
	// resource fork instead of the XML plist.
	ResourceFork bool
}

// WriteDMG encodes raw (sector-aligned) as a UDIF image at path.
func WriteDMG(path string, raw []byte, opts DMGOptions) error {
	if len(raw)%sector != 0 {
		return fmt.Errorf("raw length %d is not sector-aligned", len(raw))
	}
	if opts.ChunkSectors == 0 {
		opts.ChunkSectors = 8
	}
	if opts.Encode == nil {
		opts.Encode = func(_ int, b []byte) (uint32, []byte) {
			if isZero(b) {
				return DMGZero, nil
			}
			return DMGZlib, Zlib(b)
		}
	}
	totalSectors := len(raw) / sector
	if len(opts.Tables) == 0 {
		opts.Tables = []DMGTable{{0, totalSectors}}
	}

	var fork bytes.Buffer // the data fork
	var tables [][]byte
	chunkIdx := 0
	for ti, t := range opts.Tables {
		tableDataOff := 0
		if ti > 0 {
			tableDataOff = fork.Len()
		}
		type entry struct {
			typ                uint32
			sec, cnt, off, len uint64
		}
		// a comment entry first, as hdiutil writes, then the chunks
		entries := []entry{{typ: DMGComment}}
		for s := t.Start; s < t.End; s += opts.ChunkSectors {
			n := opts.ChunkSectors
			if s+n > t.End {
				n = t.End - s
			}
			typ, payload := opts.Encode(chunkIdx, raw[s*sector:(s+n)*sector])
			chunkIdx++
			e := entry{typ: typ, sec: uint64(s - t.Start), cnt: uint64(n)}
			if payload != nil {
				e.off = uint64(fork.Len() - tableDataOff)
				e.len = uint64(len(payload))
				fork.Write(payload)
			}
			entries = append(entries, e)
		}
		entries = append(entries, entry{typ: DMGTerminator, sec: uint64(t.End - t.Start)})

		m := make([]byte, 204+40*len(entries))
		copy(m, "mish")
		binary.BigEndian.PutUint32(m[4:], 1)
		binary.BigEndian.PutUint64(m[8:], uint64(t.Start))
		binary.BigEndian.PutUint64(m[16:], uint64(t.End-t.Start))
		binary.BigEndian.PutUint64(m[24:], uint64(tableDataOff))
		binary.BigEndian.PutUint32(m[36:], uint32(ti))
		binary.BigEndian.PutUint32(m[200:], uint32(len(entries)))
		for i, e := range entries {
			b := m[204+40*i:]
			binary.BigEndian.PutUint32(b[0:], e.typ)
			binary.BigEndian.PutUint64(b[8:], e.sec)
			binary.BigEndian.PutUint64(b[16:], e.cnt)
			binary.BigEndian.PutUint64(b[24:], e.off)
			binary.BigEndian.PutUint64(b[32:], e.len)
		}
		tables = append(tables, m)
	}

	var out bytes.Buffer
	out.Write(opts.Prefix)
	dataOff := out.Len()
	out.Write(fork.Bytes())
	k := make([]byte, sector)
	copy(k, "koly")
	binary.BigEndian.PutUint32(k[4:], 4)
	binary.BigEndian.PutUint32(k[8:], 512)
	binary.BigEndian.PutUint32(k[12:], 1)
	binary.BigEndian.PutUint64(k[24:], uint64(dataOff))
	binary.BigEndian.PutUint64(k[32:], uint64(fork.Len()))
	binary.BigEndian.PutUint32(k[56:], 1)
	binary.BigEndian.PutUint32(k[60:], 1)
	metaOff := out.Len()
	if opts.ResourceFork {
		out.Write(resourceFork(tables))
		binary.BigEndian.PutUint64(k[40:], uint64(metaOff))
		binary.BigEndian.PutUint64(k[48:], uint64(out.Len()-metaOff))
	} else {
		out.WriteString(blkxPlist(tables))
		binary.BigEndian.PutUint64(k[216:], uint64(metaOff))
		binary.BigEndian.PutUint64(k[224:], uint64(out.Len()-metaOff))
	}
	binary.BigEndian.PutUint32(k[488:], 1)
	binary.BigEndian.PutUint64(k[492:], uint64(totalSectors))
	out.Write(k)
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func blkxPlist(tables [][]byte) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>resource-fork</key>
	<dict>
		<key>blkx</key>
		<array>
`)
	for i, m := range tables {
		enc := base64.StdEncoding.EncodeToString(m)
		var wrapped strings.Builder
		for len(enc) > 52 { // wrapped like hdiutil's output
			wrapped.WriteString("\t\t\t\t" + enc[:52] + "\n")
			enc = enc[52:]
		}
		wrapped.WriteString("\t\t\t\t" + enc + "\n")
		fmt.Fprintf(&b, "\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n\t\t\t\t<key>CFName</key>\n\t\t\t\t<string>table %d</string>\n\t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n%s\t\t\t\t</data>\n\t\t\t\t<key>ID</key>\n\t\t\t\t<string>%d</string>\n\t\t\t\t<key>Name</key>\n\t\t\t\t<string>table %d</string>\n\t\t\t</dict>\n", i, wrapped.String(), i-1, i)
	}
	b.WriteString("\t\t</array>\n\t\t<key>plst</key>\n\t\t<array>\n\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n\t\t\t\t<key>Data</key>\n\t\t\t\t<data>AAAA</data>\n\t\t\t\t<key>ID</key>\n\t\t\t\t<string>0</string>\n\t\t\t\t<key>Name</key>\n\t\t\t\t<string></string>\n\t\t\t</dict>\n\t\t</array>\n\t</dict>\n</dict>\n</plist>\n")
	return b.String()
}

// resourceFork lays the tables out as 'blkx' resources of a classic Mac
// resource fork: a 256-byte header area, the data area (each resource a
// 4-byte length and its bytes), then the map with one type and its
// reference list.
func resourceFork(tables [][]byte) []byte {
	const dataOff = 256
	var data bytes.Buffer
	offs := make([]int, len(tables))
	for i, m := range tables {
		offs[i] = data.Len()
		binary.Write(&data, binary.BigEndian, uint32(len(m)))
		data.Write(m)
	}
	mp := make([]byte, 28+2+8+12*len(tables))
	binary.BigEndian.PutUint16(mp[24:], 28)              // type list offset
	binary.BigEndian.PutUint16(mp[26:], uint16(len(mp))) // name list offset (empty)
	binary.BigEndian.PutUint16(mp[28:], 0)               // one type
	copy(mp[30:], "blkx")
	binary.BigEndian.PutUint16(mp[34:], uint16(len(tables)-1))
	binary.BigEndian.PutUint16(mp[36:], 10) // reference list, from the type list
	for i := range tables {
		r := mp[38+12*i:]
		binary.BigEndian.PutUint16(r[0:], uint16(i))
		binary.BigEndian.PutUint16(r[2:], 0xffff)
		binary.BigEndian.PutUint32(r[4:], uint32(offs[i])&0x00ffffff)
	}
	mapOff := dataOff + data.Len()
	out := make([]byte, dataOff)
	binary.BigEndian.PutUint32(out[0:], dataOff)
	binary.BigEndian.PutUint32(out[4:], uint32(mapOff))
	binary.BigEndian.PutUint32(out[8:], uint32(data.Len()))
	binary.BigEndian.PutUint32(out[12:], uint32(len(mp)))
	copy(mp[0:16], out[0:16])
	out = append(out, data.Bytes()...)
	return append(out, mp...)
}

// Zlib returns b zlib-compressed.
func Zlib(b []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// ADC encodes b as an Apple Data Compression stream: greedy longest matches
// within the 64 KiB window (the two-byte form when it fits: 3..18 bytes
// within 1 KiB), literal runs of up to 128 bytes otherwise.
func ADC(b []byte) []byte {
	var out, lit []byte
	flush := func() {
		for len(lit) > 0 {
			n := min(len(lit), 128)
			out = append(out, byte(0x80|(n-1)))
			out = append(out, lit[:n]...)
			lit = lit[n:]
		}
	}
	for i := 0; i < len(b); {
		bestLen, bestDist := 0, 0
		for dist := 1; dist <= 65536 && dist <= i; dist++ {
			l := 0
			for l < 67 && i+l < len(b) && b[i+l] == b[i+l-dist] {
				l++
			}
			if l > bestLen {
				bestLen, bestDist = l, dist
				if l == 67 {
					break
				}
			}
		}
		switch {
		case bestLen >= 3 && bestLen <= 18 && bestDist <= 1024:
			flush()
			d := bestDist - 1
			out = append(out, byte((bestLen-3)<<2|d>>8), byte(d))
		case bestLen >= 4:
			flush()
			d := bestDist - 1
			out = append(out, byte(0x40|(bestLen-4)), byte(d>>8), byte(d))
		default:
			bestLen = 1
			lit = append(lit, b[i])
		}
		i += bestLen
	}
	flush()
	return out
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
