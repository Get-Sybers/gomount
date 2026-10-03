package image

// dmg_test: the UDIF reader against DMGs Apple's own hdiutil wrote
// (Homebrew's cask test fixtures, BSD-2-Clause — THIRD_PARTY_NOTICES.md),
// byte for byte against their reassembled raw disks and through the whole
// stack above; then every chunk type, table layout and malformation on
// images imagetest writes from the format.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Get-Sybers/gomount/fsx"
	_ "github.com/Get-Sybers/gomount/fsx/apfs"
	"github.com/Get-Sybers/gomount/fsx/fsxtest"
	_ "github.com/Get-Sybers/gomount/fsx/hfsplus"
	"github.com/Get-Sybers/gomount/image/imagetest"
	"github.com/Get-Sybers/gomount/partition"
)

// openStack opens a DMG through OpenImage, finds its one partition and
// opens the filesystem on it.
func openStack(t *testing.T, path, wantPart, wantFS string) fsx.FS {
	t.Helper()
	ra, size, closer, err := OpenImage(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closer() })
	parts, err := partition.Partitions(ra, size)
	if err != nil || len(parts) != 1 || parts[0].TypeName != wantPart || parts[0].Offset != 20480 {
		t.Fatalf("%s: partitions %+v %v", filepath.Base(path), parts, err)
	}
	vol := io.NewSectionReader(ra, parts[0].Offset, parts[0].Size)
	if got := fsx.Probe(vol, parts[0].Size); got != wantFS {
		t.Fatalf("%s: probe %q, want %q", filepath.Base(path), got, wantFS)
	}
	f, err := fsx.Open(vol, parts[0].Size)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func readFile(t *testing.T, f fsx.FS, path string) []byte {
	t.Helper()
	r, err := f.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	f, size := fsxtest.Open(t, "../fsx/testdata", name)
	b := make([]byte, size)
	if _, err := f.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDMGAppleTransmission(t *testing.T) {
	p := "testdata/transmission-2.61.dmg"
	if f := Format(p); f != "dmg" {
		t.Fatalf("Format: %q", f)
	}
	// zlib, zero and ignore chunks over eight block tables reassemble to
	// exactly the raw disk the HFS+ backend's own fixture holds
	readAll(t, p, fixtureBytes(t, "hfsplus-transmission"))
	f := openStack(t, p, "Apple HFS+", "hfsplus")
	if info := f.Info(); info.Label != "Transmission" || info.UUID != "89936734-09d3-3820-ac70-c19dd6a4d6b2" {
		t.Fatalf("info: %+v", info)
	}
	if b := readFile(t, f, "/Transmission.app/Contents/Info.plist"); !bytes.Contains(b, []byte("org.m0k.transmission")) {
		t.Fatalf("Info.plist: %q", b)
	}
}

func TestDMGAppleAPFS(t *testing.T) {
	p := "testdata/container-apfs.dmg"
	readAll(t, p, fixtureBytes(t, "apfs-container"))
	f := openStack(t, p, "Apple APFS", "apfs")
	if info := f.Info(); info.Label != "container-apfs" {
		t.Fatalf("info: %+v", info)
	}
	if b := readFile(t, f, "/container"); len(b) != 17 {
		t.Fatalf("/container: %q", b)
	}
}

func TestDMGAppleHFSContainer(t *testing.T) {
	// no reassembled fixture: the stack reading a script out of it is the proof
	f := openStack(t, "testdata/container.dmg", "Apple HFS+", "hfsplus")
	if info := f.Info(); info.Label != "container.dmg" {
		t.Fatalf("info: %+v", info)
	}
	if b := readFile(t, f, "/container"); string(b) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("/container: %q", b)
	}
}

// dmgRawDisk is a raw disk the synthetic images encode: random sectors (raw
// and zlib and ADC barely compress them), repetitive text (ADC and zlib do)
// and all-zero runs (zero-fill and ignore chunks).
func dmgRawDisk(sectors int) []byte {
	r := rand.New(rand.NewSource(11))
	raw := make([]byte, sectors*512)
	for s := 0; s < sectors; s++ {
		b := raw[s*512 : (s+1)*512]
		switch (s / 8) % 4 {
		case 0:
			r.Read(b)
		case 1:
			for i := range b {
				b[i] = "the quick brown fox jumps over the lazy dog\n"[(s*512+i)%44]
			}
		case 2: // zeros
		case 3:
			for i := range b {
				b[i] = byte(i / 3)
			}
		}
	}
	return raw
}

// mixedEncoder stores chunk i as raw, zlib or ADC in turn; all-zero chunks
// as zero-fill or ignore.
func mixedEncoder(i int, b []byte) (uint32, []byte) {
	if bytes.Count(b, []byte{0}) == len(b) {
		if i%2 == 0 {
			return imagetest.DMGZero, nil
		}
		return imagetest.DMGIgnore, nil
	}
	switch i % 3 {
	case 0:
		return imagetest.DMGRaw, append([]byte(nil), b...)
	case 1:
		return imagetest.DMGZlib, imagetest.Zlib(b)
	}
	return imagetest.DMGADC, imagetest.ADC(b)
}

func TestDMGChunkTypesTablesAndGaps(t *testing.T) {
	raw := dmgRawDisk(96)
	// three tables with unmapped sectors before, between and after them,
	// the data fork behind a prefix; the gaps read as zeros
	tables := []imagetest.DMGTable{{Start: 3, End: 40}, {Start: 48, End: 77}, {Start: 77, End: 90}}
	want := make([]byte, len(raw))
	for _, tb := range tables {
		copy(want[tb.Start*512:tb.End*512], raw[tb.Start*512:tb.End*512])
	}
	for _, rsrc := range []bool{false, true} {
		t.Run(fmt.Sprintf("resourceFork=%v", rsrc), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "mixed.dmg")
			err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{
				ChunkSectors: 4, Encode: mixedEncoder, Tables: tables,
				Prefix: bytes.Repeat([]byte("MacBinary?"), 101), ResourceFork: rsrc,
			})
			if err != nil {
				t.Fatal(err)
			}
			if f := Format(p); f != "dmg" {
				t.Fatalf("Format: %q", f)
			}
			readAll(t, p, want)
			ra, _, closer, err := OpenImage(p)
			if err != nil {
				t.Fatal(err)
			}
			defer closer()
			types := ra.(*dmgDisk).chunkTypes()
			for _, k := range []string{"raw", "zlib", "ADC", "zero", "ignore"} {
				if types[k] == 0 {
					t.Errorf("no %s chunk exercised: %v", k, types)
				}
			}
		})
	}
}

// bzip2 and LZFSE chunks: the encoders are not in Go's stdlib, so these
// payloads were made once by the reference implementations — Python's bz2
// (libbzip2) and Apple's lzfse CLI (github.com/lzfse/lzfse) — from
// dmgTextChunk; the reader must decode them to it.
const (
	bzip2Payload = "425a6839314159265359527ae29200038dd980001040007fe00eef86004001d1dc63028001a064c8337eaaa9bff5548dfffaaaa09800129b5553f2a37e54260230295546d137ea91fa9068f24fe75d9bb7fbfeee77f800000000000000000000000000000000000cef523e451c0a3c0a3aeb5ad6b9eb5ad666666dae850a942a50a942a50a942a50a942a50a942ef7bcccccbbbbbd6b0a152854a152854a155924924def79999977777ad492492492492495b60036aaaaaaaaaadb001b55555555556d800ecdce756d800dce75b6c006e73adb6003739d6db199999999b2760a37a91b8a3ef7f4523c0a3d6a46c28e628fd147028e2a4790a371476147b0a3c8a3a0a3fc5dc914e1424149eb8a48"
	lzfsePayload = "6276783200100000b400f00400980040a4a3cf7cfa720040970000003f6ca00fbc090200008020000000e09b000f4e000008000040000000020000000000001300800900000000c013000000005c7e517fc29ff027fc097fc29ff027fc0900000000000000000000cc39b999937973737903306f0000000000000000000000000000000000000000000000000000000000000000000000000020816aa205807f00f8eeceff57552166665655559999898888ccccfcffbbffffefeeee32332322226666565555999989a80200cc10871e11816f5e0e0571e3b3d0810be65b8f8f94a940f0701e000000000000000000004080104208218410420821442184104208218410822808218410420821841042149024621042082184104210a210420821841042082144510821841042082108210a2184104208218410422c841042082184108410a2104208218410428a8a4108510821c4c6701962767824"
)

func dmgTextChunk() []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < 4096; i++ {
		fmt.Fprintf(&b, "gomount dmg chunk line %03d\n", i)
	}
	return b.Bytes()[:4096]
}

func TestDMGBzip2AndLZFSEChunks(t *testing.T) {
	chunk := dmgTextChunk()
	raw := append(append([]byte(nil), chunk...), chunk...)
	bz, _ := hex.DecodeString(bzip2Payload)
	lz, _ := hex.DecodeString(lzfsePayload)
	p := filepath.Join(t.TempDir(), "bz-lz.dmg")
	err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{Encode: func(i int, _ []byte) (uint32, []byte) {
		if i == 0 {
			return imagetest.DMGBzip2, bz
		}
		return imagetest.DMGLZFSE, lz
	}})
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, p, raw)
}

func TestDMGLZMAAndUnknownChunksRefused(t *testing.T) {
	raw := dmgRawDisk(24)
	p := filepath.Join(t.TempDir(), "ulmo.dmg")
	err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{Encode: func(i int, b []byte) (uint32, []byte) {
		switch i {
		case 1:
			return imagetest.DMGLZMA, []byte("\xfd7zXZ\x00 not decoded")
		case 2:
			return 0x80000009, []byte("from the future")
		}
		return imagetest.DMGZlib, imagetest.Zlib(b)
	}})
	if err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err) // the image opens: only the chunks themselves are unreadable
	}
	defer closer()
	buf := make([]byte, 8*512)
	if _, err := ra.ReadAt(buf, 0); err != nil || !bytes.Equal(buf, raw[:len(buf)]) {
		t.Fatalf("zlib chunk: %v", err)
	}
	if _, err := ra.ReadAt(buf, 8*512); err == nil || !strings.Contains(err.Error(), "LZMA chunks are not supported") {
		t.Fatalf("LZMA chunk: %v", err)
	}
	if _, err := ra.ReadAt(buf, 16*512); err == nil || !strings.Contains(err.Error(), "unsupported chunk type") {
		t.Fatalf("unknown chunk: %v", err)
	}
}

func TestDMGCorruptChunkIsAnError(t *testing.T) {
	raw := dmgRawDisk(16)
	for name, enc := range map[string]func(int, []byte) (uint32, []byte){
		"zlib garbage": func(_ int, b []byte) (uint32, []byte) {
			z := imagetest.Zlib(b)
			for i := 2; i < len(z) && i < 40; i++ {
				z[i] ^= 0x5a
			}
			return imagetest.DMGZlib, z
		},
		"zlib short": func(_ int, b []byte) (uint32, []byte) { return imagetest.DMGZlib, imagetest.Zlib(b[:1000]) },
		"adc short":  func(_ int, b []byte) (uint32, []byte) { return imagetest.DMGADC, imagetest.ADC(b[:1000]) },
		"adc before start": func(_ int, _ []byte) (uint32, []byte) {
			return imagetest.DMGADC, []byte{0x40, 0x10, 0x00}
		},
		"bzip2 garbage": func(_ int, _ []byte) (uint32, []byte) { return imagetest.DMGBzip2, []byte("BZh9 not really") },
		"lzfse garbage": func(_ int, _ []byte) (uint32, []byte) { return imagetest.DMGLZFSE, []byte("bvx2 not really") },
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.dmg")
			if err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{Encode: enc}); err != nil {
				t.Fatal(err)
			}
			ra, _, closer, err := OpenImage(p)
			if err != nil {
				t.Fatal(err)
			}
			defer closer()
			if _, err := ra.ReadAt(make([]byte, 512), 0); err == nil {
				t.Fatal("a chunk that does not decode to its sectors must be an error")
			}
		})
	}
}

// mish builds one block table: a header then the given 40-byte entries.
func mish(start, count uint64, entries ...[5]uint64) []byte {
	m := make([]byte, 204+40*len(entries))
	copy(m, "mish")
	binary.BigEndian.PutUint64(m[8:], start)
	binary.BigEndian.PutUint64(m[16:], count)
	binary.BigEndian.PutUint32(m[200:], uint32(len(entries)))
	for i, e := range entries {
		b := m[204+40*i:]
		binary.BigEndian.PutUint32(b[0:], uint32(e[0]))
		binary.BigEndian.PutUint64(b[8:], e[1])
		binary.BigEndian.PutUint64(b[16:], e[2])
		binary.BigEndian.PutUint64(b[24:], e[3])
		binary.BigEndian.PutUint64(b[32:], e[4])
	}
	return m
}

func TestDMGMalformedTables(t *testing.T) {
	const body = 4096
	for name, m := range map[string][]byte{
		"not mish":          append([]byte("MISH"), make([]byte, 300)...),
		"short":             []byte("mish"),
		"count past table":  func() []byte { m := mish(0, 8); binary.BigEndian.PutUint32(m[200:], 5); return m }(),
		"data past file":    mish(0, 8, [5]uint64{0x80000005, 0, 8, 4000, 200}),
		"offset wraps":      mish(0, 8, [5]uint64{0x80000005, 0, 8, ^uint64(0) - 10, 20}),
		"sectors wrap":      mish(0, 8, [5]uint64{0, ^uint64(0) - 2, 8, 0, 0}),
		"base wraps":        mish(^uint64(0)-4, 8),
		"chunk too large":   mish(0, 1<<20, [5]uint64{0x80000005, 0, 1 << 20, 0, 100}),
		"raw stored short":  mish(0, 8, [5]uint64{1, 0, 8, 0, 100}),
		"table data offset": func() []byte { m := mish(0, 8); binary.BigEndian.PutUint64(m[24:], body+1); return m }(),
	} {
		if _, err := parseMish(m, 0, body); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// a well-formed table maps what it says, comments and zero-length
	// entries dropped, the terminator ending it
	c, err := parseMish(mish(10, 16,
		[5]uint64{0x7ffffffe, 0, 0, 0, 0},
		[5]uint64{0x80000005, 0, 8, 100, 50},
		[5]uint64{1, 8, 0, 0, 0},
		[5]uint64{2, 8, 8, 0, 0},
		[5]uint64{0xffffffff, 16, 0, 0, 0},
		[5]uint64{1, 99, 1, 0, 512},
	), 7, body)
	if err != nil || len(c) != 2 || c[0].start != 10 || c[0].off != 107 || c[1].start != 18 || c[1].typ != 2 {
		t.Fatalf("chunks %+v %v", c, err)
	}
}

func TestDMGMalformedImages(t *testing.T) {
	raw := dmgRawDisk(32)
	good := filepath.Join(t.TempDir(), "good.dmg")
	if err := imagetest.WriteDMG(good, raw, imagetest.DMGOptions{}); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	k := len(src) - 512
	xmlOff := int(binary.BigEndian.Uint64(src[k+216:]))
	put64 := func(at int, v uint64) func([]byte) { return func(b []byte) { binary.BigEndian.PutUint64(b[at:], v) } }
	for name, mutate := range map[string]func([]byte){
		"trailer size":    func(b []byte) { binary.BigEndian.PutUint32(b[k+8:], 256) },
		"segmented":       func(b []byte) { binary.BigEndian.PutUint32(b[k+60:], 3) },
		"data fork past":  put64(k+32, uint64(k)+1),
		"xml past end":    put64(k+216, uint64(k)-10),
		"xml huge":        put64(k+224, 1<<40),
		"no tables":       func(b []byte) { put64(k+224, 0)(b); put64(k+48, 0)(b) },
		"rsrc garbage":    func(b []byte) { put64(k+224, 0)(b); put64(k+40, 0)(b); put64(k+48, 64)(b) },
		"sector count":    put64(k+492, 1<<60),
		"xml not a plist": func(b []byte) { copy(b[xmlOff:], "<html>") },
		"xml no blkx":     func(b []byte) { copy(b[bytes.Index(b, []byte("<key>blkx")):], "<key>BLKX") },
		"xml bad base64":  func(b []byte) { b[bytes.Index(b, []byte("<data>"))+10] = '*' },
	} {
		b := append([]byte(nil), src...)
		mutate(b)
		if _, err := parseDMG(bytes.NewReader(b), int64(len(b))); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// overlapping tables
	p := filepath.Join(t.TempDir(), "overlap.dmg")
	if err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{Tables: []imagetest.DMGTable{{Start: 0, End: 16}, {Start: 8, End: 32}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := OpenImage(p); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping tables: %v", err)
	}
	// an uncompressed .dmg without a trailer (a bare device image, as
	// macOS's own x86_64SURamDisk.dmg is) is simply raw
	bare := filepath.Join(t.TempDir(), "bare.dmg")
	if err := os.WriteFile(bare, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if f := Format(bare); f != "raw" {
		t.Fatalf("bare .dmg: %q", f)
	}
}

// Random damage to the metadata (the binary resource-fork tables, the
// trailer) and the payloads: every outcome is an image that opens and
// reads, or a Go error — never a panic, never a read past a buffer.
func TestDMGMutationsNeverPanic(t *testing.T) {
	raw := dmgRawDisk(40)
	p := filepath.Join(t.TempDir(), "m.dmg")
	if err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{ChunkSectors: 4, Encode: mixedEncoder, ResourceFork: true}); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	meta := int(binary.BigEndian.Uint64(src[len(src)-512+40:]))
	r := rand.New(rand.NewSource(3))
	buf := make([]byte, 4096)
	opened := 0
	for iter := 0; iter < 3000; iter++ {
		b := append([]byte(nil), src...)
		for n := 1 + r.Intn(6); n > 0; n-- {
			at := meta + r.Intn(len(b)-meta) // metadata and trailer
			if r.Intn(4) == 0 {
				at = r.Intn(len(b)) // anywhere
			}
			switch r.Intn(3) {
			case 0:
				b[at] = byte(r.Intn(256))
			case 1:
				b[at] = 0xff
			default:
				b[at] ^= 1 << r.Intn(8)
			}
		}
		d, err := parseDMG(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			continue
		}
		opened++
		for off := int64(0); off < d.size && off < 1<<22; off += int64(len(buf)) - 100 {
			d.ReadAt(buf, off)
		}
	}
	// most damage leaves a readable image: the reads above really ran
	if opened < 1000 {
		t.Fatalf("only %d of 3000 damaged images opened", opened)
	}
	t.Logf("%d of 3000 damaged images opened and were read", opened)
}

func TestDMGCacheEviction(t *testing.T) {
	raw := dmgRawDisk(64)
	p := filepath.Join(t.TempDir(), "z.dmg")
	if err := imagetest.WriteDMG(p, raw, imagetest.DMGOptions{ChunkSectors: 2}); err != nil {
		t.Fatal(err)
	}
	ra, _, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	d := ra.(*dmgDisk)
	d.cacheBudget = 3 * 1024 // three decoded chunks
	got := make([]byte, 700)
	for _, off := range []int64{0, 30000, 1024, 5000, 31000, 1, 20000, 0, 32000 - 700} {
		n, err := d.ReadAt(got, off)
		if err != nil || !bytes.Equal(got[:n], raw[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
		if d.cacheBytes > d.cacheBudget || len(d.lru) != len(d.cache) {
			t.Fatalf("cache over budget: %d bytes, %d/%d entries", d.cacheBytes, len(d.lru), len(d.cache))
		}
	}
}

func TestADC(t *testing.T) {
	// hand-encoded from the opcode grammar: literal "abc", then a two-byte
	// match of 3 at distance 3, a three-byte match of 6 at distance 1
	// (overlapping: repeats the last byte), and a literal "!"
	src := []byte{0x82, 'a', 'b', 'c', 0x00, 0x02, 0x42, 0x00, 0x00, 0x80, '!'}
	const want = "abc" + "abc" + "cccccc" + "!"
	for _, size := range []int{len(want), 64} {
		dst := make([]byte, size)
		n, err := adcDecode(dst, src)
		if err != nil || string(dst[:n]) != want {
			t.Fatalf("dst %d: got %q %v", size, dst[:n], err)
		}
	}
	for name, bad := range map[string][]byte{
		"literal truncated": {0x85, 'a'},
		"match truncated":   {0x80, 'a', 0x40, 0x00},
		"before start":      {0x80, 'a', 0x00, 0x05},
		"far before start":  {0x80, 'a', 0x7f, 0xff, 0xff},
	} {
		if _, err := adcDecode(make([]byte, 64), bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := adcDecode(make([]byte, 2), []byte{0x83, 'a', 'b', 'c', 'd'}); err == nil {
		t.Error("an overrunning literal must error")
	}
	// round trips through imagetest's encoder: short and long matches, near
	// and far (beyond the two-byte form's 1 KiB) distances
	r := rand.New(rand.NewSource(5))
	far := make([]byte, 3000)
	r.Read(far[:1500])
	copy(far[1500:], far[:1500])
	for _, in := range [][]byte{
		[]byte("a"), bytes.Repeat([]byte("z"), 1000), dmgTextChunk(), dmgRawDisk(4), far,
	} {
		out := make([]byte, len(in))
		if n, err := adcDecode(out, imagetest.ADC(in)); err != nil || n != len(in) || !bytes.Equal(out, in) {
			t.Fatalf("round trip of %d bytes: n=%d %v", len(in), n, err)
		}
	}
}

func TestPlistNestingBounded(t *testing.T) {
	deep := `<plist version="1.0">` + strings.Repeat("<array>", 100) + strings.Repeat("</array>", 100) + `</plist>`
	if _, err := parsePlist(strings.NewReader(deep)); err == nil {
		t.Fatal("a plist nested 100 deep must be refused")
	}
	v, err := parsePlist(strings.NewReader(`<?xml version="1.0"?><plist><dict><key>size</key><integer> 4194304 </integer><key>flag</key><true/></dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := v.get("size").uint(); !ok || n != 4194304 || v.get("flag").kind != "true" {
		t.Fatalf("dict: %+v", v)
	}
}

// Real-world DMGs, when GOMOUNT_DMG_DIR names a directory of them: every
// *.dmg is opened, its chunk types logged, its whole virtual disk hashed
// (compare against an independent reassembly), and its volumes listed.
func TestDMGRealImages(t *testing.T) {
	dir := os.Getenv("GOMOUNT_DMG_DIR")
	if dir == "" {
		t.Skip("set GOMOUNT_DMG_DIR to a directory of .dmg files to run against real images")
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.dmg"))
	for _, p := range paths {
		ra, size, closer, err := OpenImage(p)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(p), err)
			continue
		}
		types := "raw image"
		if d, ok := ra.(*dmgDisk); ok {
			var kinds []string
			for k, n := range d.chunkTypes() {
				kinds = append(kinds, fmt.Sprintf("%s:%d", k, n))
			}
			sort.Strings(kinds)
			types = strings.Join(kinds, " ")
		}
		h := sha256.New()
		_, herr := io.Copy(h, io.NewSectionReader(ra, 0, size))
		var labels []string
		if herr == nil {
			parts, _ := partition.Partitions(ra, size)
			for _, pt := range parts {
				vol := io.NewSectionReader(ra, pt.Offset, pt.Size)
				if f, err := fsx.Open(vol, pt.Size); err == nil {
					labels = append(labels, fmt.Sprintf("%s %q", f.Info().Type, f.Info().Label))
				}
			}
			if len(parts) == 0 {
				if f, err := fsx.Open(ra, size); err == nil {
					labels = append(labels, fmt.Sprintf("%s %q", f.Info().Type, f.Info().Label))
				}
			}
		}
		closer()
		if herr != nil {
			if errors.Is(herr, io.EOF) || !strings.Contains(herr.Error(), "not supported") {
				t.Errorf("%s: %v", filepath.Base(p), herr)
			}
			t.Logf("%s: [%s] %v", filepath.Base(p), types, herr)
			continue
		}
		t.Logf("%s: %d bytes sha256 %x [%s] %s", filepath.Base(p), size, h.Sum(nil), types, strings.Join(labels, ", "))
	}
}
