package image

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sybers/gomount/image/imagetest"
)

// TestSparseImageApple: a .sparseimage hdiutil wrote — dfvfs's
// hfsplus.sparseimage test file (Apache-2.0, THIRD_PARTY_NOTICES.md), whose
// four 1 MiB bands are stored out of disk order (1, 4, 2, 3) — hashes to
// the disk an independent reassembly from the documented band formula
// gives, and the stack reads the HFS+ volume inside.
func TestSparseImageApple(t *testing.T) {
	src, err := os.Open("testdata/hfsplus.sparseimage.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	zr, err := gzip.NewReader(src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "hfsplus.sparseimage")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if f := Format(p); f != "sparseimage" {
		t.Fatalf("Format: %q", f)
	}
	ra, size, closer, err := OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(ra, 0, size)); err != nil {
		t.Fatal(err)
	}
	closer()
	if got := hex.EncodeToString(h.Sum(nil)); size != 4194304 || got != "f4e9c2c3771b3d663faffbc1a6f7bf3e001e0f1fa1a1bb4d65624ada6ddfc3b3" {
		t.Fatalf("virtual disk: %d bytes sha256 %s", size, got)
	}
	f := openStack(t, p, "Apple HFS+", "hfsplus")
	if info := f.Info(); info.Label != "hfsplus_test" {
		t.Fatalf("info: %+v", info)
	}
	if got := readFile(t, f, "/passwords.txt"); !bytes.HasPrefix(got, []byte("place,user,password\n")) {
		t.Fatalf("passwords.txt: %q", got)
	}
}

func TestSparseImageSynthetic(t *testing.T) {
	raw := dmgRawDisk(8*7 + 3) // 7 full 8-sector bands and a short one
	want := append([]byte(nil), raw...)
	clear(want[1*8*512 : 2*8*512]) // band 1 (text) never written
	p := filepath.Join(t.TempDir(), "s.sparseimage")
	if err := imagetest.WriteSparseImage(p, raw, 8, []int{7, 3, 0, 5, 2, 6, 4}); err != nil {
		t.Fatal(err)
	}
	readAll(t, p, want)

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"band past table": func(b []byte) []byte { binary.BigEndian.PutUint32(b[64:], 99); return b },
		"band twice":      func(b []byte) []byte { binary.BigEndian.PutUint32(b[68:], 8); return b },
		"zero band size":  func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 0); return b },
		"zero sectors":    func(b []byte) []byte { binary.BigEndian.PutUint32(b[16:], 0); return b },
		"file truncated":  func(b []byte) []byte { return b[:4096+5*8*512] },
		"header only":     func(b []byte) []byte { return b[:100] },
	} {
		m := mutate(append([]byte(nil), b...))
		if _, err := parseSparseImage(bytes.NewReader(m), int64(len(m))); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestSparseBundle(t *testing.T) {
	raw := dmgRawDisk(8*20 + 5)                   // 21 bands of 4 KiB: names 0..14 in hex, the last short
	dir := filepath.Join(t.TempDir(), "evidence") // content decides, not a .sparsebundle name
	if err := imagetest.WriteSparseBundle(dir, raw, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bands", "b")); err != nil {
		t.Fatalf("hex band names: %v", err)
	}
	if f := Format(dir); f != "sparsebundle" {
		t.Fatalf("Format: %q", f)
	}
	readAll(t, dir, raw)

	// a directory that only looks like one is not a disk image
	fake := filepath.Join(t.TempDir(), "fake.sparsebundle")
	os.MkdirAll(filepath.Join(fake, "bands"), 0o755)
	os.WriteFile(filepath.Join(fake, "Info.plist"), []byte(`<plist><dict><key>diskimage-bundle-type</key><string>com.example.other</string></dict></plist>`), 0o644)
	if f := Format(fake); f != "" {
		t.Fatalf("Format(fake bundle): %q", f)
	}
	if _, _, _, err := OpenImage(fake); err == nil {
		t.Fatal("a non-bundle directory must not open")
	}
	// an encrypted bundle is refused, not read as ciphertext
	os.WriteFile(filepath.Join(dir, "token"), append([]byte("encrcdsa"), make([]byte, 64)...), 0o644)
	if _, _, _, err := OpenImage(dir); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("encrypted bundle: %v", err)
	}
	// implausible geometry
	os.WriteFile(filepath.Join(dir, "token"), nil, 0o644)
	pl, _ := os.ReadFile(filepath.Join(dir, "Info.plist"))
	os.WriteFile(filepath.Join(dir, "Info.plist"), bytes.Replace(pl, []byte("<integer>4096</integer>"), []byte("<integer>0</integer>"), 1), 0o644)
	if _, _, _, err := OpenImage(dir); err == nil {
		t.Fatal("band-size 0 must be refused")
	}
}

func TestEncryptedDMGRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret.dmg")
	os.WriteFile(p, append([]byte("encrcdsa\x00\x00\x00\x02"), make([]byte, 8192)...), 0o644)
	if f := Format(p); f != "encrypted-dmg" {
		t.Fatalf("Format: %q", f)
	}
	if _, _, _, err := OpenImage(p); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("OpenImage: %v", err)
	}
}

// Readers in parallel over a DMG whose cache holds three chunks and a
// bundle with more bands than open files: every read returns the right
// bytes while chunks are decoded, cached and evicted, and band files
// opened and closed, under each other (run under -race in CI or docker).
func TestConcurrentReads(t *testing.T) {
	raw := dmgRawDisk(256)
	dir := t.TempDir()
	dmg := filepath.Join(dir, "c.dmg")
	if err := imagetest.WriteDMG(dmg, raw, imagetest.DMGOptions{ChunkSectors: 4, Encode: mixedEncoder}); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "c.sparsebundle")
	if err := imagetest.WriteSparseBundle(bundle, raw, 1024); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dmg, bundle} {
		ra, _, closer, err := OpenImage(p)
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := ra.(*dmgDisk); ok {
			d.cacheBudget = 3 * 2048
		}
		errs := make(chan error, 8)
		for g := 0; g < 8; g++ {
			go func(seed int64) {
				r := rand.New(rand.NewSource(seed))
				buf := make([]byte, 5000)
				for i := 0; i < 300; i++ {
					off := r.Int63n(int64(len(raw)))
					n, err := ra.ReadAt(buf[:1+r.Intn(len(buf))], off)
					if err != nil && err != io.EOF {
						errs <- err
						return
					}
					if !bytes.Equal(buf[:n], raw[off:off+int64(n)]) {
						errs <- fmt.Errorf("%s: ReadAt(%d) bytes differ", filepath.Base(p), off)
						return
					}
				}
				errs <- nil
			}(int64(g))
		}
		for g := 0; g < 8; g++ {
			if err := <-errs; err != nil {
				t.Error(err)
			}
		}
		closer()
	}
}
