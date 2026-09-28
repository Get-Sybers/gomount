package apfs

// apfs_test: the record parsers and the checksum over crafted bytes, and —
// when GOMOUNT_APFS_IMAGE names a disk image holding an APFS container at
// GOMOUNT_APFS_OFFSET — the whole stack over real evidence: container,
// volumes, the file-system tree, content and decmpfs. No APFS fixture is
// committed: nothing on a Linux build host can format one, and the real
// container this was written against is evidence.

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/gomount/fsx"
	"github.com/get-sybers/gomount/image"
)

func TestFletcher64RoundTrip(t *testing.T) {
	block := make([]byte, 4096)
	for i := range block {
		block[i] = byte(i * 7)
	}
	binary.LittleEndian.PutUint64(block[0:8], fletcher64(block[8:]))
	if !checksumOK(block) {
		t.Fatal("a block checksummed by fletcher64 must verify")
	}
	block[100] ^= 1
	if checksumOK(block) {
		t.Fatal("a flipped bit must fail the checksum")
	}
	// the same bytes checksum the same way twice: no hidden state
	if fletcher64(block[8:]) != fletcher64(block[8:]) {
		t.Fatal("fletcher64 is not a pure function")
	}
}

func TestParseInodeWithXfields(t *testing.T) {
	le := binary.LittleEndian
	val := make([]byte, inodeFixedSize)
	le.PutUint64(val[0:], 2)    // parent: root
	le.PutUint64(val[8:], 4242) // private id
	le.PutUint64(val[16:], uint64(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()))
	le.PutUint64(val[24:], uint64(time.Date(2026, 1, 10, 22, 14, 2, 0, time.UTC).UnixNano()))
	le.PutUint32(val[56:], 1)
	le.PutUint32(val[68:], ufCompressed)
	le.PutUint32(val[72:], 501)
	le.PutUint32(val[76:], 20)
	le.PutUint16(val[80:], sIFREG|0o644)
	// xfields: a name (12 bytes incl NUL) then a dstream (40 bytes)
	name := []byte("hostname\x00")
	xf := []byte{2, 0, 0, 0}
	xf = append(xf, xfInoName, 0, byte(len(name)), 0)
	xf = append(xf, xfInoDstream, 0, 40, 0)
	xf = append(xf, name...)
	xf = append(xf, make([]byte, (8-len(name)%8)%8)...) // 8-byte alignment
	ds := make([]byte, 40)
	le.PutUint64(ds[0:], 6)
	le.PutUint64(ds[8:], 4096)
	xf = append(xf, ds...)
	val = append(val, xf...)

	in, err := parseInode(77, val)
	if err != nil {
		t.Fatal(err)
	}
	if in.name != "hostname" || in.size != 6 || in.allocSize != 4096 || !in.hasDstream {
		t.Fatalf("xfields: %+v", in)
	}
	if in.parent != 2 || in.privateID != 4242 || in.uid != 501 || in.gid != 20 || in.mode != sIFREG|0o644 || in.nlink != 1 {
		t.Fatalf("fixed fields: %+v", in)
	}
	if !in.mtime.Equal(time.Date(2026, 1, 10, 22, 14, 2, 0, time.UTC)) || !in.btime.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("times: %v %v", in.mtime, in.btime)
	}
	if in.bsdFlags&ufCompressed == 0 {
		t.Fatal("bsd flags lost")
	}
	if _, err := parseInode(1, val[:50]); err == nil {
		t.Fatal("a short inode value must error")
	}
}

func TestParseDrecShapes(t *testing.T) {
	le := binary.LittleEndian
	val := make([]byte, drecFixedSize)
	le.PutUint64(val, 99)
	le.PutUint16(val[16:], 8) // DT_REG
	// hashed: 10-bit length (incl NUL) + hash, then the name
	name := []byte("Users\x00")
	hashed := make([]byte, 4)
	le.PutUint32(hashed, uint32(len(name))|0xabcde<<10)
	hashed = append(hashed, name...)
	d, ok := parseDrec(hashed, val)
	if !ok || d.name != "Users" || d.fileID != 99 || d.typ != 8 {
		t.Fatalf("hashed drec: %+v %v", d, ok)
	}
	// plain: 16-bit length, then the name
	plain := make([]byte, 2)
	le.PutUint16(plain, uint16(len(name)))
	plain = append(plain, name...)
	d, ok = parseDrec(plain, val)
	if !ok || d.name != "Users" {
		t.Fatalf("plain drec: %+v %v", d, ok)
	}
	if _, ok := parseDrec([]byte{9, 0, 0}, val); ok {
		t.Fatal("a key of the wrong shape must be rejected")
	}
}

func TestBTreeNodeLayout(t *testing.T) {
	// a leaf with two fixed 16/16 entries, laid out as APFS does: table of
	// contents after the header, keys growing up, values growing down
	raw := make([]byte, 4096)
	le := binary.LittleEndian
	le.PutUint16(raw[32:], btNodeLeaf|btNodeFixedKVSize)
	le.PutUint32(raw[36:], 2)
	le.PutUint16(raw[40:], 0)  // table offset
	le.PutUint16(raw[42:], 64) // table length
	// entry 0: key at keysBase+0, value 16 bytes before the end
	le.PutUint16(raw[56:], 0)
	le.PutUint16(raw[58:], 16)
	le.PutUint16(raw[60:], 16)
	le.PutUint16(raw[62:], 32)
	keysBase := 56 + 64
	le.PutUint64(raw[keysBase:], 10)
	le.PutUint64(raw[keysBase+16:], 20)
	le.PutUint64(raw[4096-16+8:], 1000) // value 0 paddr
	le.PutUint64(raw[4096-32+8:], 2000) // value 1 paddr
	n, err := parseNode(raw)
	if err != nil {
		t.Fatal(err)
	}
	tr := &tree{keySize: 16, valSize: 16}
	k, v, err := tr.entry(n, 0)
	if err != nil || le.Uint64(k) != 10 || le.Uint64(v[8:]) != 1000 {
		t.Fatalf("entry 0: %x %x %v", k, v, err)
	}
	k, v, err = tr.entry(n, 1)
	if err != nil || le.Uint64(k) != 20 || le.Uint64(v[8:]) != 2000 {
		t.Fatalf("entry 1: %x %x %v", k, v, err)
	}
	if _, _, err := tr.entry(n, 2); err == nil {
		t.Fatal("entry past nkeys must error")
	}
}

// ---- the real container ----------------------------------------------------------

func openEvidence(t *testing.T) (*Container, func()) {
	t.Helper()
	img := os.Getenv("GOMOUNT_APFS_IMAGE")
	if img == "" {
		t.Skip("set GOMOUNT_APFS_IMAGE (and GOMOUNT_APFS_OFFSET) to run against a real container")
	}
	off, _ := strconv.ParseInt(os.Getenv("GOMOUNT_APFS_OFFSET"), 10, 64)
	ra, size, closer, err := image.OpenImage(img)
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenContainer(io.NewSectionReader(ra, off, size-off), size-off)
	if err != nil {
		closer()
		t.Fatal(err)
	}
	return c, func() { closer() }
}

func TestEvidenceContainer(t *testing.T) {
	c, done := openEvidence(t)
	defer done()
	vols := c.Volumes()
	if len(vols) == 0 {
		t.Fatal("no volumes")
	}
	var data, system *VolumeInfo
	for i := range vols {
		v := vols[i]
		t.Logf("volume %d %q role=%s uuid=%s files=%d dirs=%d encrypted=%v sealed=%v ci=%v",
			v.Index, v.Name, v.RoleName, v.UUID, v.Files, v.Dirs, v.Encrypted, v.Sealed, v.CaseInsensitive)
		switch v.Role {
		case roleData:
			data = &vols[i]
		case roleSystem:
			system = &vols[i]
		}
	}
	if data == nil {
		t.Fatal("no Data volume")
	}
	vol, err := c.OpenVolume(data.Index)
	if err != nil {
		t.Fatal(err)
	}
	root, err := vol.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(root))
	for _, e := range root {
		names = append(names, e.Name)
	}
	t.Logf("Data root: %s", strings.Join(names, " "))
	if len(root) == 0 {
		t.Fatal("empty Data root")
	}
	// a file every Data volume has, its content through the extents
	for _, p := range []string{"/private/etc/hosts", "/private/var/log/install.log", "/Users"} {
		e, err := vol.Stat(p)
		if err != nil {
			t.Logf("%s: %v", p, err)
			continue
		}
		t.Logf("%s: dir=%v size=%d mode=%o uid=%d mtime=%s btime=%s", p, e.IsDir, e.Size, e.Mode&0xfff, e.UID, e.Mtime.Format(time.RFC3339), e.Btime.Format(time.RFC3339))
		if !e.IsDir {
			r, err := vol.Open(p)
			if err != nil {
				t.Errorf("open %s: %v", p, err)
				continue
			}
			b, err := io.ReadAll(io.LimitReader(r, 512))
			r.Close()
			if err != nil {
				t.Errorf("read %s: %v", p, err)
				continue
			}
			t.Logf("%s head: %q", p, strings.SplitN(string(b), "\n", 3)[0])
		}
	}
	// the System volume: sealed, most files decmpfs-compressed
	if system != nil {
		sv, err := c.OpenVolume(system.Index)
		if err != nil {
			t.Fatal(err)
		}
		p := "/System/Library/CoreServices/SystemVersion.plist"
		r, err := sv.Open(p)
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if !bytes.Contains(b, []byte("ProductVersion")) {
			t.Fatalf("%s does not read as the version plist: %q", p, b[:min(len(b), 200)])
		}
		t.Logf("%s: %d bytes, contains ProductVersion", p, len(b))
	}
	// a bounded walk of the Data volume: every entry a real fsx.Entry
	count, compressed := 0, 0
	err = vol.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		count++
		if open != nil && count%997 == 0 { // spot-read a sample of files
			r, err := open()
			if err != nil {
				return nil
			}
			io.CopyN(io.Discard, r, 4096)
			r.Close()
			compressed++
		}
		if count >= 20000 {
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("walked %d entries, spot-read %d files", count, compressed)
}
