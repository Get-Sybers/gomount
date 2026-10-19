package ntfsvol

import (
	"bytes"
	"testing"
)

// TestReadSerial pins the NTFS $Boot volume-serial read (offset +0x48, 8
// bytes) and its hex encoding against a crafted boot sector — no mkntfs, so
// it runs anywhere.
func TestReadSerial(t *testing.T) {
	b := make([]byte, 512)
	copy(b[3:11], []byte("NTFS    ")) // OEM id
	copy(b[72:80], []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04})
	b[510], b[511] = 0x55, 0xAA
	if got := ReadSerial(bytes.NewReader(b), 0); got != "deadbeef01020304" {
		t.Errorf("ReadSerial = %q, want deadbeef01020304", got)
	}

	// a non-NTFS sector yields an honest null, not a bogus serial
	if got := ReadSerial(bytes.NewReader(make([]byte, 512)), 0); got != "" {
		t.Errorf("non-NTFS ReadSerial = %q, want empty", got)
	}
}
