package vfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// pattern fills a buffer with a deterministic, position-dependent byte pattern
// so a mis-offset read is detectable.
func pattern(n int64) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7 + 3) & 0xff)
	}
	return b
}

// bytesReaderAt adapts a []byte to io.ReaderAt for the pure in-memory case.
type bytesReaderAt struct{ b []byte }

func (r bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestNodeSemantics exercises the node behaviours without a live mount, so it
// runs anywhere (no /dev/fuse, no user namespace).
func TestNodeSemantics(t *testing.T) {
	const size = 4096
	data := pattern(size)
	f := &volFile{ra: bytesReaderAt{data}, size: size}

	var attr fuse.AttrOut
	if e := f.Getattr(t.Context(), nil, &attr); e != 0 {
		t.Fatalf("Getattr errno %v", e)
	}
	if attr.Size != size {
		t.Fatalf("Getattr size = %d, want %d", attr.Size, size)
	}
	if attr.Mode != fuse.S_IFREG|0o400 {
		t.Fatalf("Getattr mode = %#o, want %#o", attr.Mode, fuse.S_IFREG|0o400)
	}

	if _, _, e := f.Open(t.Context(), uint32(syscall.O_WRONLY)); e != syscall.EROFS {
		t.Fatalf("Open O_WRONLY errno = %v, want EROFS", e)
	}
	_, flags, e := f.Open(t.Context(), uint32(syscall.O_RDONLY))
	if e != 0 {
		t.Fatalf("Open O_RDONLY errno %v", e)
	}
	if flags&fuse.FOPEN_DIRECT_IO == 0 {
		t.Fatalf("Open did not set FOPEN_DIRECT_IO (flags %#x)", flags)
	}

	// Full read.
	dst := make([]byte, size)
	res, e := f.Read(t.Context(), nil, dst, 0)
	if e != 0 {
		t.Fatalf("Read errno %v", e)
	}
	got, _ := res.Bytes(dst)
	if !bytes.Equal(got, data) {
		t.Fatal("full read mismatch")
	}

	// Tail read clamps to volume length.
	tail := make([]byte, 512)
	res, e = f.Read(t.Context(), nil, tail, size-100)
	if e != 0 {
		t.Fatalf("tail Read errno %v", e)
	}
	got, _ = res.Bytes(tail)
	if len(got) != 100 {
		t.Fatalf("tail read len = %d, want 100", len(got))
	}
	if !bytes.Equal(got, data[size-100:]) {
		t.Fatal("tail read mismatch")
	}

	// Read past end is empty, not an error.
	res, e = f.Read(t.Context(), nil, tail, size)
	if e != 0 {
		t.Fatalf("past-end Read errno %v", e)
	}
	if got, _ = res.Bytes(tail); len(got) != 0 {
		t.Fatalf("past-end read len = %d, want 0", len(got))
	}

	// Writes and truncation are refused.
	if _, e := f.Write(t.Context(), nil, []byte("x"), 0); e != syscall.EROFS {
		t.Fatalf("Write errno = %v, want EROFS", e)
	}
	var sin fuse.SetAttrIn
	sin.Valid = fuse.FATTR_SIZE
	sin.Size = 0
	if e := f.Setattr(t.Context(), nil, &sin, &attr); e != syscall.EROFS {
		t.Fatalf("Setattr truncate errno = %v, want EROFS", e)
	}
}

// TestLiveMountRoundTrip mounts over a 1 MiB backing file and reads it back
// through the kernel. It needs /dev/fuse plus either the privilege to mount(2)
// directly or the fusermount helper binary; without them the mount fails and the
// test skips.
func TestLiveMountRoundTrip(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}

	const size = 1 << 20
	data := pattern(size)
	backing := filepath.Join(t.TempDir(), "backing.bin")
	if err := os.WriteFile(backing, data, 0o600); err != nil {
		t.Fatal(err)
	}
	bf, err := os.Open(backing)
	if err != nil {
		t.Fatal(err)
	}
	defer bf.Close()

	mnt := t.TempDir()
	srv, err := Mount(mnt, bf, size)
	if err != nil {
		// EPERM/EACCES/ENODEV: no privilege or /dev/fuse for a direct mount(2).
		// os.ErrNotExist: the fusermount fallback helper is not installed
		// (exec.LookPath on the helper wraps fs.ErrNotExist). Either way FUSE is
		// unusable here, so skip rather than fail.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
			errors.Is(err, syscall.ENODEV) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("cannot mount FUSE in this environment: %v", err)
		}
		t.Fatalf("Mount: %v", err)
	}
	t.Logf("mounted (DirectMount=%v)", srv.DirectMount)
	defer func() {
		if err := srv.Unmount(); err != nil {
			t.Errorf("Unmount: %v", err)
		}
	}()

	// Metadata is the exact size.
	st, err := os.Stat(filepath.Join(mnt, VolumeName))
	if err != nil {
		t.Fatalf("stat volume.img: %v", err)
	}
	if st.Size() != size {
		t.Fatalf("volume.img size = %d, want %d", st.Size(), size)
	}

	// Every byte round-trips through the kernel.
	got, err := os.ReadFile(filepath.Join(mnt, VolumeName))
	if err != nil {
		t.Fatalf("read volume.img: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mounted bytes differ from backing (len got=%d want=%d)", len(got), size)
	}

	// The mount is read-only.
	if err := os.WriteFile(filepath.Join(mnt, VolumeName), []byte("x"), 0o600); err == nil {
		t.Fatal("write to read-only volume.img unexpectedly succeeded")
	}
}
