// Package vfile presents a single in-memory-backed regular file over FUSE.
//
// It exposes exactly one file, "volume.img", whose bytes come from an
// io.ReaderAt of a fixed size. The file is read-only: opens for write, writes
// and size changes all fail with EROFS. A separate ntfs-3g process mounts this
// regular file read-only; because the backing object is a plain file and not a
// block/loop device, the kernel mount type is "fuse" (FS_USERNS_MOUNT), which
// mounts unprivileged inside a user namespace with no CAP_SYS_ADMIN.
//
// The reported size is the exact byte length of the volume. ntfs-3g derives the
// device length from fstat/lseek, so Getattr returning the true size is the one
// correctness constraint that makes the downstream mount see the whole volume.
//
// The provider uses the go-fuse fs package. Reads pass straight through to the
// io.ReaderAt with bounds clamped to the volume length; opens set
// FOPEN_DIRECT_IO so the kernel forwards every read to Read rather than serving
// a cached page for a file whose size the kernel learns only from Getattr.
package vfile

import (
	"context"
	"io"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// VolumeName is the single regular file this provider exposes.
const VolumeName = "volume.img"

// volFile is the "volume.img" node: a read-only regular file backed by an
// io.ReaderAt of a fixed size.
type volFile struct {
	fs.Inode
	ra   io.ReaderAt
	size int64
}

// Compile-time proof volFile implements the node behaviours this provider needs.
var (
	_ fs.NodeGetattrer = (*volFile)(nil)
	_ fs.NodeOpener    = (*volFile)(nil)
	_ fs.NodeReader    = (*volFile)(nil)
	_ fs.NodeWriter    = (*volFile)(nil)
	_ fs.NodeSetattrer = (*volFile)(nil)
)

// Getattr reports the node as a read-only regular file whose size is the exact
// volume byte length. ntfs-3g sizes the device from this value.
func (f *volFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFREG | 0o400
	out.Size = uint64(f.size)
	out.Nlink = 1
	out.Blksize = 4096
	out.Blocks = (uint64(f.size) + 511) / 512
	return fs.OK
}

// Open refuses write access and returns FOPEN_DIRECT_IO so every read reaches
// Read. The nil handle is valid: Read serves from the node's io.ReaderAt.
func (f *volFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	switch flags & uint32(syscall.O_ACCMODE) {
	case syscall.O_WRONLY, syscall.O_RDWR:
		return nil, 0, syscall.EROFS
	}
	return nil, fuse.FOPEN_DIRECT_IO, fs.OK
}

// Read copies from the backing io.ReaderAt into dest, clamped to the volume
// length. A short count at end-of-volume returns the partial slice; io.EOF is
// not an error to the kernel.
func (f *volFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 {
		return nil, syscall.EINVAL
	}
	if off >= f.size {
		return fuse.ReadResultData(dest[:0]), fs.OK
	}
	want := int64(len(dest))
	if off+want > f.size {
		want = f.size - off
	}
	n, err := f.ra.ReadAt(dest[:want], off)
	if err != nil && err != io.EOF {
		return nil, fs.ToErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), fs.OK
}

// Write refuses all writes: the volume is read-only.
func (f *volFile) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	return 0, syscall.EROFS
}

// Setattr refuses truncation or any other size change with EROFS, and reports
// the current attributes for metadata-only calls. ntfs-3g mounted read-only
// never truncates; this refusal keeps the volume length authoritative.
func (f *volFile) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if _, ok := in.GetSize(); ok {
		return syscall.EROFS
	}
	return f.Getattr(ctx, fh, out)
}

// volRoot is the mount root directory. Its only child is "volume.img".
type volRoot struct {
	fs.Inode
	child *volFile
}

var _ fs.NodeOnAdder = (*volRoot)(nil)

// OnAdd attaches the single "volume.img" node when the tree is mounted.
func (r *volRoot) OnAdd(ctx context.Context) {
	ch := r.NewPersistentInode(ctx, r.child, fs.StableAttr{Mode: fuse.S_IFREG})
	r.AddChild(VolumeName, ch, false)
}

// Server is the mount handle: a live FUSE mount serving one read-only file.
type Server struct {
	srv         *fuse.Server
	DirectMount bool // true when mounted via mount(2); false when fusermount3 was used
}

// Mount serves a read-only "volume.img" of the given size, backed by ra, at
// mountDir. It first forces a setuid-free mount(2) (DirectMountStrict) and, if
// the kernel or environment refuses it, falls back to the fusermount3 helper.
// Strict on the first attempt is deliberate: with DirectMount alone go-fuse
// silently falls back to fusermount3 internally, so Server.DirectMount could
// not then report which mechanism actually mounted. The returned Server is
// already serving; call Wait to block until unmount, or Unmount to tear it
// down.
func Mount(mountDir string, ra io.ReaderAt, size int64) (*Server, error) {
	opts := func(direct bool) *fs.Options {
		return &fs.Options{
			MountOptions: fuse.MountOptions{
				MaxWrite:          1 << 20,
				DisableXAttrs:     true,
				FsName:            "gomount",
				Name:              "gomount",
				DirectMount:       direct,
				DirectMountStrict: direct,
			},
		}
	}
	newRoot := func() *volRoot {
		return &volRoot{child: &volFile{ra: ra, size: size}}
	}

	srv, err := fs.Mount(mountDir, newRoot(), opts(true))
	if err == nil {
		return &Server{srv: srv, DirectMount: true}, nil
	}
	srv, ferr := fs.Mount(mountDir, newRoot(), opts(false))
	if ferr != nil {
		return nil, ferr
	}
	return &Server{srv: srv, DirectMount: false}, nil
}

// Wait blocks until the mount is torn down (by Unmount or an external umount).
func (s *Server) Wait() { s.srv.Wait() }

// Unmount removes the mount.
func (s *Server) Unmount() error { return s.srv.Unmount() }
