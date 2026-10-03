// Package fsx is the filesystem seam of the Linux side (docs/linux §5.1):
// one read-only contract every backend satisfies over a bounded volume
// io.ReaderAt, so the verbs (ls, cat, stat, tree, stream, materialise,
// timeline) speak one language whatever the on-disk format. NTFS keeps its
// existing ntfsfs backend behind the same CLI contract; ext2/3/4, XFS and
// vfat implement fsx directly.
//
// The design rules, per the plan:
//   - expose every timestamp the filesystem actually has (crtime included)
//     and nothing it does not — a zero time is an honest null;
//   - owner, mode, inode, nlink and the unfollowed link target ride every
//     entry;
//   - allocation state is first-class (residue rows are the Allocated=false
//     ones), and the residue enumeration seam (§5.5) is part of the
//     contract from the first backend, not bolted on;
//   - a malformed filesystem is a Go error, never a panic or a kernel
//     fault: every offset is bounds-checked against the volume.
package fsx

import (
	"fmt"
	"io"
	"time"
)

// Entry is one filesystem object as a backend exposes it. Fields a
// filesystem does not have stay zero (vfat has no uid; only ext4 crtime
// and XFS v5 carry Btime): honest nulls, never fabricated.
type Entry struct {
	Name       string // leaf name
	Path       string // full "/"-separated volume path
	IsDir      bool
	Mode       uint32 // POSIX mode bits incl. type (0 where the FS has none)
	UID        uint32
	GID        uint32
	Inode      uint64 // inode / cluster identity, backend-native
	Nlink      uint32
	Size       int64
	LinkTarget string // symlink target, verbatim and unfollowed
	Allocated  bool   // false only on residue rows

	Btime time.Time // born / created (crtime)
	Mtime time.Time // content modified
	Atime time.Time // accessed
	Ctime time.Time // metadata changed
}

// Info is the volume-level identity a backend reads from its superblock:
// the durable names fstab/crypttab rows use (Origin.FSUUID / Origin.Label,
// the drive-serial role of rule 2).
type Info struct {
	Type      string // "ext4", "ext2", "xfs", "vfat", "ntfs", "apfs", "hfsplus"
	UUID      string // filesystem UUID (vfat: the 32-bit serial, xxxx-xxxx)
	Label     string
	BlockSize int64
}

// FS is the read-only contract the verbs consume.
type FS interface {
	Info() Info
	ReadDir(dir string) ([]Entry, error)
	Stat(path string) (Entry, error)
	Open(path string) (io.ReadCloser, error)
	// Walk streams every entry (files, dirs and symlinks) depth-first with
	// a lazy opener for regular files (nil for the rest). A callback error
	// stops the walk.
	Walk(fn func(e Entry, open func() (io.ReadCloser, error)) error) error
}

// Residue is one recovered item of §5.5: what the filesystem's own
// metadata still proves about something no longer (fully) live. Content is
// present only where it is still addressable.
type Residue struct {
	Kind   string // lost_found | orphan_inode | deleted_dirent
	Detail string // human trace: where/how it was recovered
	Entry  Entry  // whatever metadata survives; Allocated=false unless live (lost+found)
	ID     string // stable id within the volume (inode or dirent position)
}

// Residuer is the optional residue seam. A backend without recovery
// support simply does not implement it.
type Residuer interface {
	Residues(fn func(r Residue, open func() (io.ReadCloser, error)) error) error
}

// Detector probes a bounded volume reader and opens it when recognised.
type Detector struct {
	Type  string
	Probe func(ra io.ReaderAt, size int64) bool
	Open  func(ra io.ReaderAt, size int64) (FS, error)
}

// detectors is the probe order. Registered by each backend's init via
// Register; ext4 before vfat since an ext filesystem formatted over old
// FAT media can leave a stale BPB in block 0 while 0xEF53 is unambiguous.
var detectors []Detector

// Register adds a backend to the probe chain (called from backend inits).
func Register(d Detector) { detectors = append(detectors, d) }

// Probe names the filesystem on the volume, or "" when nothing matches.
func Probe(ra io.ReaderAt, size int64) string {
	for _, d := range detectors {
		if d.Probe(ra, size) {
			return d.Type
		}
	}
	return ""
}

// Open probes and opens the volume with the matching backend.
func Open(ra io.ReaderAt, size int64) (FS, error) {
	for _, d := range detectors {
		if d.Probe(ra, size) {
			return d.Open(ra, size)
		}
	}
	return nil, fmt.Errorf("no known filesystem on volume (%d bytes)", size)
}

// ReadFull is the bounds-checked read every backend uses: n bytes at off,
// erroring (never panicking) on a short or out-of-range read.
func ReadFull(ra io.ReaderAt, off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 {
		return nil, fmt.Errorf("read %d bytes at %#x: out of range", n, off)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(io.NewSectionReader(ra, off, int64(n)), b); err != nil {
		return nil, fmt.Errorf("read %d bytes at %#x: %w", n, off, err)
	}
	return b, nil
}
