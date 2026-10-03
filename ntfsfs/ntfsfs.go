// Package ntfsfs reads one NTFS volume entirely in-process with Velociraptor's
// go-ntfs (Apache-2.0, the same parser the sibling GoDFIR tools use) and exposes
// a small read-only filesystem API — ReadDir, Stat, Open/OpenStream and Walk —
// that gomount's userspace verbs (ls, cat, stat, tree, browse, stream) consume
// through the ntfsbind adapter.
//
// This is gomount's USERSPACE backend: pure user-space NTFS parsing with no
// mount, no FUSE, no kernel driver, no loop device and no privilege. A parser
// bug is a Go panic in this process, never host code execution, so it is the
// maximum-security path and the only one that runs end-to-end in an unprivileged
// LXC with no /dev/fuse. It consumes exactly what the rest of gomount already
// produces: the NTFS volume as an io.ReaderAt plus the partition's byte offset
// (image.OpenImage -> partition.SelectNTFSVolume -> ntfsvol.VolumeReader).
//
// Everything is read-only: the API never writes, and the volume ReaderAt is
// opened O_RDONLY upstream. Paths are POSIX-style with "/" separators; a Windows
// "\\" is accepted on input. A named alternate data stream is listed in an
// entry's Streams field and read with the NTFS ADS syntax "path:stream" (Open)
// or an explicit stream (OpenStream). Timestamps are the $STANDARD_INFORMATION
// MACB times in UTC.
package ntfsfs

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

const (
	// rootMFT is the fixed record number of the NTFS root directory (".").
	rootMFT = 5

	// pageSize / cachePages configure the PagedReader wrapped around the volume
	// so random MFT and cluster reads (expensive over an E01's zlib chunks) are
	// cached. 4 KiB pages, ~16 MiB of cache.
	pageSize   = 0x1000
	cachePages = 4096

	// maxDirDepth bounds full-path resolution and the Walk recursion so a
	// corrupt or maliciously cyclic directory tree cannot loop forever. It is
	// deeper than go-ntfs's own default to avoid truncating legitimate paths.
	maxDirDepth = 128
)

// FS is a read-only view of one NTFS volume. It is safe for sequential use by a
// single operator or tool; go-ntfs's caches are internally locked.
type FS struct {
	ctx *ntfs.NTFSContext
}

// Entry describes one NTFS filesystem object (a file, a directory, or the
// volume root). It is what ReadDir, Stat and Walk return.
type Entry struct {
	Name    string   // leaf name, long (Win32/POSIX) name preferred over the 8.3 short name
	Path    string   // full path from the volume root, "/"-separated (e.g. "/Users/test/f.txt")
	IsDir   bool     // a directory (has an $INDEX_ROOT / $I30)
	Size    int64    // logical byte length of the default unnamed $DATA stream (0 for a directory)
	MFTID   int64    // MFT record number of this entry
	Deleted bool     // the MFT entry is not ALLOCATED (unlinked/deleted)
	Streams []string // names of the named alternate data streams ($DATA:name), if any

	Btime time.Time // $STANDARD_INFORMATION creation (birth) time, UTC
	Mtime time.Time // $STANDARD_INFORMATION file-altered (modified) time, UTC
	Ctime time.Time // $STANDARD_INFORMATION MFT-altered (metadata-changed) time, UTC
	Atime time.Time // $STANDARD_INFORMATION file-accessed time, UTC
}

// Open builds an in-process NTFS filesystem over the volume in r whose boot
// sector begins at offset. r is any read-only random-access view of the media;
// offset is the volume's byte offset within it (0 when r is already bounded to
// the volume, as ntfsvol.VolumeReader returns it). The reader is wrapped in a
// cached PagedReader and handed to go-ntfs, which bootstraps the $MFT from the
// boot sector.
//
// It fails if the bytes at offset are not a valid NTFS boot sector.
func Open(r io.ReaderAt, offset int64) (*FS, error) {
	if r == nil {
		return nil, errors.New("ntfsfs: nil reader")
	}
	if offset < 0 {
		return nil, fmt.Errorf("ntfsfs: negative volume offset %d", offset)
	}

	// Present the volume to go-ntfs at offset 0: NTFS cluster addresses are
	// relative to the volume start, and go-ntfs reads clusters from the disk
	// reader without re-adding the boot-sector offset, so a non-zero offset must
	// be folded into the reader itself.
	base := r
	if offset != 0 {
		base = io.NewSectionReader(r, offset, math.MaxInt64-offset)
	}

	paged, err := ntfs.NewPagedReader(base, pageSize, cachePages)
	if err != nil {
		return nil, fmt.Errorf("ntfsfs: page cache: %w", err)
	}

	ctx, err := ntfs.GetNTFSContext(paged, 0)
	if err != nil {
		return nil, fmt.Errorf("ntfsfs: open NTFS volume: %w", err)
	}

	// Prefer long names and allow deep trees when reconstructing full paths.
	opts := ntfs.GetDefaultOptions()
	opts.IncludeShortNames = false
	opts.MaxDirectoryDepth = maxDirDepth
	ctx.SetOptions(opts)

	return &FS{ctx: ctx}, nil
}

// Close releases the parser's caches. The FS is unusable afterwards.
func (fs *FS) Close() {
	if fs != nil && fs.ctx != nil {
		fs.ctx.Close()
	}
}

// ReadDir lists the immediate children of the directory at path. The root is
// named "", "/" or ".". Each child is returned once (the $I30 index carries a
// separate record per name, e.g. the 8.3 short name, which are de-duplicated by
// MFT id here). Entries are sorted by name.
func (fs *FS) ReadDir(path string) ([]Entry, error) {
	dir, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	if !dir.Flags().IsSet("DIRECTORY") {
		return nil, fmt.Errorf("ntfsfs: %q is not a directory", path)
	}

	parent := cleanPath(path)
	seen := make(map[int64]bool)
	var out []Entry

	for _, rec := range dir.Dir(fs.ctx) {
		id := int64(rec.MftReference())
		// Skip the directory's reference to itself and any duplicate name records.
		if id == int64(dir.Record_number()) || seen[id] {
			continue
		}
		seen[id] = true

		child, err := fs.ctx.GetMFT(id)
		if err != nil {
			continue // an unreadable child does not abort the listing
		}
		e := fs.entry(child)
		e.Path = joinPath(parent, e.Name)
		out = append(out, e)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Stat returns the entry at path. An ADS suffix ("path:stream") is ignored; the
// entry describes the underlying file, and its Streams field lists the named
// streams. The full canonical path is resolved from the MFT.
func (fs *FS) Stat(path string) (Entry, error) {
	mft, err := fs.resolve(path)
	if err != nil {
		return Entry{}, err
	}
	e := fs.entry(mft)
	if mft.Record_number() == rootMFT {
		e.Name, e.Path = "/", "/"
		e.IsDir = true
		return e, nil
	}
	e.Path = ntfs.GetFullPath(fs.ctx, mft)
	return e, nil
}

// Open opens the default unnamed $DATA stream of the file at path for reading,
// unless path carries an ADS suffix ("path:stream"), in which case that named
// stream is opened. The returned ReadCloser streams the (resident or
// non-resident) content; Close is a no-op that satisfies io.ReadCloser.
func (fs *FS) Open(path string) (io.ReadCloser, error) {
	return fs.OpenStream(path, adsFromPath(path))
}

// OpenStream opens a named data stream of the file at path. An empty stream name
// selects the default unnamed $DATA. Any ADS suffix on path is ignored in favour
// of the explicit stream argument.
func (fs *FS) OpenStream(path, stream string) (io.ReadCloser, error) {
	mft, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	if stream == "" && mft.Flags().IsSet("DIRECTORY") {
		return nil, fmt.Errorf("ntfsfs: %q is a directory", path)
	}
	return fs.openStream(mft, stream)
}

// Walk streams every regular (non-directory) file in the volume, depth-first
// from the root, to fn. Each call receives the file's Entry (with its full path
// from GetFullPath) and an open closure that opens the file's default $DATA
// stream on demand — so a consumer that only needs metadata never touches the
// content.
//
// Per-entry failures (an unreadable MFT record, a cyclic or too-deep branch) are
// counted and skipped so a single bad record cannot abort a whole-volume walk.
// If fn returns an error the walk stops and returns it. Otherwise the walk runs
// to completion and returns nil on a clean pass, or a *WalkErrors reporting how
// many entries were skipped.
func (fs *FS) Walk(fn func(e Entry, open func() (io.ReadCloser, error)) error) error {
	root, err := fs.ctx.GetMFT(rootMFT)
	if err != nil {
		return fmt.Errorf("ntfsfs: read root directory: %w", err)
	}
	w := &walker{fs: fs, fn: fn, seen: map[int64]bool{rootMFT: true}}
	if err := w.descend(root, 0); err != nil {
		return err // an error returned by fn
	}
	if w.errCount > 0 {
		return &WalkErrors{Count: w.errCount, Sample: w.sample}
	}
	return nil
}

// ---- walk internals ---------------------------------------------------------

// walker carries the state of one Walk: the callback, the set of MFT ids already
// visited (cycle break), and the running count and sample of skipped entries.
type walker struct {
	fs       *FS
	fn       func(e Entry, open func() (io.ReadCloser, error)) error
	seen     map[int64]bool
	errCount int
	sample   []error
}

const maxWalkErrSamples = 16

func (w *walker) note(err error) {
	w.errCount++
	if len(w.sample) < maxWalkErrSamples {
		w.sample = append(w.sample, err)
	}
}

// descend visits every child of dir, emitting files to fn and recursing into
// subdirectories. A returned error is only ever fn's own error (which stops the
// walk); per-entry problems are recorded via note and skipped.
func (w *walker) descend(dir *ntfs.MFT_ENTRY, depth int) error {
	if depth > maxDirDepth {
		w.note(fmt.Errorf("ntfsfs: directory nesting exceeds %d at MFT %d", maxDirDepth, dir.Record_number()))
		return nil
	}

	for _, rec := range dir.Dir(w.fs.ctx) {
		id := int64(rec.MftReference())
		if w.seen[id] {
			continue
		}
		w.seen[id] = true

		child, err := w.fs.ctx.GetMFT(id)
		if err != nil {
			w.note(fmt.Errorf("ntfsfs: MFT %d: %w", id, err))
			continue
		}

		if child.Flags().IsSet("DIRECTORY") {
			if err := w.descend(child, depth+1); err != nil {
				return err
			}
			continue
		}

		e := w.fs.entry(child)
		e.Path = ntfs.GetFullPath(w.fs.ctx, child)

		// Bind the open closure to this specific MFT entry so it is independent
		// of any later path resolution.
		entry := child
		open := func() (io.ReadCloser, error) { return w.fs.openStream(entry, "") }

		if err := w.fn(e, open); err != nil {
			return err
		}
	}
	return nil
}

// WalkErrors reports that a Walk completed but skipped some unreadable entries.
// It is returned by Walk (as an error) only when at least one entry was skipped;
// the walk itself still visited every entry it could read.
type WalkErrors struct {
	Count  int     // number of entries skipped
	Sample []error // up to the first maxWalkErrSamples skip reasons
}

func (e *WalkErrors) Error() string {
	if len(e.Sample) > 0 {
		return fmt.Sprintf("ntfsfs: walk completed, %d entr%s skipped (e.g. %v)",
			e.Count, plural(e.Count), e.Sample[0])
	}
	return fmt.Sprintf("ntfsfs: walk completed, %d entr%s skipped", e.Count, plural(e.Count))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// ---- shared helpers ---------------------------------------------------------

// resolve walks the directory indexes to the MFT entry named by path. "", "/"
// and "." are the volume root. Any ADS suffix is dropped (the underlying file is
// resolved); go-ntfs's MFT_ENTRY.Open handles "\\" and case-insensitive lookup.
func (fs *FS) resolve(path string) (*ntfs.MFT_ENTRY, error) {
	root, err := fs.ctx.GetMFT(rootMFT)
	if err != nil {
		return nil, fmt.Errorf("ntfsfs: read root directory: %w", err)
	}
	clean := cleanPath(path)
	if clean == "" {
		return root, nil
	}
	mft, err := root.Open(fs.ctx, clean)
	if err != nil {
		return nil, fmt.Errorf("ntfsfs: %q: %w", path, err)
	}
	return mft, nil
}

// entry reads one MFT record into an Entry: its preferred name, kind, default
// $DATA size, named streams, deletion state and MACB timestamps. Path is left
// for the caller to fill (joined for ReadDir, GetFullPath for Stat/Walk).
func (fs *FS) entry(mft *ntfs.MFT_ENTRY) Entry {
	flags := mft.Flags()
	e := Entry{
		MFTID:   int64(mft.Record_number()),
		IsDir:   flags.IsSet("DIRECTORY"),
		Deleted: !flags.IsSet("ALLOCATED"),
	}

	var fileNames []*ntfs.FILE_NAME
	seenStream := make(map[string]bool)

	for _, attr := range mft.EnumerateAttributes(fs.ctx) {
		switch attr.Type().Value {
		case ntfs.ATTR_TYPE_STANDARD_INFORMATION:
			si := fs.ctx.Profile.STANDARD_INFORMATION(attr.Data(fs.ctx), 0)
			e.Btime = si.Create_time().Time
			e.Mtime = si.File_altered_time().Time
			e.Ctime = si.Mft_altered_time().Time
			e.Atime = si.File_accessed_time().Time

		case ntfs.ATTR_TYPE_FILE_NAME:
			fileNames = append(fileNames, fs.ctx.Profile.FILE_NAME(attr.Data(fs.ctx), 0))

		case ntfs.ATTR_TYPE_DATA:
			// Only the first fragment of a stream carries its size; later VCN
			// fragments of the same stream repeat the type and are skipped.
			if !attr.IsResident() && attr.Runlist_vcn_start() != 0 {
				continue
			}
			name := attr.Name()
			if name == "" {
				e.Size = attr.DataSize() // the default unnamed $DATA
			} else if !seenStream[name] {
				seenStream[name] = true
				e.Streams = append(e.Streams, name)
			}
		}
	}

	e.Name = displayName(fileNames)
	sort.Strings(e.Streams)
	return e
}

// openStream opens a data stream of mft as a bounded, read-only stream. An empty
// name selects the default unnamed $DATA; a non-empty name selects that ADS.
// Resident and non-resident content is handled by go-ntfs's OpenStream.
func (fs *FS) openStream(mft *ntfs.MFT_ENTRY, name string) (io.ReadCloser, error) {
	reader, err := ntfs.OpenStream(fs.ctx, mft,
		ntfs.ATTR_TYPE_DATA, ntfs.WILDCARD_STREAM_ID, name)
	if err != nil {
		if name == "" {
			return nil, fmt.Errorf("ntfsfs: no $DATA stream: %w", err)
		}
		return nil, fmt.Errorf("ntfsfs: no data stream %q: %w", name, err)
	}
	return &streamReader{ra: reader, size: ntfs.RangeSize(reader)}, nil
}

// streamReader adapts a go-ntfs RangeReaderAt to a sequential io.ReadCloser,
// bounded to the stream's logical length so a read never runs past the file into
// slack. Close is a no-op: the stream holds no OS resource of its own (the
// backing volume reader is owned by the FS).
type streamReader struct {
	ra   io.ReaderAt
	size int64
	pos  int64
}

func (s *streamReader) Read(p []byte) (int, error) {
	if s.pos >= s.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if remain := s.size - s.pos; want > remain {
		want = remain
	}
	n, err := s.ra.ReadAt(p[:want], s.pos)
	s.pos += int64(n)
	if n > 0 {
		return n, nil
	}
	if err == nil || err == io.EOF {
		return 0, io.EOF
	}
	return 0, err
}

func (s *streamReader) Close() error { return nil }

// displayName picks the human name from an MFT entry's $FILE_NAME attributes,
// preferring a long (Win32/POSIX) name over the 8.3 short (DOS) name, matching
// how go-ntfs itself chooses a display name.
func displayName(names []*ntfs.FILE_NAME) string {
	short := ""
	for _, fn := range names {
		switch fn.NameType().Name {
		case "Win32", "DOS+Win32", "POSIX":
			return fn.Name()
		default:
			short = fn.Name()
		}
	}
	return short
}

// cleanPath normalises a path to "/"-separated, ADS-stripped, slash-trimmed
// form. The volume root ("", "/", ".", "\\") becomes "".
func cleanPath(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if i := strings.IndexByte(path, ':'); i >= 0 {
		path = path[:i] // drop any ADS suffix
	}
	path = strings.Trim(path, "/")
	if path == "." {
		return ""
	}
	return path
}

// adsFromPath returns the alternate-data-stream name in a "path:stream" path, or
// "" when there is none. A volume-relative path has no drive letter, so the
// first ':' delimits the stream.
func adsFromPath(path string) string {
	if i := strings.IndexByte(path, ':'); i >= 0 {
		return path[i+1:]
	}
	return ""
}

// joinPath joins a cleaned parent (possibly "") and a leaf into a rooted,
// "/"-separated path.
func joinPath(parent, leaf string) string {
	if parent == "" {
		return "/" + leaf
	}
	return "/" + parent + "/" + leaf
}
