// Package uac reads a UAC collection (github.com/tclahr/uac) — the tar.gz,
// tar or zip archive the collector writes — as gomount volumes. A collection holds two things:
// the host's own files, copied under `[root]/` with their paths intact,
// and the collector's output beside them (uac.log, bodyfile/,
// hash_executables/, live_response/, …). Root exposes the first as a
// read-only fsx.FS whose paths are the host's (`[root]/etc/passwd` reads
// as `/etc/passwd`), so every verb and artefact set that reads a disk
// image's root volume reads a collection unchanged; Meta exposes the
// second the same way.
//
// Detection is by content, never by name: the container's magic (zip,
// gzip, ustar) and then the collection's own layout — `uac.log` among the
// first members (UAC writes it first) or a `[root]/` member. A zip and a
// plain tar read in place through the archive's own index; a gzip'd tar
// is decompressed once into an unlinked spool file under the temp dir
// (TMPDIR), so its members read at random after one pass.
package uac

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

// Kind is the container a collection came in.
type Kind string

// The containers UAC writes (`--output-format tar|zip`; tar is gzip'd when
// the host has gzip, plain otherwise).
const (
	KindZip   Kind = "zip"
	KindTar   Kind = "tar"
	KindTarGz Kind = "tar.gz"
)

// rootDir is the member directory UAC copies the host's files under.
const rootDir = "[root]"

// logName is the collector's run log, the first member of every archive.
const logName = "uac.log"

// detectMembers bounds the layout scan of Detect: UAC writes uac.log first,
// so a collection declares itself within a handful of members.
const detectMembers = 16

// detectBytes bounds the decompressed bytes Detect reads from a gzip'd tar.
const detectBytes = 4 << 20

// Archive is one opened collection.
type Archive struct {
	kind      Kind
	root      *tree
	meta      *tree
	log       Log
	spool     *os.File // the gunzipped tar (tar.gz only)
	spoolName string   // set when the spool could not be unlinked at creation
	truncated error    // the index stopped early: the archive ends mid-member
}

// Log is what the collector's own run log (uac.log) says about the
// collection: the UAC version, the host and the acquisition. Fields the log
// does not carry stay empty.
type Log struct {
	Version      string
	Hostname     string
	OS           string
	Arch         string
	Timezone     string
	MountPoint   string
	OutputFormat string
	Started      time.Time
	Finished     time.Time
	CommandLine  string
}

// Detect reports whether ra holds a UAC collection, and in which container.
func Detect(ra io.ReaderAt, size int64) (Kind, bool) {
	kind, ok := containerKind(ra, size)
	if !ok {
		return "", false
	}
	switch kind {
	case KindZip:
		zr, err := zip.NewReader(io.NewSectionReader(ra, 0, size), size)
		if err != nil {
			return "", false
		}
		for i, f := range zr.File {
			if i >= detectMembers {
				break
			}
			if isCollectionMember(f.Name) {
				return kind, true
			}
		}
		return "", false
	case KindTarGz:
		zr, err := gzip.NewReader(io.NewSectionReader(ra, 0, size))
		if err != nil {
			return "", false
		}
		defer zr.Close()
		return kind, scanTar(io.LimitReader(zr, detectBytes))
	default:
		return kind, scanTar(io.NewSectionReader(ra, 0, min(size, detectBytes)))
	}
}

// containerKind names the archive container by its magic bytes: zip
// (PK\x03\x04), gzip (1f 8b) or a ustar tar (the magic at byte 257).
func containerKind(ra io.ReaderAt, size int64) (Kind, bool) {
	if size < 512 {
		return "", false
	}
	var head [512]byte
	if _, err := ra.ReadAt(head[:], 0); err != nil {
		return "", false
	}
	switch {
	case bytes.Equal(head[:4], []byte{'P', 'K', 3, 4}):
		return KindZip, true
	case head[0] == 0x1f && head[1] == 0x8b:
		return KindTarGz, true
	case string(head[257:262]) == "ustar":
		return KindTar, true
	}
	return "", false
}

// scanTar reads the first members of a tar stream for the collection layout.
func scanTar(r io.Reader) bool {
	tr := tar.NewReader(r)
	for i := 0; i < detectMembers; i++ {
		hdr, err := tr.Next()
		if err != nil {
			return false
		}
		if isCollectionMember(hdr.Name) {
			return true
		}
	}
	return false
}

// isCollectionMember reports whether a member name declares the UAC layout.
func isCollectionMember(name string) bool {
	clean := cleanName(name)
	return clean == logName || clean == rootDir || strings.HasPrefix(clean, rootDir+"/")
}

// cleanName folds an archive member name to a slash path with no leading
// "./" or "/" and no trailing slash. A name that reduces to the root — "",
// "/", "./", "." (the first member of `tar czf x.tgz .`) — is the empty
// string, which the callers skip.
func cleanName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// Open indexes the collection held by ra. It is a Detect followed by one
// pass over the members: the archive is never modified, and a gzip'd tar
// is spooled under the temp dir (TMPDIR). Close releases the spool.
func Open(ra io.ReaderAt, size int64) (*Archive, error) {
	kind, ok := Detect(ra, size)
	if !ok {
		return nil, errors.New("uac: not a UAC collection (no uac.log or [root]/ member in a zip, tar or tar.gz)")
	}
	a := &Archive{kind: kind, root: newTree(), meta: newTree()}
	var err error
	switch kind {
	case KindZip:
		err = a.indexZip(ra, size)
	case KindTar:
		err = a.indexTar(io.NewSectionReader(ra, 0, size), size)
	case KindTarGz:
		err = a.spoolAndIndex(ra, size)
	}
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	a.log = readLog(a.meta)
	return a, nil
}

// Kind is the container the collection came in.
func (a *Archive) Kind() Kind { return a.kind }

// Root is the host's files — the `[root]/` tree — at their own paths.
func (a *Archive) Root() *FS { return &FS{t: a.root, label: "root"} }

// Meta is the collector's own output: uac.log, bodyfile/, live_response/, ….
func (a *Archive) Meta() *FS { return &FS{t: a.meta, label: "meta"} }

// Log is what uac.log says about the collection.
func (a *Archive) Log() Log { return a.log }

// Truncated is non-nil when the archive ended inside a member: an
// interrupted collection, indexed as far as it goes.
func (a *Archive) Truncated() error { return a.truncated }

// Close releases the spool of a gzip'd tar; the archive itself was only read.
func (a *Archive) Close() error {
	if a.spool == nil {
		return nil
	}
	err := a.spool.Close()
	if a.spoolName != "" {
		if rerr := os.Remove(a.spoolName); rerr != nil && err == nil {
			err = rerr
		}
	}
	a.spool = nil
	return err
}

// place files one member into the root or meta tree by its name.
func (a *Archive) place(name string, m *member) {
	clean := cleanName(name)
	if clean == "" {
		return
	}
	if clean == rootDir {
		return // the [root] directory itself is the Root tree's "/"
	}
	if rest, ok := strings.CutPrefix(clean, rootDir+"/"); ok {
		a.root.add(rest, m)
		return
	}
	a.meta.add(clean, m)
}

// ---- tar ----------------------------------------------------------------

// spoolAndIndex decompresses a gzip'd tar once into an unlinked temp file
// and indexes that: the members then read at random through the spool.
func (a *Archive) spoolAndIndex(ra io.ReaderAt, size int64) error {
	zr, err := gzip.NewReader(io.NewSectionReader(ra, 0, size))
	if err != nil {
		return fmt.Errorf("uac: gzip: %w", err)
	}
	defer zr.Close()
	spool, err := spoolTemp()
	if err != nil {
		return fmt.Errorf("uac: spool: %w", err)
	}
	a.spool = spool
	// Unlink at once: the inode lives while the descriptor is open, and
	// nothing is left behind even if the process dies. A platform that
	// refuses removes it on Close instead.
	if rerr := os.Remove(spool.Name()); rerr != nil {
		a.spoolName = spool.Name()
	}
	n, readErr, writeErr := spoolCopy(spool, zr)
	if writeErr != nil {
		// the spool, not the evidence — a full or unwritable TMPDIR. Never
		// a "truncated collection": that would pass a partial index off as
		// the archive's own state, and materialise would exit 0 with
		// members missing.
		return fmt.Errorf("uac: spool: %w", writeErr)
	}
	if readErr != nil && n == 0 {
		return fmt.Errorf("uac: gunzip: %w", readErr)
	}
	if readErr != nil {
		// a truncated gzip stream: index what decompressed
		a.truncated = fmt.Errorf("gzip stream ends early: %w", readErr)
	}
	return a.indexTar(io.NewSectionReader(spool, 0, n), n)
}

// spoolTemp opens the spool under TMPDIR; a test hands in an unwritable one.
var spoolTemp = func() (*os.File, error) { return os.CreateTemp("", "gomount-uac-*.tar") }

// spoolCopy copies the gunzipped stream into the spool and keeps the two
// ways it can stop apart — io.Copy folds them into one error: a read error
// is the evidence (the gzip stream ends early, a checksum fails), a write
// error is the spool (TMPDIR full, unwritable).
func spoolCopy(dst io.Writer, src io.Reader) (n int64, readErr, writeErr error) {
	buf := make([]byte, 256<<10)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, nil, ew
			}
			if nw != nr {
				return n, nil, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil, nil
			}
			return n, er, nil
		}
	}
}

// note records why the index stopped early, keeping the first cause: a
// gzip stream that ends early makes its tar end early too.
func (a *Archive) note(err error) {
	if a.truncated == nil {
		a.truncated = err
	}
}

// indexTar walks the tar once, recording where each member's data starts
// so Open reads it in place later.
func (a *Archive) indexTar(src *io.SectionReader, size int64) error {
	cr := &countingReader{r: src}
	tr := tar.NewReader(cr)
	var pending []hardLink
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if a.root.n+a.meta.n == 0 {
				return fmt.Errorf("uac: tar: %w", err)
			}
			a.note(fmt.Errorf("tar ends early at member %d: %w", a.root.n+a.meta.n, err))
			break
		}
		dataOff := cr.n
		m := &member{
			size: hdr.Size, mode: uint32(hdr.Mode) & 0o7777,
			uid: uint32(hdr.Uid), gid: uint32(hdr.Gid),
			mtime: hdr.ModTime, atime: hdr.AccessTime, ctime: hdr.ChangeTime,
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			m.typ = typeDir
		case tar.TypeSymlink:
			m.typ = typeSymlink
			m.link = hdr.Linkname
		case tar.TypeLink:
			m.typ = typeFile
			pending = append(pending, hardLink{name: hdr.Name, target: hdr.Linkname, m: m})
		case tar.TypeReg, tar.TypeGNUSparse: // archive/tar reads the old TypeRegA as TypeReg
			m.typ = typeFile
			if dataOff+hdr.Size > size {
				m.size = max(size-dataOff, 0) // what the archive still holds
				a.note(fmt.Errorf("tar ends inside %s", hdr.Name))
			}
			off, n := dataOff, m.size
			m.open = func() (io.ReadCloser, error) {
				return io.NopCloser(io.NewSectionReader(src, off, n)), nil
			}
		default:
			continue // devices, fifos: nothing a tree reads
		}
		a.place(hdr.Name, m)
	}
	for _, hl := range pending { // a hard link reads its target's bytes
		if t := a.lookupMember(hl.target); t != nil && t.open != nil {
			hl.m.open, hl.m.size = t.open, t.size
		} else {
			hl.m.open = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }
		}
	}
	return nil
}

type hardLink struct {
	name, target string
	m            *member
}

// lookupMember resolves an archive member name to its indexed member.
func (a *Archive) lookupMember(name string) *member {
	clean := cleanName(name)
	if rest, ok := strings.CutPrefix(clean, rootDir+"/"); ok {
		if n := a.root.lookup("/" + rest); n != nil {
			return n.m
		}
		return nil
	}
	if n := a.meta.lookup("/" + clean); n != nil {
		return n.m
	}
	return nil
}

// countingReader tracks the stream position of a tar read, so the data
// offset of every member is known; its Seek lets archive/tar skip member
// bodies instead of reading them.
type countingReader struct {
	r *io.SectionReader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Seek(offset int64, whence int) (int64, error) {
	pos, err := c.r.Seek(offset, whence)
	if err == nil {
		c.n = pos
	}
	return pos, err
}

// ---- zip ----------------------------------------------------------------

// indexZip reads the central directory: every member is addressable at
// once, so nothing is spooled.
func (a *Archive) indexZip(ra io.ReaderAt, size int64) error {
	zr, err := zip.NewReader(io.NewSectionReader(ra, 0, size), size)
	if err != nil {
		return fmt.Errorf("uac: zip: %w", err)
	}
	for _, f := range zr.File {
		mode := f.Mode()
		m := &member{size: int64(f.UncompressedSize64), mtime: f.Modified, mode: zipPerm(mode)}
		m.uid, m.gid = zipOwner(f.Extra)
		switch {
		case mode.IsDir() || strings.HasSuffix(f.Name, "/"):
			m.typ = typeDir
		case mode&os.ModeSymlink != 0:
			m.typ = typeSymlink
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
			rc.Close()
			m.link = string(b)
		case mode.IsRegular() || mode&os.ModeType == 0:
			m.typ = typeFile
			f := f
			m.open = func() (io.ReadCloser, error) { return f.Open() }
		default:
			continue
		}
		a.place(f.Name, m)
	}
	return nil
}

// zipPerm folds an os.FileMode back to the POSIX permission bits.
func zipPerm(mode os.FileMode) uint32 {
	perm := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		perm |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		perm |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		perm |= 0o1000
	}
	return perm
}

// zipOwner reads the Info-ZIP "ux" (0x7875) extra field Info-ZIP's zip
// writes on Unix: version, then variable-width uid and gid. Zero when absent.
func zipOwner(extra []byte) (uid, gid uint32) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+n > len(extra) {
			return 0, 0
		}
		data := extra[4 : 4+n]
		if id == 0x7875 && len(data) >= 2 && data[0] == 1 {
			us := int(data[1])
			if 2+us+1 > len(data) {
				return 0, 0
			}
			uid = leUint(data[2 : 2+us])
			gs := int(data[2+us])
			if 3+us+gs > len(data) {
				return uid, 0
			}
			gid = leUint(data[3+us : 3+us+gs])
			return uid, gid
		}
		extra = extra[4+n:]
	}
	return 0, 0
}

func leUint(b []byte) uint32 {
	var v uint32
	for i := len(b) - 1; i >= 0 && i < 4; i-- {
		v = v<<8 | uint32(b[i])
	}
	return v
}

// ---- uac.log ------------------------------------------------------------

// logStamp is the timestamp uac.log leads every line with.
const logStamp = "2006-01-02 15:04:05 -0700"

// readLog parses the collector's run log out of the meta tree: the version
// on its banner line, the `Key: value` facts it logs at start-up, and the
// first and last stamped lines as the acquisition's start and finish.
func readLog(meta *tree) Log {
	var lg Log
	n := meta.lookup("/" + logName)
	if n == nil || n.m.open == nil {
		return lg
	}
	rc, err := n.m.open()
	if err != nil {
		return lg
	}
	defer rc.Close()
	sc := bufio.NewScanner(io.LimitReader(rc, 8<<20))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if len(line) >= len(logStamp) {
			if t, err := time.Parse(logStamp, line[:len(logStamp)]); err == nil {
				if lg.Started.IsZero() {
					lg.Started = t
				}
				lg.Finished = t
				line = strings.TrimSpace(line[len(logStamp):])
			}
		}
		// the banner line names the tool in full and then its version;
		// older releases wrap the name in "UAC (…)"
		if _, rest, ok := strings.Cut(line, "Unix-like Artifacts Collector"); ok && lg.Version == "" {
			rest = strings.TrimLeft(rest, ") ")
			if f := strings.Fields(rest); len(f) > 0 && f[0] != "" && f[0][0] >= '0' && f[0][0] <= '9' {
				lg.Version = f[0]
				continue
			}
		}
		msg := line
		if i := strings.Index(line, " "); i > 0 && len(line[:i]) == 3 && strings.ToUpper(line[:i]) == line[:i] {
			msg = strings.TrimSpace(line[i:]) // drop the level word (INF, ERR, …)
		}
		key, value, ok := strings.Cut(msg, ": ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "operating system":
			lg.OS = value
		case "system architecture":
			lg.Arch = value
		case "hostname":
			lg.Hostname = value
		case "time zone":
			lg.Timezone = value
		case "mount point":
			lg.MountPoint = value
		case "output format":
			lg.OutputFormat = value
		case "command line":
			lg.CommandLine = value
		}
	}
	return lg
}
