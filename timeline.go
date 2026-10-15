// timeline — one JSONL record per (file, timestamp kind), the fs:stat
// shape of docs/linux §5.4 that replaces filestat+l2t_filestat in the
// Linux path: TimeKind (birth/modify/access/change — whatever the
// backend actually has), EventTime as ISO 8601 UTC at fixed microsecond
// precision, path, size, mode, owner, inode, nlink, link target — and
// the entry's ALLOCATION STATE on every row. --residue adds the
// recovered rows of §5.5 (Allocated=false, the residue kind and detail
// riding each one); --hash adds md5/sha1/sha256 of each regular file,
// canonical by the filestat precedent. Rows cover every volume with a
// recognised fsx filesystem, or one volume under --volume/--lv; NTFS
// volumes are gomft's business and are skipped with a note.
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/image"
	"github.com/Get-Sybers/gomount/uac"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// timelineRow is one emitted record.
type timelineRow struct {
	Tool       string       `json:"Tool"`
	RecordType string       `json:"RecordType"`
	EventTime  string       `json:"EventTime"`
	TimeKind   string       `json:"TimeKind"`
	Volume     string       `json:"Volume"`
	FSType     string       `json:"FSType"`
	FSUUID     string       `json:"FSUUID,omitempty"`
	Label      string       `json:"Label,omitempty"`
	Path       string       `json:"Path"`
	IsDir      bool         `json:"IsDir,omitempty"`
	Size       int64        `json:"Size"`
	Mode       string       `json:"Mode,omitempty"` // octal, type bits included
	UID        *uint32      `json:"UID,omitempty"`
	GID        *uint32      `json:"GID,omitempty"`
	Inode      uint64       `json:"Inode,omitempty"`
	Nlink      uint32       `json:"Nlink,omitempty"`
	LinkTarget string       `json:"LinkTarget,omitempty"`
	Allocated  bool         `json:"Allocated"`
	Residue    *residueNote `json:"Residue,omitempty"`
	MD5        string       `json:"MD5,omitempty"`
	SHA1       string       `json:"SHA1,omitempty"`
	SHA256     string       `json:"SHA256,omitempty"`
}

type residueNote struct {
	Kind   string `json:"Kind"`
	Detail string `json:"Detail,omitempty"`
}

// timelineSummary is the one stderr line.
type timelineSummary struct {
	Volumes int `json:"volumes"`
	Rows    int `json:"rows"`
	Errors  int `json:"errors"`
	Skipped int `json:"skipped_volumes"`
}

func runTimeline(argv []string) int {
	fs := flag.NewFlagSet("timeline", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = every recognised volume)")
	lvName := fs.String("lv", "", "address one LVM logical volume as vg/lv")
	withResidue := fs.Bool("residue", false, "also emit the recovered rows (lost+found, orphans, deleted dirents)")
	withHash := fs.Bool("hash", false, "add md5/sha1/sha256 of each regular file's content")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gomount timeline: usage: timeline [--volume N | --lv vg/lv] [--residue] [--hash] <image>")
		return 1
	}
	ra, size, closeImage, err := image.OpenImage(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: open image: %v\n", err)
		return 1
	}
	defer func() { _ = closeImage() }()
	vols, _, err := resolveVolumes(ra, size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closeCollections(vols)
	if *volume > 0 || *lvName != "" {
		sel, serr := selectVolume(vols, *volume, *lvName)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "gomount: %v\n", serr)
			return 1
		}
		vols = []volumeRef{sel}
	}

	var sum timelineSummary
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for _, v := range vols {
		switch v.FSType {
		case "", "lvm2-pv":
			continue
		case "ntfs":
			fmt.Fprintf(os.Stderr, "gomount timeline: %s is NTFS — the $MFT timeline is gomft's business, skipped\n", v.Source)
			sum.Skipped++
			continue
		}
		if err := timelineVolume(enc, v, *withResidue, *withHash, &sum); err != nil {
			fmt.Fprintf(os.Stderr, "gomount timeline: %s: %v\n", v.Source, err)
			sum.Errors++
			continue
		}
		sum.Volumes++
	}
	line, _ := json.Marshal(sum)
	fmt.Fprintln(os.Stderr, string(line))
	if sum.Errors > 0 {
		return 2
	}
	if sum.Volumes == 0 {
		fmt.Fprintln(os.Stderr, "gomount timeline: no volume with a recognised filesystem")
		return 1
	}
	return 0
}

// timelineVolume emits one volume's rows.
func timelineVolume(enc *json.Encoder, v volumeRef, withResidue, withHash bool, sum *timelineSummary) error {
	// A UAC collection's [root] volume: its collected member mtimes are only a
	// fraction of the host, but the collector's bodyfile/bodyfile.txt carries
	// the whole fs:stat timeline — emit that instead when it is present (#9).
	// The collector-output volume keeps its member-mtime rows.
	if handled, err := emitBodyfile(enc, v, sum); err != nil {
		return err
	} else if handled {
		return nil
	}
	_, fsys, release, err := openRef(v)
	if err != nil {
		return err
	}
	if release != nil {
		defer release()
	}
	if fsys == nil {
		return fmt.Errorf("no fsx backend for %s", v.FSType)
	}
	info := fsys.Info()
	emit := func(e fsx.Entry, res *residueNote, open func() (io.ReadCloser, error)) error {
		base := timelineRow{
			Tool: "gomount", RecordType: "timeline",
			Volume: v.Source, FSType: info.Type, FSUUID: info.UUID, Label: info.Label,
			Path: e.Path, IsDir: e.IsDir, Size: e.Size,
			Inode: e.Inode, Nlink: e.Nlink, LinkTarget: e.LinkTarget,
			Allocated: e.Allocated, Residue: res,
		}
		if e.Mode != 0 {
			base.Mode = fmt.Sprintf("%o", e.Mode)
			uid, gid := e.UID, e.GID
			base.UID, base.GID = &uid, &gid
		}
		if withHash && open != nil {
			if md5s, sha1s, sha256s, herr := hashContent(open); herr == nil {
				base.MD5, base.SHA1, base.SHA256 = md5s, sha1s, sha256s
			}
		}
		kinds := []struct {
			kind string
			t    time.Time
		}{
			{"birth", e.Btime}, {"modify", e.Mtime},
			{"access", e.Atime}, {"change", e.Ctime},
		}
		emitted := false
		for _, k := range kinds {
			if k.t.IsZero() {
				continue
			}
			row := base
			row.TimeKind, row.EventTime = k.kind, k.t.UTC().Format(tstamp.ISO8601Layout)
			if err := enc.Encode(row); err != nil {
				return err
			}
			sum.Rows++
			emitted = true
		}
		if !emitted { // an entry with no timestamps at all still exists
			row := base
			row.TimeKind = "none"
			if err := enc.Encode(row); err != nil {
				return err
			}
			sum.Rows++
		}
		return nil
	}

	err = fsys.Walk(func(e fsx.Entry, open func() (io.ReadCloser, error)) error {
		return emit(e, nil, open)
	})
	if err != nil {
		return err
	}
	if !withResidue {
		return nil
	}
	rr, ok := fsys.(fsx.Residuer)
	if !ok {
		return nil
	}
	return rr.Residues(func(r fsx.Residue, open func() (io.ReadCloser, error)) error {
		return emit(r.Entry, &residueNote{Kind: r.Kind, Detail: r.Detail}, open)
	})
}

// hashContent streams the file once through all three digests.
func hashContent(open func() (io.ReadCloser, error)) (md5s, sha1s, sha256s string, err error) {
	r, err := open()
	if err != nil {
		return "", "", "", err
	}
	defer r.Close()
	h5, h1, h256 := md5.New(), sha1.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(h5, h1, h256), r); err != nil {
		return "", "", "", err
	}
	hexOf := func(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
	return hexOf(h5), hexOf(h1), hexOf(h256), nil
}

// emitBodyfile emits a UAC collection's full fs:stat timeline from the
// collector's bodyfile/bodyfile.txt (TSK 3.x), when the volume is the host
// tree ([root]) and the bodyfile is present. Returns handled=true when it took
// the volume (so the caller skips the collected-member walk); handled=false
// means no bodyfile — fall back to that walk.
func emitBodyfile(enc *json.Encoder, v volumeRef, sum *timelineSummary) (bool, error) {
	if v.collection == nil || v.FSType != uac.FSTypeRoot {
		return false, nil
	}
	rc, err := v.collection.Meta().Open("/bodyfile/bodyfile.txt")
	if err != nil {
		return false, nil // no bodyfile in this collection
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // long paths
	for sc.Scan() {
		e, ok := parseBodyfile(sc.Text())
		if !ok {
			continue
		}
		base := timelineRow{
			Tool: "gomount", RecordType: "timeline",
			Volume: v.Source, FSType: v.FSType,
			Path: e.path, IsDir: e.isDir, Size: e.size,
			Inode: e.inode, LinkTarget: e.link, Allocated: true,
		}
		if e.mode != 0 {
			base.Mode = fmt.Sprintf("%o", e.mode)
			uid, gid := e.uid, e.gid
			base.UID, base.GID = &uid, &gid
		}
		for _, k := range []struct {
			kind string
			t    int64
		}{{"birth", e.crtime}, {"modify", e.mtime}, {"access", e.atime}, {"change", e.ctime}} {
			if k.t <= 0 {
				continue // a 0 is an honest null — no row
			}
			row := base
			row.TimeKind = k.kind
			row.EventTime = time.Unix(k.t, 0).UTC().Format(tstamp.ISO8601Layout)
			if err := enc.Encode(row); err != nil {
				return true, err
			}
			sum.Rows++
		}
	}
	return true, sc.Err()
}

// bodyfileEntry is one parsed TSK 3.x bodyfile row.
type bodyfileEntry struct {
	path, link                  string
	inode                       uint64
	mode                        uint32
	isDir                       bool
	uid, gid                    uint32
	size                        int64
	atime, mtime, ctime, crtime int64
}

// parseBodyfile parses one TSK 3.x bodyfile line:
//
//	MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
//
// The name may itself contain "|"; the nine trailing fields are fixed, so the
// name is whatever lies between the leading MD5 and them. A symlink's name is
// "path -> target".
func parseBodyfile(line string) (bodyfileEntry, bool) {
	parts := strings.Split(line, "|")
	if len(parts) < 11 {
		return bodyfileEntry{}, false
	}
	tail := parts[len(parts)-9:]
	name := strings.Join(parts[1:len(parts)-9], "|")
	e := bodyfileEntry{path: name}
	if i := strings.Index(name, " -> "); i >= 0 {
		e.path, e.link = name[:i], name[i+4:]
	}
	if e.path == "" {
		return e, false
	}
	e.inode = parseUint(tail[0])
	e.mode, e.isDir = modeStringToMode(tail[1])
	e.uid = uint32(parseUint(tail[2]))
	e.gid = uint32(parseUint(tail[3]))
	e.size = int64(parseUint(tail[4]))
	e.atime, e.mtime, e.ctime, e.crtime = parseInt(tail[5]), parseInt(tail[6]), parseInt(tail[7]), parseInt(tail[8])
	return e, true
}

func parseUint(s string) uint64 { n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64); return n }
func parseInt(s string) int64   { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

// modeStringToMode turns TSK's `-rwxr-xr-x` rendering back into an octal mode
// with its type bits, and reports whether it is a directory.
func modeStringToMode(s string) (uint32, bool) {
	if len(s) < 10 {
		return 0, false
	}
	var mode uint32
	isDir := false
	switch s[0] {
	case 'd':
		mode, isDir = 0o040000, true
	case 'l':
		mode = 0o120000
	case 'b':
		mode = 0o060000
	case 'c':
		mode = 0o020000
	case 'p':
		mode = 0o010000
	case 's':
		mode = 0o140000
	default: // '-' and anything unexpected: a regular file
		mode = 0o100000
	}
	p := s[1:10]
	for i, bit := range []uint32{0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001} {
		switch p[i] {
		case '-', 'S', 'T': // no execute bit (S/T is the special bit without execute)
		default: // r, w, x, s, t
			mode |= bit
		}
	}
	if p[2] == 's' || p[2] == 'S' {
		mode |= 0o4000 // setuid
	}
	if p[5] == 's' || p[5] == 'S' {
		mode |= 0o2000 // setgid
	}
	if p[8] == 't' || p[8] == 'T' {
		mode |= 0o1000 // sticky
	}
	return mode, isDir
}
