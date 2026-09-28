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
	"time"

	"github.com/get-sybers/gomount/fsx"
	"github.com/get-sybers/gomount/image"
	"github.com/get-sybers/gopinfo/tstamp"
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
	defer closeImage()
	vols, _, err := resolveVolumes(ra, size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
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
	fsys, err := fsx.Open(v.ra, v.Size)
	if err != nil {
		return err
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
