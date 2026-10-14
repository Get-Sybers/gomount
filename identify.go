// identify — print the whole resolved volume stack as ONE JSON document
// (docs/linux §5.2): image format, partitions, LVM findings, every
// addressable volume with its filesystem type, UUID, label and an OS
// guess, plus the snapshot inventory (which lands with P3 and is an
// honest empty list until then). It is the lane's routing and reporting
// input.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/image"
	"github.com/Get-Sybers/gomount/lvm"
	"github.com/Get-Sybers/gomount/uac"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// identifyDoc is the one JSON document.
type identifyDoc struct {
	Image      identifyImage       `json:"image"`
	Collection *identifyCollection `json:"collection,omitempty"` // the image is a UAC collection
	Partitions []identifyPart      `json:"partitions"`
	LVM        *identifyLVM        `json:"lvm,omitempty"`
	Volumes    []identifyVolume    `json:"volumes"`
	Snapshots  []any               `json:"snapshots"` // P3: LVM-cow + Btrfs inventory
}

type identifyImage struct {
	Path   string `json:"path"`
	Format string `json:"format"` // "e01" | "dmg" | "sparseimage" | "sparsebundle" | "vmdk" | "vhdx" | "vhd" | "qcow2" | "vdi" | "zip" | "gzip" | "tar" | "raw"
	Size   int64  `json:"size"`
}

// identifyCollection describes a UAC collection: what the collector's own
// run log (uac.log) says about the host and the acquisition, and how the
// archive indexed. The host's files are the stack's volume 1 ([root]).
type identifyCollection struct {
	Tool        string `json:"tool"` // "uac"
	Version     string `json:"version,omitempty"`
	Container   string `json:"container"` // zip | tar | tar.gz
	Hostname    string `json:"hostname,omitempty"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	MountPoint  string `json:"mount_point,omitempty"`
	Started     string `json:"started,omitempty"`
	Finished    string `json:"finished,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	RootMembers int    `json:"root_members"` // members under [root]/
	MetaMembers int    `json:"meta_members"` // the collector's own files
	Truncated   string `json:"truncated,omitempty"`
}

type identifyPart struct {
	Index  int    `json:"index"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Type   string `json:"type"`
}

type identifyLVM struct {
	VGs []identifyVG `json:"vgs"`
}

type identifyVG struct {
	Name       string       `json:"name"`
	UUID       string       `json:"uuid"`
	ExtentSize int64        `json:"extent_size"`
	MissingPVs []string     `json:"missing_pvs,omitempty"`
	ShortPVs   []string     `json:"short_pvs,omitempty"` // PVs the image holds less of than the metadata declares (a truncated capture)
	LVs        []identifyLV `json:"lvs"`
}

type identifyLV struct {
	Name     string   `json:"name"`
	Size     int64    `json:"size"`
	Segments []string `json:"segments"` // "linear(pv0)" / "striped2x64KiB(pv0,pv1)"
}

type identifyVolume struct {
	Volume int    `json:"volume"` // the --volume index
	Source string `json:"source"` // "p1" | "vg0/root" | "disk"
	Offset int64  `json:"offset,omitempty"`
	Size   int64  `json:"size"`
	FSType string `json:"fstype,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	Label  string `json:"label,omitempty"`
	OS     string `json:"os,omitempty"` // "linux (debian)" | "windows" | ""
	Note   string `json:"note,omitempty"`
}

func runIdentify(argv []string) int {
	fs := flag.NewFlagSet("identify", flag.ExitOnError)
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gomount identify: usage: identify <image>")
		return 1
	}
	doc, err := identifyImageFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	return 0
}

func identifyImageFile(path string) (*identifyDoc, error) {
	ra, size, closeImage, err := image.OpenImage(path)
	if err != nil {
		return nil, fmt.Errorf("open image: %w", err)
	}
	defer func() { _ = closeImage() }()

	doc := &identifyDoc{
		Image:     identifyImage{Path: path, Format: sniffFormat(path), Size: size},
		Snapshots: []any{},
	}
	vols, vgs, err := resolveVolumes(ra, size)
	if err != nil {
		return nil, err
	}
	defer closeCollections(vols)
	if len(vols) > 0 && vols[0].collection != nil {
		doc.Collection = describeCollection(vols[0].collection)
	}
	for _, v := range vols {
		if strings.HasPrefix(v.Source, "p") && !strings.Contains(v.Source, "/") {
			doc.Partitions = append(doc.Partitions, identifyPart{
				Index: v.Index, Offset: v.Offset, Size: v.Size, Type: v.TypeName,
			})
		}
		iv := identifyVolume{
			Volume: v.Index, Source: v.Source, Offset: v.Offset, Size: v.Size,
			FSType: v.FSType,
			Note:   v.Note,
		}
		if v.FSType != "" && v.FSType != "lvm2-pv" && v.FSType != "ntfs" && v.FSType != "apfs-container" && v.ra != nil {
			if _, raw, release, ferr := openRef(v); ferr == nil && raw != nil {
				info := raw.Info()
				iv.UUID, iv.Label = info.UUID, info.Label
				iv.OS = osGuess(raw)
				if release != nil {
					release()
				}
			}
		}
		if v.FSType == "apfs-container" || v.FSType == "apfs" || v.collection != nil {
			iv.Note = v.TypeName
		}
		if v.FSType == "ntfs" {
			iv.OS = "windows"
		}
		if v.FSType == "" && v.ra != nil {
			iv.Note = "no recognised filesystem"
		}
		doc.Volumes = append(doc.Volumes, iv)
	}
	if len(vgs) > 0 {
		l := &identifyLVM{}
		for _, vg := range vgs {
			ivg := identifyVG{
				Name: vg.Name, UUID: vg.UUID, ExtentSize: vg.ExtentSize,
				MissingPVs: vg.Missing, ShortPVs: vg.Short,
			}
			for _, lv := range vg.LVs {
				ivg.LVs = append(ivg.LVs, identifyLV{
					Name: lv.Name, Size: lv.Extents * vg.ExtentSize,
					Segments: describeSegments(lv),
				})
			}
			l.VGs = append(l.VGs, ivg)
		}
		doc.LVM = l
	}
	return doc, nil
}

func describeSegments(lv lvm.LV) []string {
	var out []string
	for _, s := range lv.Segments {
		var pvs []string
		for _, st := range s.Stripes {
			pvs = append(pvs, st.PVName)
		}
		if len(s.Stripes) <= 1 {
			out = append(out, "linear("+strings.Join(pvs, ",")+")")
			continue
		}
		out = append(out, fmt.Sprintf("striped%dx%d(%s)", len(s.Stripes), s.StripeSize, strings.Join(pvs, ",")))
	}
	return out
}

// describeCollection renders a UAC collection's uac.log facts.
func describeCollection(a *uac.Archive) *identifyCollection {
	lg := a.Log()
	c := &identifyCollection{
		Tool: "uac", Version: lg.Version, Container: string(a.Kind()),
		Hostname: lg.Hostname, OS: lg.OS, Arch: lg.Arch, Timezone: lg.Timezone, MountPoint: lg.MountPoint,
		CommandLine: lg.CommandLine,
		RootMembers: a.Root().Members(), MetaMembers: a.Meta().Members(),
	}
	if !lg.Started.IsZero() {
		c.Started = tstamp.ISO8601(lg.Started)
	}
	if !lg.Finished.IsZero() {
		c.Finished = tstamp.ISO8601(lg.Finished)
	}
	if err := a.Truncated(); err != nil {
		c.Truncated = err.Error()
	}
	return c
}

// openFollowing opens p, following a symlink (relative to its directory)
// up to a few levels — /etc/os-release is a link into /usr/lib on every
// modern distribution, and its target is what identifies the OS.
func openFollowing(fsys fsx.FS, p string) (io.ReadCloser, error) {
	for hop := 0; hop < 8; hop++ {
		e, err := fsys.Stat(p)
		if err != nil {
			return nil, err
		}
		if e.LinkTarget == "" {
			return fsys.Open(p)
		}
		target := e.LinkTarget
		if !strings.HasPrefix(target, "/") {
			target = path.Join(path.Dir(p), target)
		}
		p = target
	}
	return nil, fmt.Errorf("%s: too many levels of symbolic links", p)
}

// osGuess reads the identity files a root filesystem carries.
func osGuess(fsys fsx.FS) string {
	if r, err := openFollowing(fsys, "/etc/os-release"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(r, 4096))
		r.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if id, ok := strings.CutPrefix(line, "ID="); ok {
				return "linux (" + strings.Trim(id, `"`) + ")"
			}
		}
		return "linux"
	}
	if _, err := fsys.Stat("/Windows/System32"); err == nil {
		return "windows"
	}
	if _, err := fsys.Stat("/System/Library/CoreServices/SystemVersion.plist"); err == nil {
		return "macos (system)"
	}
	if _, err := fsys.Stat("/private/var/db/dslocal"); err == nil {
		return "macos (data)"
	}
	return ""
}

// sniffFormat labels the image container by its content (image.Format).
func sniffFormat(path string) string { return image.Format(path) }
