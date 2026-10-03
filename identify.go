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
	"strings"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/image"
	"github.com/Get-Sybers/gomount/lvm"
)

// identifyDoc is the one JSON document.
type identifyDoc struct {
	Image      identifyImage    `json:"image"`
	Partitions []identifyPart   `json:"partitions"`
	LVM        *identifyLVM     `json:"lvm,omitempty"`
	Volumes    []identifyVolume `json:"volumes"`
	Snapshots  []any            `json:"snapshots"` // P3: LVM-cow + Btrfs inventory
}

type identifyImage struct {
	Path   string `json:"path"`
	Format string `json:"format"` // "e01" | "dmg" | "sparseimage" | "sparsebundle" | "vmdk" | "vhdx" | "vhd" | "qcow2" | "vdi" | "raw"
	Size   int64  `json:"size"`
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
	defer closeImage()

	doc := &identifyDoc{
		Image:     identifyImage{Path: path, Format: sniffFormat(path), Size: size},
		Snapshots: []any{},
	}
	vols, vgs, err := resolveVolumes(ra, size)
	if err != nil {
		return nil, err
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
		if v.FSType == "apfs-container" || v.FSType == "apfs" {
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
				MissingPVs: vg.Missing,
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

// osGuess reads the identity files a root filesystem carries.
func osGuess(fsys fsx.FS) string {
	if r, err := fsys.Open("/etc/os-release"); err == nil {
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
