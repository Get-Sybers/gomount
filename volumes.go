// The volume stack (docs/linux §5.2): between partition and filesystem
// sits the container-peeling layer. resolveVolumes walks it — partitions
// (or the bare whole-disk filesystem), LVM2 physical volumes assembled
// into their VGs, each logical volume probed like any partition — and
// returns every addressable volume in one deterministic order:
// partitions first (p1, p2, …), then LVs (vg/lv, VG name order). That
// order IS the --volume numbering; --lv addresses an LV by name.
package main

import (
	"fmt"
	"io"
	"strconv"

	"github.com/Get-Sybers/gomount/fsx"
	"github.com/Get-Sybers/gomount/fsx/apfs"
	_ "github.com/Get-Sybers/gomount/fsx/ext4"
	_ "github.com/Get-Sybers/gomount/fsx/hfsplus"
	_ "github.com/Get-Sybers/gomount/fsx/vfat"
	_ "github.com/Get-Sybers/gomount/fsx/xfs"
	"github.com/Get-Sybers/gomount/image"
	"github.com/Get-Sybers/gomount/lvm"
	"github.com/Get-Sybers/gomount/ntfsfs"
	"github.com/Get-Sybers/gomount/ntfsvol"
	"github.com/Get-Sybers/gomount/partition"
)

// volumeRef is one addressable volume of the resolved stack.
type volumeRef struct {
	Index    int    // 1-based position in the resolved order (--volume N)
	Source   string // "p1" | "vg0/root" | "disk" (whole-image filesystem) | "p2/apfs1" (an APFS volume)
	Offset   int64  // byte offset in the image (partition-backed; 0 for LVs)
	Size     int64
	FSType   string // "ntfs", "ext4", "ext3", "ext2", "xfs", "vfat", "apfs", "apfs-container", "lvm2-pv", or ""
	TypeName string // partition-table label, or "LVM2 logical volume", or the APFS volume's name and role
	ra       io.ReaderAt
	// an APFS volume: its 1-based index in the container the ra spans, and its role
	apfsIndex int
	apfsRole  string
}

// apfsVolumes peels an APFS container into its volumes: the container's own
// ref becomes "apfs-container" (it holds no filesystem itself) and one ref
// per volume follows, addressed as <source>/apfs<N>.
func apfsVolumes(container volumeRef) []volumeRef {
	container.FSType = "apfs-container"
	container.TypeName = "APFS container (" + container.TypeName + ")"
	out := []volumeRef{container}
	c, err := apfs.OpenContainer(container.ra, container.Size)
	if err != nil {
		container.TypeName += " — " + err.Error()
		out[0] = container
		return out
	}
	for _, v := range c.Volumes() {
		name := fmt.Sprintf("APFS volume %q (%s)", v.Name, v.RoleName)
		if v.Encrypted {
			name += " [FileVault]"
		}
		if v.Sealed {
			name += " [sealed]"
		}
		out = append(out, volumeRef{
			Source: container.Source + "/apfs" + strconv.Itoa(v.Index), Offset: container.Offset, Size: container.Size,
			FSType: "apfs", TypeName: name, ra: container.ra, apfsIndex: v.Index, apfsRole: v.RoleName,
		})
	}
	return out
}

// resolveVolumes peels the stack over an opened image.
func resolveVolumes(ra io.ReaderAt, size int64) ([]volumeRef, []*lvm.VG, error) {
	var vols []volumeRef
	var pvs []*lvm.PV

	// Superfloppy first, the same reasoning as partition.go's NTFS rule:
	// a partitionless vfat volume ends in the very 0x55AA an MBR does, so
	// a recognised whole-disk filesystem (or PV label) outranks whatever
	// the boot-code bytes would parse to as a partition table.
	whole := io.NewSectionReader(ra, 0, size)
	if lvm.IsPV(whole, size) {
		if pv, perr := lvm.ProbePV(whole, size, 0); perr == nil {
			pvs = append(pvs, pv)
			vols = append(vols, volumeRef{Source: "disk", Size: size,
				FSType: "lvm2-pv", TypeName: "LVM2 PV (whole disk)", ra: whole})
		}
	} else if t := fsx.Probe(whole, size); t != "" {
		v := volumeRef{Source: "disk", Size: size, FSType: t, TypeName: t + " (whole disk, partitionless)", ra: whole}
		if t == "apfs" {
			vols = apfsVolumes(v)
		} else {
			vols = append(vols, v)
		}
		for i := range vols {
			vols[i].Index = i + 1
		}
		return vols, nil, nil
	}

	var parts []partition.Partition
	if len(pvs) == 0 {
		var err error
		if parts, err = partition.Partitions(ra, size); err != nil {
			return nil, nil, err
		}
	}

	for i, p := range parts {
		v := volumeRef{
			Source: "p" + strconv.Itoa(i+1), Offset: p.Offset, Size: p.Size,
			TypeName: p.TypeName, ra: io.NewSectionReader(ra, p.Offset, p.Size),
		}
		switch {
		case p.Size <= 0:
		case lvm.IsPV(v.ra, p.Size):
			v.FSType = "lvm2-pv"
			if pv, perr := lvm.ProbePV(v.ra, p.Size, p.Offset); perr == nil {
				pvs = append(pvs, pv)
			}
		case p.LikelyNTFS:
			v.FSType = "ntfs"
		default:
			v.FSType = fsx.Probe(v.ra, p.Size)
		}
		if v.FSType == "apfs" {
			vols = append(vols, apfsVolumes(v)...)
			continue
		}
		vols = append(vols, v)
	}

	var vgs []*lvm.VG
	if len(pvs) > 0 {
		var err error
		if vgs, err = lvm.Assemble(pvs); err != nil {
			return nil, nil, fmt.Errorf("assemble LVM: %w", err)
		}
	}
	for _, vg := range vgs {
		for _, lv := range vg.LVs {
			lvRA, lvSize, lerr := vg.Reader(lv)
			v := volumeRef{
				Source:   vg.Name + "/" + lv.Name,
				Size:     lv.Extents * vg.ExtentSize,
				TypeName: "LVM2 logical volume",
			}
			if lerr != nil {
				v.TypeName = "LVM2 logical volume (" + lerr.Error() + ")"
			} else {
				v.ra, v.Size = lvRA, lvSize
				if looksNTFS(lvRA, lvSize) {
					v.FSType = "ntfs"
				} else {
					v.FSType = fsx.Probe(lvRA, lvSize)
				}
			}
			vols = append(vols, v)
		}
	}
	for i := range vols {
		vols[i].Index = i + 1
	}
	return vols, vgs, nil
}

// looksNTFS peeks a bounded volume's boot sector for the NTFS OEM id.
func looksNTFS(ra io.ReaderAt, size int64) bool {
	if size < 512 {
		return false
	}
	b, err := fsx.ReadFull(ra, 0, 512)
	return err == nil && string(b[3:11]) == "NTFS    " && b[510] == 0x55 && b[511] == 0xAA
}

// openVolumeFS resolves the stack and opens ONE volume as the verbs'
// volumeFS: --lv names an LV, --volume indexes the resolved order, and
// auto-select prefers the largest NTFS volume (the Windows behaviour,
// unchanged), else the Linux volume holding /etc/os-release, else the
// largest volume with a recognised filesystem.
func openVolumeFS(imgPath string, volume int, lvName string) (volumeFS, func() error, error) {
	fsys, _, _, closer, err := openVolume(imgPath, volume, lvName)
	return fsys, closer, err
}

// openVolume is openVolumeFS plus the selected volume's identity and,
// for the fsx backends, the raw fsx.FS (nil on NTFS) — what materialise
// needs to write origin-record manifest rows and stage residue.
func openVolume(imgPath string, volume int, lvName string) (volumeFS, fsx.FS, volumeRef, func() error, error) {
	ra, size, closeImage, err := image.OpenImage(imgPath)
	if err != nil {
		return nil, nil, volumeRef{}, nil, fmt.Errorf("open image: %w", err)
	}
	vols, _, err := resolveVolumes(ra, size)
	if err != nil {
		closeImage()
		return nil, nil, volumeRef{}, nil, err
	}
	sel, err := selectVolume(vols, volume, lvName)
	if err != nil {
		closeImage()
		return nil, nil, volumeRef{}, nil, err
	}
	fsys, raw, release, err := openRef(sel)
	if err != nil {
		closeImage()
		return nil, nil, volumeRef{}, nil, fmt.Errorf("open %s (%s): %w", sel.Source, sel.FSType, err)
	}
	closer := func() error {
		if release != nil {
			release()
		}
		return closeImage()
	}
	return fsys, raw, sel, closer, nil
}

// selectVolume applies the addressing rules over the resolved list.
func selectVolume(vols []volumeRef, volume int, lvName string) (volumeRef, error) {
	if len(vols) == 0 {
		return volumeRef{}, fmt.Errorf("no volumes found on image")
	}
	if lvName != "" {
		for _, v := range vols {
			if v.Source == lvName {
				return v, nil
			}
		}
		return volumeRef{}, fmt.Errorf("no logical volume %q (identify lists the stack)", lvName)
	}
	if volume > 0 {
		if volume > len(vols) {
			return volumeRef{}, fmt.Errorf("volume %d out of range (%d resolved)", volume, len(vols))
		}
		return vols[volume-1], nil
	}
	best := -1
	for i, v := range vols { // 1: the Windows rule — largest NTFS
		if v.FSType == "ntfs" && (best < 0 || v.Size > vols[best].Size) {
			best = i
		}
	}
	if best >= 0 {
		return vols[best], nil
	}
	for _, role := range []string{"data", "system", "user"} { // 2: a Mac — the Data volume, else System
		for _, v := range vols {
			if v.FSType == "apfs" && v.apfsRole == role {
				return v, nil
			}
		}
	}
	for _, v := range vols { // 3: a Mac on HFS+ — the volume holding SystemVersion.plist
		if v.FSType != "hfsplus" || v.ra == nil {
			continue
		}
		if fsys, err := fsx.Open(v.ra, v.Size); err == nil {
			if _, serr := fsys.Stat("/System/Library/CoreServices/SystemVersion.plist"); serr == nil {
				return v, nil
			}
		}
	}
	for _, v := range vols { // 4: the Linux root — /etc/os-release
		if v.FSType == "" || v.FSType == "lvm2-pv" || v.FSType == "apfs-container" || v.FSType == "apfs" || v.ra == nil {
			continue
		}
		if fsys, err := fsx.Open(v.ra, v.Size); err == nil {
			if _, serr := fsys.Stat("/etc/os-release"); serr == nil {
				return v, nil
			}
		}
	}
	for i, v := range vols { // 5: largest recognised filesystem
		if v.FSType == "" || v.FSType == "lvm2-pv" || v.FSType == "apfs-container" {
			continue
		}
		if best < 0 || v.Size > vols[best].Size {
			best = i
		}
	}
	if best < 0 {
		return volumeRef{}, fmt.Errorf("no recognised filesystem among %d volumes", len(vols))
	}
	return vols[best], nil
}

// openRef opens one resolved volume with its backend. The second return
// is the raw fsx.FS for the Linux backends (nil for NTFS): the residue
// seam and the volume's UUID/label live there. The third is the
// backend's release hook (the NTFS parser holds caches its Close must
// free; the fsx backends hold none).
func openRef(v volumeRef) (volumeFS, fsx.FS, func(), error) {
	switch v.FSType {
	case "":
		return nil, nil, nil, fmt.Errorf("no recognised filesystem")
	case "lvm2-pv":
		return nil, nil, nil, fmt.Errorf("an LVM2 PV holds no filesystem itself — address its LVs with --lv vg/lv")
	case "apfs-container":
		return nil, nil, nil, fmt.Errorf("an APFS container holds volumes — address one with --volume N (identify lists them as <partition>/apfs<N>)")
	case "apfs":
		c, err := apfs.OpenContainer(v.ra, v.Size)
		if err != nil {
			return nil, nil, nil, err
		}
		vol, err := c.OpenVolume(v.apfsIndex)
		if err != nil {
			return nil, nil, nil, err
		}
		return fsxFS{fs: vol}, vol, nil, nil
	case "ntfs":
		geom, err := ntfsvol.ReadNTFSGeometry(v.ra, 0, v.Size)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read NTFS geometry: %w", err)
		}
		fsys, err := ntfsfs.Open(ntfsvol.VolumeReader(v.ra, 0, geom), 0)
		if err != nil {
			return nil, nil, nil, err
		}
		return ntfsFS{fs: fsys}, nil, fsys.Close, nil
	default:
		fsys, err := fsx.Open(v.ra, v.Size)
		if err != nil {
			return nil, nil, nil, err
		}
		return fsxFS{fs: fsys}, fsys, nil, nil
	}
}
