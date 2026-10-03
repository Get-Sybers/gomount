// Residue (docs/linux §5.5) for ext2/3/4: what the filesystem's own
// metadata still proves. Three kinds land with this backend —
//
//	lost_found      fsck-recovered orphans living under /lost+found: real,
//	                allocated files whose original path is gone;
//	orphan_inode    unlinked-but-intact inodes, from the superblock orphan
//	                chain and an inode-bitmap sweep for in-use inodes no
//	                directory entry references;
//	deleted_dirent  names still readable in directory-block slack — the
//	                filename and parent of a deleted file, joined to its
//	                inode when the number survives in the slot.
//
// Structure-driven only: nothing here carves unallocated space.
package ext4

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"

	"github.com/Get-Sybers/gomount/fsx"
)

// residueFn is the callback shape of fsx.Residuer.
type residueFn = func(r fsx.Residue, open func() (io.ReadCloser, error)) error

// bgFlags reads a group's flags (bit 0 = INODE_UNINIT: bitmap meaningless).
func (f *FS) bgFlags(g int) uint16 {
	b, err := fsx.ReadFull(f.ra, f.gdtOffset+int64(g)*int64(f.descSize)+0x12, 2)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

// Residues implements fsx.Residuer.
func (f *FS) Residues(fn residueFn) error {
	if err := f.lostFound(fn); err != nil {
		return err
	}
	if err := f.orphans(fn); err != nil {
		return err
	}
	return f.deletedDirents(fn)
}

// lostFound emits every entry under /lost+found — allocated files whose
// original path fsck could not restore (the "#<inode>" names).
func (f *FS) lostFound(fn residueFn) error {
	in, _, err := f.lookup("/lost+found")
	if err != nil {
		return nil // no lost+found is a fine filesystem
	}
	ents, err := f.readDirents(in)
	if err != nil {
		return nil
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].name < ents[j].name })
	for _, d := range ents {
		if d.name == "." || d.name == ".." {
			continue
		}
		ci, err := f.inode(d.ino)
		if err != nil {
			continue
		}
		e := f.entry(ci, d.name, path.Join("/lost+found", d.name))
		r := fsx.Residue{
			Kind:   "lost_found",
			Detail: fmt.Sprintf("fsck-recovered entry %s (inode %d)", d.name, d.ino),
			Entry:  e,
			ID:     fmt.Sprintf("inode-%d", d.ino),
		}
		var open func() (io.ReadCloser, error)
		if ci.mode&sIFMT == sIFREG {
			c := ci
			open = func() (io.ReadCloser, error) { return f.openInode(c) }
		}
		if err := fn(r, open); err != nil {
			return err
		}
	}
	return nil
}

// orphans emits unlinked-but-intact inodes: the superblock orphan chain
// (i_dtime doubles as the next-orphan pointer while an inode sits on it),
// then a sweep of every group's inode bitmap for in-use inodes that no
// directory entry references.
func (f *FS) orphans(fn residueFn) error {
	seen := map[uint64]bool{}
	emit := func(ino uint64, how string) error {
		if seen[ino] {
			return nil
		}
		seen[ino] = true
		in, err := f.inode(ino)
		if err != nil {
			return nil
		}
		e := f.entry(in, fmt.Sprintf("inode-%d", ino), fmt.Sprintf("/[orphan]/inode-%d", ino))
		e.Allocated = false
		r := fsx.Residue{
			Kind:   "orphan_inode",
			Detail: how,
			Entry:  e,
			ID:     fmt.Sprintf("inode-%d", ino),
		}
		var open func() (io.ReadCloser, error)
		if in.mode&sIFMT == sIFREG && in.size > 0 {
			c := in
			open = func() (io.ReadCloser, error) { return f.openInode(c) }
		}
		return fn(r, open)
	}

	// 1. the superblock chain
	ino := uint64(f.lastOrphan)
	for hops := 0; ino != 0 && ino <= uint64(f.inodesCount) && hops < 1<<16; hops++ {
		in, err := f.inode(ino)
		if err != nil {
			break
		}
		if err := emit(ino, fmt.Sprintf("superblock orphan chain (hop %d)", hops)); err != nil {
			return err
		}
		ino = uint64(in.dtime) // the chain's next pointer
	}

	// 2. the bitmap sweep against the referenced set
	referenced := map[uint64]bool{rootIno: true}
	var walkRefs func(in *inode, depth int)
	walkRefs = func(in *inode, depth int) {
		if depth > maxWalkDepth {
			return
		}
		ents, err := f.readDirents(in)
		if err != nil {
			return
		}
		for _, d := range ents {
			if d.name == "." || d.name == ".." {
				referenced[d.ino] = true
				continue
			}
			first := !referenced[d.ino]
			referenced[d.ino] = true
			if !first {
				continue
			}
			ci, err := f.inode(d.ino)
			if err == nil && ci.mode&sIFMT == sIFDIR {
				walkRefs(ci, depth+1)
			}
		}
	}
	if root, err := f.inode(rootIno); err == nil {
		walkRefs(root, 0)
	}
	for g := 0; g < f.groups; g++ {
		if f.bgFlags(g)&0x1 != 0 {
			continue // INODE_UNINIT: no used inodes recorded here
		}
		d, err := f.groupDesc(g)
		if err != nil {
			continue
		}
		bm, err := f.readBlock(d.inodeBitmap)
		if err != nil {
			continue
		}
		base := uint64(g) * uint64(f.inodesPerGroup)
		for i := uint64(0); i < uint64(f.inodesPerGroup); i++ {
			ino := base + i + 1
			if ino < firstIno || ino > uint64(f.inodesCount) {
				continue
			}
			if bm[i/8]&(1<<(i%8)) == 0 || referenced[ino] {
				continue
			}
			if err := emit(ino, "in-use inode with no directory entry (bitmap sweep)"); err != nil {
				return err
			}
		}
	}
	return nil
}

// deletedDirents scans every directory block's slack for old entries the
// live rec_len chain skips over.
func (f *FS) deletedDirents(fn residueFn) error {
	var walk func(in *inode, dir string, depth int) error
	walk = func(in *inode, dir string, depth int) error {
		if depth > maxWalkDepth {
			return nil
		}
		ra, size, err := f.blockReader(in)
		if err != nil {
			return nil
		}
		buf := make([]byte, f.blockSize)
		var children []dirent
		for off := int64(0); off < size; off += f.blockSize {
			n, rerr := ra.ReadAt(buf, off)
			if rerr != nil && rerr != io.EOF {
				break
			}
			var slackErr error
			parseDirentBlock(buf[:n], func(d dirent) { children = append(children, d) },
				func(gap []byte, _ int) {
					if slackErr != nil {
						return
					}
					slackErr = f.scanSlack(gap, dir, fn)
				})
			if slackErr != nil {
				return slackErr
			}
		}
		sort.Slice(children, func(i, j int) bool { return children[i].name < children[j].name })
		for _, d := range children {
			if d.name == "." || d.name == ".." {
				continue
			}
			ci, err := f.inode(d.ino)
			if err == nil && ci.mode&sIFMT == sIFDIR {
				if err := walk(ci, path.Join(dir, d.name), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	root, err := f.inode(rootIno)
	if err != nil {
		return err
	}
	return walk(root, "/", 0)
}

// scanSlack looks for plausible dirent shapes inside one live entry's gap.
func (f *FS) scanSlack(gap []byte, dir string, fn residueFn) error {
	le := binary.LittleEndian
	for off := 0; off+8 <= len(gap); off += 4 {
		ino := uint64(le.Uint32(gap[off:]))
		nameLen := int(gap[off+6])
		if nameLen == 0 || off+8+nameLen > len(gap) {
			continue
		}
		name := gap[off+8 : off+8+nameLen]
		if !plausibleName(name) || ino > uint64(f.inodesCount) {
			continue
		}
		e := fsx.Entry{Name: string(name), Path: path.Join(dir, string(name))}
		detail := fmt.Sprintf("deleted entry %q in %s", string(name), dir)
		var open func() (io.ReadCloser, error)
		if ino != 0 {
			if in, err := f.inode(ino); err == nil {
				e = f.entry(in, string(name), path.Join(dir, string(name)))
				e.Allocated = false
				if in.dtime != 0 {
					detail = fmt.Sprintf("%s, inode %d deleted at epoch %d", detail, ino, in.dtime)
				} else {
					detail = fmt.Sprintf("%s, inode %d", detail, ino)
				}
				if in.mode&sIFMT == sIFREG && in.size > 0 && in.links > 0 {
					c := in
					open = func() (io.ReadCloser, error) { return f.openInode(c) }
				}
			}
		}
		r := fsx.Residue{
			Kind:   "deleted_dirent",
			Detail: detail,
			Entry:  e,
			ID:     fmt.Sprintf("dirent-%s-%s", path.Join(dir, string(name)), idSuffix(ino)),
		}
		if err := fn(r, open); err != nil {
			return err
		}
		off += ((8 + nameLen + 3) &^ 3) - 4 // continue past this recovered entry
	}
	return nil
}

func idSuffix(ino uint64) string {
	if ino == 0 {
		return "noinode"
	}
	return fmt.Sprintf("inode-%d", ino)
}

// plausibleName filters slack candidates: no NUL, no '/', printable-ish.
func plausibleName(b []byte) bool {
	for _, c := range b {
		if c == 0 || c == '/' || c < 0x20 || c == 0x7F {
			return false
		}
	}
	return true
}
