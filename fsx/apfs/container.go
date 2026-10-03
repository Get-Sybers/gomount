package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// The container: block 0 carries a copy of the container superblock
// (nx_superblock_t, "NXSB"); the authoritative one is the newest
// checksummed superblock in the checkpoint descriptor area. It names the
// block size, the container object map (physical) and the volume
// superblocks (virtual oids, resolved through that map).
const (
	nxMagic          = 0x4253584e // "NXSB" little-endian
	nxMaxVolumes     = 100
	nxIncompatV1     = 0x1
	nxIncompatV2     = 0x2
	nxIncompatFusion = 0x100

	// nx_xp_desc_blocks' top bit: the descriptor area is a tree, not a range
	xpAreaIsTree = 0x80000000
)

// Container is an opened APFS container.
type Container struct {
	br         blockReader
	sb         []byte // the chosen superblock block
	xid        uint64
	blockSize  int64
	blockCount uint64
	uuid       string
	incompat   uint64
	omap       *tree // the container object map
	fsOIDs     []uint64
}

// OpenContainer reads the superblock, chooses the newest checkpoint and
// opens the container object map.
func OpenContainer(ra io.ReaderAt, size int64) (*Container, error) {
	if size < 4096 {
		return nil, fmt.Errorf("apfs: volume too small for a container superblock")
	}
	head := make([]byte, 4096)
	if _, err := ra.ReadAt(head, 0); err != nil && err != io.EOF {
		return nil, fmt.Errorf("apfs: read superblock: %w", err)
	}
	le := binary.LittleEndian
	if le.Uint32(head[32:]) != nxMagic {
		return nil, fmt.Errorf("apfs: no NXSB superblock at block 0")
	}
	bs := int64(le.Uint32(head[36:]))
	if bs < 4096 || bs > 65536 || bs&(bs-1) != 0 {
		return nil, fmt.Errorf("apfs: implausible block size %d", bs)
	}
	c := &Container{br: blockReader{ra: ra, size: size, blockSize: bs}, blockSize: bs}
	sb, _, err := c.br.readObject(0, typeNXSuperblock)
	if err != nil {
		// a stale or damaged block 0 is survivable when the checkpoint area is not
		sb, err = c.br.read(0)
		if err != nil {
			return nil, err
		}
	}
	c.sb = sb
	c.xid = le.Uint64(sb[16:])
	if newest := c.newestCheckpointSuperblock(sb); newest != nil {
		c.sb = newest
		c.xid = le.Uint64(newest[16:])
	}
	sb = c.sb
	c.blockCount = le.Uint64(sb[40:])
	c.incompat = le.Uint64(sb[64:])
	if c.incompat&^(nxIncompatV1|nxIncompatV2|nxIncompatFusion) != 0 {
		return nil, fmt.Errorf("apfs: unsupported container features %#x", c.incompat)
	}
	c.uuid = formatUUID(sb[72:88])
	if bc := uint64(size / bs); c.blockCount == 0 || c.blockCount > bc {
		c.blockCount = bc // an image cut short of the container is read as far as it goes
	}
	omapAddr := le.Uint64(sb[160:])
	root, err := c.omapRoot(omapAddr)
	if err != nil {
		return nil, fmt.Errorf("apfs: container object map: %w", err)
	}
	c.omap = &tree{br: &c.br, rootAddr: root, resolve: identity}
	if err := c.omap.open(); err != nil {
		return nil, fmt.Errorf("apfs: container object map tree: %w", err)
	}
	maxFS := int(le.Uint32(sb[180:]))
	if maxFS <= 0 || maxFS > nxMaxVolumes {
		maxFS = nxMaxVolumes
	}
	for i := 0; i < maxFS; i++ {
		if oid := le.Uint64(sb[184+8*i:]); oid != 0 {
			c.fsOIDs = append(c.fsOIDs, oid)
		}
	}
	return c, nil
}

func identity(oid uint64) (uint64, error) { return oid, nil }

// newestCheckpointSuperblock scans the checkpoint descriptor area for the
// checksummed superblock with the highest transaction id; nil when the
// area is unreadable (or laid out as a tree, which this reader leaves to
// block 0's copy).
func (c *Container) newestCheckpointSuperblock(sb []byte) []byte {
	le := binary.LittleEndian
	descBlocks := le.Uint32(sb[104:])
	descBase := le.Uint64(sb[112:])
	if descBlocks&xpAreaIsTree != 0 || descBlocks == 0 || descBlocks > 1<<16 {
		return nil
	}
	var best []byte
	bestXID := le.Uint64(sb[16:])
	for i := uint64(0); i < uint64(descBlocks); i++ {
		b, err := c.br.read(descBase + i)
		if err != nil {
			break
		}
		h := parseObjHeader(b)
		if h.kind() != typeNXSuperblock || le.Uint32(b[32:]) != nxMagic || !checksumOK(b) {
			continue
		}
		if h.xid > bestXID || best == nil && h.xid == bestXID {
			best, bestXID = b, h.xid
		}
	}
	return best
}

// omapRoot reads an object-map object (omap_phys_t) and returns its
// B-tree root block.
func (c *Container) omapRoot(paddr uint64) (uint64, error) {
	b, _, err := c.br.readObject(paddr, typeOmap)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[48:]), nil
}

func formatUUID(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// BlockSize is the container's block size.
func (c *Container) BlockSize() int64 { return c.blockSize }

// UUID is the container identifier.
func (c *Container) UUID() string { return c.uuid }

// VolumeInfo describes one volume of the container as its superblock
// states it, before it is opened.
type VolumeInfo struct {
	Index           int    // 1-based position in the container's volume array
	Name            string // apfs_volname
	UUID            string
	Role            uint16
	RoleName        string
	Encrypted       bool // the APFS_FS_UNENCRYPTED flag is not set
	CaseInsensitive bool
	Sealed          bool
	Files, Dirs     uint64
	OID             uint64 // the volume superblock's virtual oid
	Xid             uint64
}

// volume roles (apfs_role)
const (
	roleNone       = 0x0000
	roleSystem     = 0x0001
	roleUser       = 0x0002
	roleRecovery   = 0x0004
	roleVM         = 0x0008
	rolePreboot    = 0x0010
	roleInstaller  = 0x0020
	roleData       = 0x0040
	roleBaseband   = 0x0080
	roleUpdate     = 0x00c0
	roleXART       = 0x0100
	roleHardware   = 0x0140
	roleBackup     = 0x0180
	roleSidecar    = 0x01c0
	roleEnterprise = 0x0200
	rolePrelogin   = 0x0240
)

func roleName(r uint16) string {
	switch r {
	case roleNone:
		return "none"
	case roleSystem:
		return "system"
	case roleUser:
		return "user"
	case roleRecovery:
		return "recovery"
	case roleVM:
		return "vm"
	case rolePreboot:
		return "preboot"
	case roleInstaller:
		return "installer"
	case roleData:
		return "data"
	case roleBaseband:
		return "baseband"
	case roleUpdate:
		return "update"
	case roleXART:
		return "xart"
	case roleHardware:
		return "hardware"
	case roleBackup:
		return "backup"
	case roleSidecar:
		return "sidecar"
	case roleEnterprise:
		return "enterprise"
	case rolePrelogin:
		return "prelogin"
	}
	return fmt.Sprintf("role-%#x", r)
}

// volume superblock (apfs_superblock_t) fields
const (
	apsbMagic = 0x42535041 // "APSB" little-endian

	fsIncompatCaseInsensitive   = 0x01
	fsIncompatDatalessSnaps     = 0x02
	fsIncompatEncRolled         = 0x04
	fsIncompatNormInsensitive   = 0x08
	fsIncompatIncompleteRestore = 0x10
	fsIncompatSealed            = 0x20
	fsIncompatPFK               = 0x40
	fsIncompatSecondaryFSRoot   = 0x80

	fsFlagUnencrypted = 0x01
)

// readVolumeSuperblock resolves a volume oid through the container map.
func (c *Container) readVolumeSuperblock(oid uint64) ([]byte, objHeader, error) {
	paddr, err := c.omap.omapLookup(oid, c.xid)
	if err != nil {
		return nil, objHeader{}, err
	}
	b, h, err := c.br.readObject(paddr, typeFS)
	if err != nil {
		return nil, h, err
	}
	if binary.LittleEndian.Uint32(b[32:]) != apsbMagic {
		return nil, h, fmt.Errorf("apfs: volume object %d has no APSB magic", oid)
	}
	return b, h, nil
}

func volumeInfoFrom(index int, oid uint64, b []byte, h objHeader) VolumeInfo {
	le := binary.LittleEndian
	incompat := le.Uint64(b[56:])
	role := le.Uint16(b[964:])
	return VolumeInfo{
		Index: index, OID: oid, Xid: h.xid,
		Name:            strings.TrimRight(string(b[704:960]), "\x00"),
		UUID:            formatUUID(b[240:256]),
		Role:            role,
		RoleName:        roleName(role),
		Encrypted:       le.Uint64(b[264:])&fsFlagUnencrypted == 0,
		CaseInsensitive: incompat&fsIncompatCaseInsensitive != 0,
		Sealed:          incompat&fsIncompatSealed != 0,
		Files:           le.Uint64(b[184:]),
		Dirs:            le.Uint64(b[192:]),
	}
}

// Volumes lists the container's volumes. A volume whose superblock cannot
// be read is reported with its oid and the error in its name, never
// silently dropped.
func (c *Container) Volumes() []VolumeInfo {
	out := make([]VolumeInfo, 0, len(c.fsOIDs))
	for i, oid := range c.fsOIDs {
		b, h, err := c.readVolumeSuperblock(oid)
		if err != nil {
			out = append(out, VolumeInfo{Index: i + 1, OID: oid, Name: fmt.Sprintf("(unreadable: %v)", err), RoleName: "unknown"})
			continue
		}
		out = append(out, volumeInfoFrom(i+1, oid, b, h))
	}
	return out
}

// OpenVolume opens the volume at a 1-based index.
func (c *Container) OpenVolume(index int) (*Volume, error) {
	if index < 1 || index > len(c.fsOIDs) {
		return nil, fmt.Errorf("apfs: volume %d out of range (%d volumes)", index, len(c.fsOIDs))
	}
	oid := c.fsOIDs[index-1]
	b, h, err := c.readVolumeSuperblock(oid)
	if err != nil {
		return nil, fmt.Errorf("apfs: volume %d: %w", index, err)
	}
	return openVolume(c, volumeInfoFrom(index, oid, b, h), b)
}

// DefaultVolume picks the volume an unattended reader wants: the Data
// role (the user data, logs and most artefacts on a modern Mac), else the
// System role, else the first volume that opens.
func (c *Container) DefaultVolume() (*Volume, error) {
	vols := c.Volumes()
	for _, want := range []uint16{roleData, roleSystem, roleUser} {
		for _, v := range vols {
			if v.Role == want {
				if vol, err := c.OpenVolume(v.Index); err == nil {
					return vol, nil
				}
			}
		}
	}
	var firstErr error
	for _, v := range vols {
		vol, err := c.OpenVolume(v.Index)
		if err == nil {
			return vol, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("apfs: container holds no volume")
	}
	return nil, firstErr
}
