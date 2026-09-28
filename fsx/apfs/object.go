package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Every APFS object is one block that opens with a 32-byte header
// (obj_phys_t): a Fletcher-64 checksum over the rest of the block, the
// object identifier, the transaction that last wrote it, and a type word
// whose low 16 bits name the object and whose high bits say how it is
// addressed (virtual through an object map, physical by block, or
// ephemeral in a checkpoint).
const (
	objHeaderSize = 32

	objTypeMask     = 0x0000ffff
	objStorageMask  = 0xc0000000
	objVirtual      = 0x00000000
	objPhysical     = 0x40000000
	objEphemeral    = 0x80000000
	objNoHeaderFlag = 0x20000000

	typeNXSuperblock = 0x01
	typeBTree        = 0x02
	typeBTreeNode    = 0x03
	typeOmap         = 0x0b
	typeFS           = 0x0d // volume superblock
	typeFSTree       = 0x0e
)

type objHeader struct {
	cksum   uint64
	oid     uint64
	xid     uint64
	typ     uint32 // the full type word, flags included
	subtype uint32
}

func (h objHeader) kind() uint32 { return h.typ & objTypeMask }

func parseObjHeader(b []byte) objHeader {
	le := binary.LittleEndian
	return objHeader{
		cksum: le.Uint64(b[0:]), oid: le.Uint64(b[8:]), xid: le.Uint64(b[16:]),
		typ: le.Uint32(b[24:]), subtype: le.Uint32(b[28:]),
	}
}

// fletcher64 is APFS's object checksum: Fletcher-64 over the block's
// 32-bit words past the checksum field, modulo 2^32-1, then folded so the
// checksum of (checksum ‖ data) is zero.
func fletcher64(data []byte) uint64 {
	const mod = 0xffffffff
	var sum1, sum2 uint64
	for i := 0; i+4 <= len(data); i += 4 {
		sum1 = (sum1 + uint64(binary.LittleEndian.Uint32(data[i:]))) % mod
		sum2 = (sum2 + sum1) % mod
	}
	low := mod - (sum1+sum2)%mod
	high := mod - (sum1+low)%mod
	return high<<32 | low
}

// checksumOK verifies a block's header checksum.
func checksumOK(block []byte) bool {
	if len(block) < objHeaderSize {
		return false
	}
	return fletcher64(block[8:]) == binary.LittleEndian.Uint64(block[0:8])
}

// blockReader reads whole blocks off the bounded container reader,
// bounds-checked against the container's size.
type blockReader struct {
	ra        io.ReaderAt
	size      int64
	blockSize int64
}

func (r *blockReader) read(paddr uint64) ([]byte, error) {
	off := int64(paddr) * r.blockSize
	if paddr > uint64(r.size/r.blockSize) || off < 0 || off+r.blockSize > r.size {
		return nil, fmt.Errorf("apfs: block %d beyond the container (%d blocks)", paddr, r.size/r.blockSize)
	}
	b := make([]byte, r.blockSize)
	if _, err := r.ra.ReadAt(b, off); err != nil && err != io.EOF {
		return nil, fmt.Errorf("apfs: read block %d: %w", paddr, err)
	}
	return b, nil
}

// readObject reads a block and insists it is a checksummed object of the
// wanted kind (0 = any).
func (r *blockReader) readObject(paddr uint64, want uint32) ([]byte, objHeader, error) {
	b, err := r.read(paddr)
	if err != nil {
		return nil, objHeader{}, err
	}
	h := parseObjHeader(b)
	if !checksumOK(b) {
		return nil, h, fmt.Errorf("apfs: block %d: object checksum mismatch (type %#x)", paddr, h.typ)
	}
	if want != 0 && h.kind() != want {
		return nil, h, fmt.Errorf("apfs: block %d: object type %#x, want %#x", paddr, h.kind(), want)
	}
	return b, h, nil
}
