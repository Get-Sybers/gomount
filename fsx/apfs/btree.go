package apfs

import (
	"encoding/binary"
	"fmt"
)

// The B-trees: the object maps (fixed 16-byte keys and values, physical
// child pointers) and the file-system trees (variable keys and values,
// virtual child oids resolved through the volume's object map). A node is
// one object block: the 24-byte node header after the object header, a
// table of contents, keys growing up from the end of the table, values
// growing down from the end of the block (the root keeps a 40-byte
// btree_info_t footer there).
const (
	btNodeRoot        = 0x0001
	btNodeLeaf        = 0x0002
	btNodeFixedKVSize = 0x0004
	btNodeHashed      = 0x0008
	btNodeNoHeader    = 0x0010

	btHeaderEnd  = objHeaderSize + 24 // where the table of contents area starts
	btFooterSize = 40
	invalidOff   = 0xffff
)

type btNode struct {
	raw      []byte
	flags    uint16
	level    uint16
	nkeys    int
	tocStart int // absolute offset of the table of contents
	keysBase int // key offsets are relative to this
	valsEnd  int // value offsets count back from this
	fixed    bool
}

func (n *btNode) isLeaf() bool { return n.flags&btNodeLeaf != 0 }
func (n *btNode) isRoot() bool { return n.flags&btNodeRoot != 0 }

// tree is one B-tree with what its footer declares and how its child
// pointers are resolved.
type tree struct {
	br       *blockReader
	rootAddr uint64
	rootOID  uint64 // the root's virtual oid: a hashed tree's child oids are relative to it
	keySize  int    // fixed key size (0 = variable)
	valSize  int    // fixed leaf value size (0 = variable)
	physical bool   // BTREE_PHYSICAL: child values are block numbers
	hashed   bool   // BTREE_HASHED: branch values carry a hash after the child oid
	// resolve turns a branch value (a child oid) into the child's block:
	// identity for physical trees, an object-map lookup for virtual ones.
	resolve func(oid uint64) (uint64, error)
}

func parseNode(raw []byte) (*btNode, error) {
	if len(raw) < btHeaderEnd {
		return nil, fmt.Errorf("apfs: b-tree node too small")
	}
	le := binary.LittleEndian
	n := &btNode{raw: raw}
	n.flags = le.Uint16(raw[32:])
	n.level = le.Uint16(raw[34:])
	n.nkeys = int(le.Uint32(raw[36:]))
	tableOff := int(le.Uint16(raw[40:]))
	tableLen := int(le.Uint16(raw[42:]))
	if tableOff == invalidOff {
		return nil, fmt.Errorf("apfs: b-tree node without a table of contents")
	}
	n.tocStart = btHeaderEnd + tableOff
	n.keysBase = n.tocStart + tableLen
	n.valsEnd = len(raw)
	if n.isRoot() {
		n.valsEnd -= btFooterSize
	}
	n.fixed = n.flags&btNodeFixedKVSize != 0
	if n.tocStart > len(raw) || n.keysBase > len(raw) || n.valsEnd < n.keysBase {
		return nil, fmt.Errorf("apfs: b-tree node layout out of range")
	}
	if n.nkeys < 0 || n.nkeys > 1<<16 {
		return nil, fmt.Errorf("apfs: b-tree node with %d keys", n.nkeys)
	}
	return n, nil
}

// entry returns the i-th key and value of a node. In a fixed-size tree a
// branch value is the 8-byte child oid whatever the leaf value size is.
func (t *tree) entry(n *btNode, i int) (key, val []byte, err error) {
	if i < 0 || i >= n.nkeys {
		return nil, nil, fmt.Errorf("apfs: b-tree entry %d of %d", i, n.nkeys)
	}
	le := binary.LittleEndian
	var koff, klen, voff, vlen int
	if n.fixed {
		e := n.tocStart + 4*i
		if e+4 > len(n.raw) {
			return nil, nil, fmt.Errorf("apfs: b-tree table of contents out of range")
		}
		koff, voff = int(le.Uint16(n.raw[e:])), int(le.Uint16(n.raw[e+2:]))
		klen = t.keySize
		vlen = t.valSize
		if !n.isLeaf() {
			vlen = 8
		}
	} else {
		e := n.tocStart + 8*i
		if e+8 > len(n.raw) {
			return nil, nil, fmt.Errorf("apfs: b-tree table of contents out of range")
		}
		koff, klen = int(le.Uint16(n.raw[e:])), int(le.Uint16(n.raw[e+2:]))
		voff, vlen = int(le.Uint16(n.raw[e+4:])), int(le.Uint16(n.raw[e+6:]))
	}
	ks := n.keysBase + koff
	if koff == invalidOff || ks+klen > n.valsEnd || klen < 0 {
		return nil, nil, fmt.Errorf("apfs: b-tree key %d out of range", i)
	}
	key = n.raw[ks : ks+klen]
	if voff == invalidOff {
		return key, nil, nil // a ghost: key without value
	}
	vs := n.valsEnd - voff
	if vs < n.keysBase || vs+vlen > n.valsEnd || vlen < 0 {
		return nil, nil, fmt.Errorf("apfs: b-tree value %d out of range", i)
	}
	return key, n.raw[vs : vs+vlen], nil
}

// node reads and parses the node at a block. A sealed volume's tree
// nodes carry no object header (BTNODE_NOHEADER: the header bytes are
// zero and the parent's hash vouches for the child), so an all-zero
// header is accepted as such and the checksum is not demanded.
func (t *tree) node(paddr uint64) (*btNode, error) {
	raw, err := t.br.read(paddr)
	if err != nil {
		return nil, err
	}
	h := parseObjHeader(raw)
	if h.typ == 0 && h.cksum == 0 && h.oid == 0 {
		n, err := parseNode(raw)
		if err != nil {
			return nil, err
		}
		if n.flags&btNodeNoHeader == 0 {
			return nil, fmt.Errorf("apfs: block %d: empty object header on a node not flagged headerless", paddr)
		}
		return n, nil
	}
	if !checksumOK(raw) {
		return nil, fmt.Errorf("apfs: block %d: object checksum mismatch (type %#x)", paddr, h.typ)
	}
	if k := h.kind(); k != typeBTree && k != typeBTreeNode {
		return nil, fmt.Errorf("apfs: block %d is not a b-tree node (type %#x)", paddr, k)
	}
	return parseNode(raw)
}

// child follows a branch entry's value to its node.
func (t *tree) child(val []byte) (*btNode, error) {
	if len(val) < 8 {
		return nil, fmt.Errorf("apfs: b-tree branch value too short")
	}
	oid := binary.LittleEndian.Uint64(val)
	switch {
	case t.physical:
		// a physical tree addresses its children by block
		return t.node(oid)
	case t.hashed:
		// a hashed tree (a sealed volume's fs tree: headerless nodes whose
		// parent hash vouches for them) stores child oids relative to the
		// root's oid; they are virtual like any other
		oid += t.rootOID
	}
	paddr, err := t.resolve(oid)
	if err != nil {
		return nil, err
	}
	return t.node(paddr)
}

// open reads the root and its footer, learning the fixed key/value sizes.
func (t *tree) open() error {
	root, err := t.node(t.rootAddr)
	if err != nil {
		return err
	}
	if !root.isRoot() {
		return fmt.Errorf("apfs: block %d is not a b-tree root", t.rootAddr)
	}
	f := root.raw[len(root.raw)-btFooterSize:]
	flags := binary.LittleEndian.Uint32(f[0:])
	t.physical = flags&0x10 != 0
	t.hashed = flags&0x80 != 0 || root.flags&btNodeHashed != 0
	t.keySize = int(binary.LittleEndian.Uint32(f[8:]))
	t.valSize = int(binary.LittleEndian.Uint32(f[12:]))
	return nil
}

// cmpFunc orders a search target against a stored key: <0 when the target
// sorts before the key, 0 when equal, >0 when after.
type cmpFunc func(key []byte) int

// iter walks a tree's leaves in key order from a seek point.
type iter struct {
	t     *tree
	stack []iterFrame
}

type iterFrame struct {
	n   *btNode
	idx int
}

// seek positions an iterator at the first leaf entry whose key sorts at
// or after the target (cmp(key) <= 0), descending through the last branch
// entry whose key sorts before it.
func (t *tree) seek(cmp cmpFunc) (*iter, error) {
	it := &iter{t: t}
	n, err := t.node(t.rootAddr)
	if err != nil {
		return nil, err
	}
	for depth := 0; ; depth++ {
		if depth > 32 {
			return nil, fmt.Errorf("apfs: b-tree deeper than 32 levels")
		}
		if n.isLeaf() {
			idx := n.nkeys
			for i := 0; i < n.nkeys; i++ {
				k, _, err := t.entry(n, i)
				if err != nil {
					return nil, err
				}
				if cmp(k) <= 0 {
					idx = i
					break
				}
			}
			it.stack = append(it.stack, iterFrame{n: n, idx: idx})
			if idx == n.nkeys { // the target sorts after this leaf: step on
				if err := it.advanceLeaf(); err != nil {
					return nil, err
				}
			}
			return it, nil
		}
		pick := 0
		for i := 0; i < n.nkeys; i++ {
			k, _, err := t.entry(n, i)
			if err != nil {
				return nil, err
			}
			if cmp(k) >= 0 {
				pick = i
			} else {
				break
			}
		}
		_, v, err := t.entry(n, pick)
		if err != nil {
			return nil, err
		}
		it.stack = append(it.stack, iterFrame{n: n, idx: pick})
		if n, err = t.child(v); err != nil {
			return nil, err
		}
	}
}

// valid reports whether the iterator sits on an entry.
func (it *iter) valid() bool {
	if len(it.stack) == 0 {
		return false
	}
	top := it.stack[len(it.stack)-1]
	return top.n.isLeaf() && top.idx < top.n.nkeys
}

// current returns the entry under the iterator.
func (it *iter) current() (key, val []byte, err error) {
	top := it.stack[len(it.stack)-1]
	return it.t.entry(top.n, top.idx)
}

// next moves to the following leaf entry, crossing nodes as needed.
func (it *iter) next() error {
	top := &it.stack[len(it.stack)-1]
	top.idx++
	if top.idx < top.n.nkeys {
		return nil
	}
	return it.advanceLeaf()
}

// advanceLeaf pops exhausted frames and descends into the next sibling's
// leftmost leaf; an exhausted root leaves the iterator invalid.
func (it *iter) advanceLeaf() error {
	for {
		it.stack = it.stack[:len(it.stack)-1]
		if len(it.stack) == 0 {
			return nil
		}
		parent := &it.stack[len(it.stack)-1]
		parent.idx++
		if parent.idx >= parent.n.nkeys {
			continue
		}
		_, v, err := it.t.entry(parent.n, parent.idx)
		if err != nil {
			return err
		}
		n, err := it.t.child(v)
		if err != nil {
			return err
		}
		for !n.isLeaf() {
			if n.nkeys == 0 {
				return fmt.Errorf("apfs: empty b-tree branch")
			}
			it.stack = append(it.stack, iterFrame{n: n, idx: 0})
			_, v, err := it.t.entry(n, 0)
			if err != nil {
				return err
			}
			if n, err = it.t.child(v); err != nil {
				return err
			}
		}
		it.stack = append(it.stack, iterFrame{n: n, idx: 0})
		if n.nkeys == 0 {
			continue
		}
		return nil
	}
}

// omapLookup resolves (oid, xid) in an object-map tree: the entry for that
// oid with the greatest transaction not after xid.
func (t *tree) omapLookup(oid, xid uint64) (uint64, error) {
	le := binary.LittleEndian
	target := func(k []byte) int {
		if len(k) < 16 {
			return 1
		}
		ko, kx := le.Uint64(k), le.Uint64(k[8:])
		switch {
		case oid < ko:
			return -1
		case oid > ko:
			return 1
		case xid < kx:
			return -1
		case xid > kx:
			return 1
		}
		return 0
	}
	// descend to the leaf, then take the last entry at or before the target
	n, err := t.node(t.rootAddr)
	if err != nil {
		return 0, err
	}
	for depth := 0; !n.isLeaf(); depth++ {
		if depth > 32 {
			return 0, fmt.Errorf("apfs: object map deeper than 32 levels")
		}
		pick := 0
		for i := 0; i < n.nkeys; i++ {
			k, _, err := t.entry(n, i)
			if err != nil {
				return 0, err
			}
			if target(k) >= 0 {
				pick = i
			} else {
				break
			}
		}
		_, v, err := t.entry(n, pick)
		if err != nil {
			return 0, err
		}
		if n, err = t.child(v); err != nil {
			return 0, err
		}
	}
	best := -1
	for i := 0; i < n.nkeys; i++ {
		k, _, err := t.entry(n, i)
		if err != nil {
			return 0, err
		}
		if target(k) >= 0 {
			best = i
		} else {
			break
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("apfs: object %d not in the object map", oid)
	}
	k, v, err := t.entry(n, best)
	if err != nil {
		return 0, err
	}
	if le.Uint64(k) != oid {
		return 0, fmt.Errorf("apfs: object %d not in the object map", oid)
	}
	if len(v) < 16 {
		return 0, fmt.Errorf("apfs: object map value too short")
	}
	if flags := le.Uint32(v); flags&0x1 != 0 { // OMAP_VAL_DELETED
		return 0, fmt.Errorf("apfs: object %d is deleted in the object map", oid)
	}
	return le.Uint64(v[8:]), nil
}
