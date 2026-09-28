package hfsplus

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The HFS+ B-tree file: fixed-size nodes, node 0 the header node whose
// header record gives the node size, the root and the first leaf. Every
// node is a 14-byte descriptor, its records, and a table of 16-bit record
// offsets growing down from the node's end (one extra marks the free
// space). Index records are a key followed by a child node number; leaf
// records a key followed by data. Keys carry a 16-bit length (big keys,
// mandatory on HFS+); in an index node without variable-size index keys
// (the extents tree) every key occupies the maximum key length.
const (
	nodeDescSize = 14
	nodeLeaf     = -1
	nodeIndex    = 0
	nodeHeader   = 1
	nodeMap      = 2

	btBigKeys          = 0x2
	btVariableIndexKey = 0x4

	maxTreeDepth = 16
)

type btree struct {
	name        string
	fork        io.ReaderAt
	size        int64
	nodeSize    int
	root        uint32
	firstLeaf   uint32
	lastLeaf    uint32
	totalNodes  uint32
	maxKeyLen   int
	varIndexKey bool
	keyCompare  byte
}

type node struct {
	num    uint32
	raw    []byte
	kind   int8
	height uint8
	n      int
	fLink  uint32
	bLink  uint32
}

func (f *FS) openBTree(fork *forkReader, name string) (*btree, error) {
	if fork.size < 512 {
		return nil, fmt.Errorf("hfsplus: %s B-tree of %d bytes", name, fork.size)
	}
	hdr := make([]byte, 512)
	if _, err := fork.ReadAt(hdr, 0); err != nil && err != io.EOF {
		return nil, fmt.Errorf("hfsplus: %s B-tree header: %w", name, err)
	}
	be := binary.BigEndian
	if int8(hdr[8]) != nodeHeader {
		return nil, fmt.Errorf("hfsplus: %s B-tree: node 0 is not a header node", name)
	}
	rec := hdr[nodeDescSize:]
	t := &btree{
		name:       name,
		fork:       fork,
		size:       fork.size,
		nodeSize:   int(be.Uint16(rec[18:])),
		root:       be.Uint32(rec[2:]),
		firstLeaf:  be.Uint32(rec[10:]),
		lastLeaf:   be.Uint32(rec[14:]),
		totalNodes: be.Uint32(rec[22:]),
		maxKeyLen:  int(be.Uint16(rec[20:])),
		keyCompare: rec[37],
	}
	attrs := be.Uint32(rec[38:])
	t.varIndexKey = attrs&btVariableIndexKey != 0
	if attrs&btBigKeys == 0 {
		return nil, fmt.Errorf("hfsplus: %s B-tree without big keys", name)
	}
	if t.nodeSize < 512 || t.nodeSize > 32768 || t.nodeSize&(t.nodeSize-1) != 0 {
		return nil, fmt.Errorf("hfsplus: %s B-tree node size %d", name, t.nodeSize)
	}
	if int64(t.totalNodes)*int64(t.nodeSize) > fork.size {
		return nil, fmt.Errorf("hfsplus: %s B-tree claims %d nodes in %d bytes", name, t.totalNodes, fork.size)
	}
	return t, nil
}

// empty reports a tree with no records (root 0).
func (t *btree) empty() bool { return t.root == 0 }

func (t *btree) node(num uint32) (*node, error) {
	off := int64(num) * int64(t.nodeSize)
	if num >= t.totalNodes || off+int64(t.nodeSize) > t.size {
		return nil, fmt.Errorf("hfsplus: %s B-tree node %d outside the file", t.name, num)
	}
	raw := make([]byte, t.nodeSize)
	if _, err := t.fork.ReadAt(raw, off); err != nil && err != io.EOF {
		return nil, fmt.Errorf("hfsplus: %s B-tree node %d: %w", t.name, num, err)
	}
	be := binary.BigEndian
	n := &node{
		num:    num,
		raw:    raw,
		fLink:  be.Uint32(raw[0:]),
		bLink:  be.Uint32(raw[4:]),
		kind:   int8(raw[8]),
		height: raw[9],
		n:      int(be.Uint16(raw[10:])),
	}
	if nodeDescSize+2*(n.n+1) > t.nodeSize {
		return nil, fmt.Errorf("hfsplus: %s B-tree node %d claims %d records", t.name, num, n.n)
	}
	return n, nil
}

// record returns record i's bytes: from its offset to the next record's.
func (t *btree) record(n *node, i int) ([]byte, error) {
	if i < 0 || i >= n.n {
		return nil, fmt.Errorf("hfsplus: %s B-tree node %d: record %d of %d", t.name, n.num, i, n.n)
	}
	be := binary.BigEndian
	start := int(be.Uint16(n.raw[t.nodeSize-2*(i+1):]))
	end := int(be.Uint16(n.raw[t.nodeSize-2*(i+2):]))
	if start < nodeDescSize || end > t.nodeSize-2*(n.n+1) || start > end {
		return nil, fmt.Errorf("hfsplus: %s B-tree node %d: record %d spans %d..%d", t.name, n.num, i, start, end)
	}
	return n.raw[start:end], nil
}

// split separates a record into its key and its payload (the data of a
// leaf record, the child node number of an index record).
func (t *btree) split(n *node, rec []byte) (key, data []byte, err error) {
	if len(rec) < 2 {
		return nil, nil, fmt.Errorf("hfsplus: %s B-tree: record too short", t.name)
	}
	kl := int(binary.BigEndian.Uint16(rec))
	if 2+kl > len(rec) {
		return nil, nil, fmt.Errorf("hfsplus: %s B-tree: key of %d bytes in a %d-byte record", t.name, kl, len(rec))
	}
	key = rec[2 : 2+kl]
	span := kl
	if n.kind == nodeIndex && !t.varIndexKey {
		span = t.maxKeyLen
	}
	off := 2 + span
	off += off & 1 // the payload is 2-byte aligned
	if off > len(rec) {
		return nil, nil, fmt.Errorf("hfsplus: %s B-tree: payload past the record", t.name)
	}
	return key, rec[off:], nil
}

// cursor is a position in the leaf chain.
type cursor struct {
	t    *btree
	node *node
	i    int
}

// seek descends to the first leaf record whose key is >= the search key,
// where cmp(key) is the sign of (search - key). A nil cursor means every
// key is smaller (or the tree is empty).
func (t *btree) seek(cmp func(key []byte) int) (*cursor, error) {
	if t.empty() {
		return nil, nil
	}
	num := t.root
	for depth := 0; depth < maxTreeDepth; depth++ {
		n, err := t.node(num)
		if err != nil {
			return nil, err
		}
		switch n.kind {
		case nodeIndex:
			// the last child whose key is <= the search key; the first
			// child when every key is larger (the leaves to its left hold
			// nothing smaller than the tree's smallest key)
			child := uint32(0)
			for i := 0; i < n.n; i++ {
				rec, err := t.record(n, i)
				if err != nil {
					return nil, err
				}
				key, data, err := t.split(n, rec)
				if err != nil {
					return nil, err
				}
				if len(data) < 4 {
					return nil, fmt.Errorf("hfsplus: %s B-tree: index record without a child", t.name)
				}
				c := binary.BigEndian.Uint32(data)
				if i == 0 || cmp(key) >= 0 {
					child = c
				} else {
					break
				}
			}
			if child == 0 || child == num {
				return nil, fmt.Errorf("hfsplus: %s B-tree: index node %d without a child", t.name, num)
			}
			num = child
		case nodeLeaf:
			for i := 0; i < n.n; i++ {
				rec, err := t.record(n, i)
				if err != nil {
					return nil, err
				}
				key, _, err := t.split(n, rec)
				if err != nil {
					return nil, err
				}
				if cmp(key) <= 0 {
					return &cursor{t: t, node: n, i: i}, nil
				}
			}
			// every key in this leaf is smaller: the next leaf's first record
			c := &cursor{t: t, node: n, i: n.n}
			if err := c.advance(); err != nil {
				return nil, err
			}
			if c.node == nil {
				return nil, nil
			}
			return c, nil
		default:
			return nil, fmt.Errorf("hfsplus: %s B-tree: node %d of kind %d on the search path", t.name, num, n.kind)
		}
	}
	return nil, fmt.Errorf("hfsplus: %s B-tree deeper than %d levels", t.name, maxTreeDepth)
}

// first positions at the first leaf record of the tree.
func (t *btree) first() (*cursor, error) {
	if t.empty() || t.firstLeaf == 0 {
		return nil, nil
	}
	n, err := t.node(t.firstLeaf)
	if err != nil {
		return nil, err
	}
	c := &cursor{t: t, node: n, i: 0}
	if n.n == 0 {
		if err := c.advance(); err != nil {
			return nil, err
		}
		if c.node == nil {
			return nil, nil
		}
	}
	return c, nil
}

// valid reports whether the cursor sits on a record.
func (c *cursor) valid() bool { return c != nil && c.node != nil && c.i < c.node.n }

// current returns the record under the cursor.
func (c *cursor) current() (key, data []byte, err error) {
	rec, err := c.t.record(c.node, c.i)
	if err != nil {
		return nil, nil, err
	}
	return c.t.split(c.node, rec)
}

// next moves to the following record, crossing into the next leaf.
func (c *cursor) next() error {
	c.i++
	if c.i >= c.node.n {
		return c.advance()
	}
	return nil
}

// advance follows fLink to the next non-empty leaf (node nil at the end).
func (c *cursor) advance() error {
	for hops := 0; hops < 1<<20; hops++ {
		if c.node.fLink == 0 {
			c.node = nil
			return nil
		}
		n, err := c.t.node(c.node.fLink)
		if err != nil {
			return err
		}
		if n.kind != nodeLeaf {
			return fmt.Errorf("hfsplus: %s B-tree: leaf %d links to a non-leaf", c.t.name, c.node.num)
		}
		if n.num == c.node.num {
			return fmt.Errorf("hfsplus: %s B-tree: leaf %d links to itself", c.t.name, n.num)
		}
		c.node, c.i = n, 0
		if n.n > 0 {
			return nil
		}
	}
	return fmt.Errorf("hfsplus: %s B-tree: leaf chain does not end", c.t.name)
}
