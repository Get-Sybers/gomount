package uac

// The trees: one node per member (and per directory the member paths
// imply), served as a read-only fsx.FS the same way the ext4 backend serves
// an inode table — entries carry what the archive recorded and nothing it
// did not (an implied directory has a type and no mode, owner or time).

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Get-Sybers/gomount/fsx"
)

type memberType uint8

const (
	typeFile memberType = iota + 1
	typeDir
	typeSymlink
)

// POSIX type bits, added to a member's permission bits for fsx.Entry.Mode.
const (
	modeDir     = 0o040000
	modeRegular = 0o100000
	modeSymlink = 0o120000
)

// member is what the archive recorded about one entry.
type member struct {
	typ                 memberType
	size                int64
	mode                uint32 // permission bits incl. setuid/setgid/sticky; the type rides typ
	uid, gid            uint32
	mtime, atime, ctime time.Time
	link                string // symlink target, verbatim
	open                func() (io.ReadCloser, error)
}

// node is one entry of a tree.
type node struct {
	name     string
	path     string // "/"-rooted slash path
	m        *member
	implied  bool // a directory no member declared: only its existence is known
	children map[string]*node
}

// tree is a path-indexed set of members with the directories they imply.
type tree struct {
	root *node
	n    int // members placed
}

func newTree() *tree {
	return &tree{root: &node{path: "/", m: &member{typ: typeDir}, implied: true, children: map[string]*node{}}}
}

// add places one member at rel (a clean, slash-separated path with no
// leading slash), creating the directories above it. A name that climbs
// out of the tree is dropped: a crafted member never lands elsewhere.
func (t *tree) add(rel string, m *member) {
	comps := strings.Split(rel, "/")
	cur := t.root
	for i, c := range comps {
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			return
		}
		child, ok := cur.children[c]
		if !ok {
			child = &node{name: c, path: path.Join(cur.path, c), children: map[string]*node{}}
			cur.children[c] = child
		}
		if i == len(comps)-1 {
			// the member itself; a directory member declared after the
			// files beneath it keeps them
			if m.typ != typeDir || child.m == nil || child.m.typ == typeDir {
				child.m, child.implied = m, false
			}
			t.n++
		} else if child.m == nil {
			child.m, child.implied = &member{typ: typeDir}, true
		}
		cur = child
	}
}

// lookup resolves a volume path to its node, nil when absent.
func (t *tree) lookup(p string) *node {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	if clean == "/" {
		return t.root
	}
	cur := t.root
	for _, c := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		next, ok := cur.children[c]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// entry renders a node as the fsx view of it.
func (n *node) entry() fsx.Entry {
	m := n.m
	e := fsx.Entry{
		Name: n.name, Path: n.path, Allocated: true, Nlink: 1,
		Size: m.size, UID: m.uid, GID: m.gid, Mode: m.mode,
		Mtime: m.mtime, Atime: m.atime, Ctime: m.ctime, LinkTarget: m.link,
	}
	switch m.typ {
	case typeDir:
		e.IsDir, e.Size = true, 0
		e.Mode |= modeDir
	case typeSymlink:
		e.Mode |= modeSymlink
		e.Size = int64(len(m.link)) // the icat precedent: a link's data is its target
	default:
		e.Mode |= modeRegular
	}
	return e
}

// sortedChildren lists a directory's children by name.
func (n *node) sortedChildren() []*node {
	out := make([]*node, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// FS is one tree of a collection as a read-only fsx.FS: the host's files
// (Root) or the collector's output (Meta).
type FS struct {
	t     *tree
	label string
}

// FSTypeRoot and FSTypeMeta are what identify, timeline and the volume
// stack call a collection's two volumes: the host's tree and the
// collector's output.
const (
	FSTypeRoot = "uac"
	FSTypeMeta = "uac-meta"
)

// Info names the backend — the host's tree `uac`, the collector's output
// `uac-meta`, the names identify gives the two volumes, so a timeline row
// says which it came from; a collection carries no filesystem UUID or label.
func (f *FS) Info() fsx.Info {
	if f.label == "meta" {
		return fsx.Info{Type: FSTypeMeta}
	}
	return fsx.Info{Type: FSTypeRoot}
}

// ReadDir lists a directory, sorted by name.
func (f *FS) ReadDir(dir string) ([]fsx.Entry, error) {
	n := f.t.lookup(dir)
	if n == nil {
		return nil, fmt.Errorf("%s: no such file or directory", dir)
	}
	if n.m.typ != typeDir {
		return nil, fmt.Errorf("%s: not a directory", dir)
	}
	children := n.sortedChildren()
	out := make([]fsx.Entry, 0, len(children))
	for _, c := range children {
		out = append(out, c.entry())
	}
	return out, nil
}

// Stat returns one entry's metadata, the symlink unfollowed.
func (f *FS) Stat(p string) (fsx.Entry, error) {
	n := f.t.lookup(p)
	if n == nil {
		return fsx.Entry{}, fmt.Errorf("%s: no such file or directory", p)
	}
	return n.entry(), nil
}

// Open reads a regular file's bytes, or a symlink's target text (the icat
// precedent the ext4 backend follows).
func (f *FS) Open(p string) (io.ReadCloser, error) {
	n := f.t.lookup(p)
	if n == nil {
		return nil, fmt.Errorf("%s: no such file or directory", p)
	}
	switch n.m.typ {
	case typeDir:
		return nil, fmt.Errorf("%s: is a directory", p)
	case typeSymlink:
		return io.NopCloser(strings.NewReader(n.m.link)), nil
	}
	if n.m.open == nil {
		return nil, fmt.Errorf("%s: no content in the archive", p)
	}
	return n.m.open()
}

// Walk streams every entry depth-first, children by name, with an opener
// on the regular files alone.
func (f *FS) Walk(fn func(e fsx.Entry, open func() (io.ReadCloser, error)) error) error {
	var walk func(n *node) error
	walk = func(n *node) error {
		for _, c := range n.sortedChildren() {
			var open func() (io.ReadCloser, error)
			if c.m.typ == typeFile && c.m.open != nil {
				open = c.m.open
			}
			if err := fn(c.entry(), open); err != nil {
				return err
			}
			if c.m.typ == typeDir {
				if err := walk(c); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(f.t.root)
}

// Members is the number of archive members placed in this tree.
func (f *FS) Members() int { return f.t.n }
