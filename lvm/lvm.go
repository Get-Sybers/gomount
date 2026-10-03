// Package lvm reads LVM2 physical-volume labels and the VG text metadata
// (docs/linux §5.2), and assembles logical volumes — linear and striped
// segments — into bounded io.ReaderAt views, so the container-peeling
// layer between partition and fsx can descend into a volume group
// without device-mapper, privilege, or a kernel. Read-only: checksums
// are not verified, structure is bounds-checked, and an LV whose PVs are
// not all present reports exactly that.
package lvm

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	labelID   = "LABELONE"
	labelType = "LVM2 001"
	fmttMagic = " LVM2 x[5A%r0N*>"
	sector    = 512
)

// PV is one discovered physical volume: where it sits in the image and
// the VG metadata text its metadata area holds.
type PV struct {
	UUID   string // 32-char LVM uuid, no dashes
	Offset int64  // absolute byte offset of the PV (its containing volume)
	Size   int64
	ra     io.ReaderAt // bounded to the PV
	seqno  int64
	vgName string
	text   string
}

// IsPV reports whether a bounded volume starts with an LVM2 label (in
// one of its first four sectors, per the format).
func IsPV(ra io.ReaderAt, size int64) bool {
	_, ok := findLabel(ra, size)
	return ok
}

func findLabel(ra io.ReaderAt, size int64) (int64, bool) {
	for s := int64(0); s < 4; s++ {
		off := s * sector
		if off+sector > size {
			break
		}
		b := make([]byte, sector)
		if _, err := io.ReadFull(io.NewSectionReader(ra, off, sector), b); err != nil {
			return 0, false
		}
		if string(b[0:8]) == labelID && string(b[24:32]) == labelType {
			return off, true
		}
	}
	return 0, false
}

// ProbePV reads one volume's PV label, header and current metadata text.
// ra must be bounded to the volume; absOffset records where that volume
// sits in the evidence image (for reporting).
func ProbePV(ra io.ReaderAt, size, absOffset int64) (*PV, error) {
	labelOff, ok := findLabel(ra, size)
	if !ok {
		return nil, fmt.Errorf("lvm: no PV label")
	}
	lb := make([]byte, sector)
	if _, err := io.ReadFull(io.NewSectionReader(ra, labelOff, sector), lb); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	pvhOff := int64(le.Uint32(lb[20:24])) // offset of pv_header within the label sector
	if pvhOff < 32 || pvhOff+40 > sector {
		return nil, fmt.Errorf("lvm: implausible pv_header offset %d", pvhOff)
	}
	ph := lb[pvhOff:]
	pv := &PV{
		UUID:   string(ph[0:32]),
		Offset: absOffset,
		Size:   size,
		ra:     ra,
	}
	// After uuid + device_size: the data-area list then the metadata-area
	// list, each {offset u64, size u64} and zero-terminated.
	pos := int(pvhOff) + 32 + 8
	skipList := func() error {
		for {
			if pos+16 > sector {
				return fmt.Errorf("lvm: disk_locn list runs off the label sector")
			}
			off := le.Uint64(lb[pos:])
			sz := le.Uint64(lb[pos+8:])
			pos += 16
			if off == 0 && sz == 0 {
				return nil
			}
		}
	}
	if err := skipList(); err != nil { // data areas
		return nil, err
	}
	// first metadata area
	if pos+16 > sector {
		return nil, fmt.Errorf("lvm: missing metadata area list")
	}
	mdaOff := int64(le.Uint64(lb[pos:]))
	mdaSize := int64(le.Uint64(lb[pos+8:]))
	if mdaOff == 0 || mdaSize < sector || mdaOff+mdaSize > size {
		return nil, fmt.Errorf("lvm: no usable metadata area")
	}
	mh := make([]byte, sector)
	if _, err := io.ReadFull(io.NewSectionReader(ra, mdaOff, sector), mh); err != nil {
		return nil, err
	}
	if string(mh[4:20]) != fmttMagic {
		return nil, fmt.Errorf("lvm: bad mda magic")
	}
	// raw_locn list at 40: {offset u64 (mda-relative), size u64, checksum
	// u32, flags u32}; the first live entry is the current metadata.
	rlOff := int64(le.Uint64(mh[40:]))
	rlSize := int64(le.Uint64(mh[48:]))
	if rlOff <= 0 || rlSize <= 0 || rlSize > 16<<20 || rlOff+rlSize > mdaSize {
		return nil, fmt.Errorf("lvm: no current metadata text")
	}
	// The text is a circular buffer entry; the common case is contiguous.
	txt := make([]byte, rlSize)
	if _, err := io.ReadFull(io.NewSectionReader(ra, mdaOff+rlOff, rlSize), txt); err != nil {
		return nil, err
	}
	pv.text = strings.TrimRight(string(txt), "\x00")
	name, root, err := parseConfig(pv.text)
	if err != nil {
		return nil, fmt.Errorf("lvm: metadata text: %w", err)
	}
	pv.vgName = name
	pv.seqno, _ = root.section(name).int("seqno")
	return pv, nil
}

// ---- the VG view -------------------------------------------------------------

// VG is one assembled volume group.
type VG struct {
	Name       string
	UUID       string
	ExtentSize int64 // bytes
	LVs        []LV
	pvs        map[string]pvRef // metadata pv name ("pv0") -> located PV
	Missing    []string         // pv names the image did not provide
}

type pvRef struct {
	pv      *PV
	peStart int64 // bytes from PV start to the first extent
}

// LV is one logical volume of a VG.
type LV struct {
	Name     string
	UUID     string
	Extents  int64
	Segments []Segment
}

// Segment maps a run of LV extents onto PV areas.
type Segment struct {
	StartExtent int64
	ExtentCount int64
	Type        string // "linear" or "striped" (striped with 1 stripe = linear)
	StripeSize  int64  // bytes, striped only
	Stripes     []Stripe
}

// Stripe is one (pv, starting extent on that pv) leg of a segment.
type Stripe struct {
	PVName  string
	StartPE int64
}

// Assemble groups discovered PVs into VGs, parsing each group's highest-
// seqno metadata text.
func Assemble(pvs []*PV) ([]*VG, error) {
	byVG := map[string][]*PV{}
	for _, pv := range pvs {
		byVG[pv.vgName] = append(byVG[pv.vgName], pv)
	}
	var names []string
	for n := range byVG {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []*VG
	for _, name := range names {
		group := byVG[name]
		best := group[0]
		for _, pv := range group[1:] {
			if pv.seqno > best.seqno {
				best = pv
			}
		}
		vg, err := buildVG(name, best.text, group)
		if err != nil {
			return nil, fmt.Errorf("vg %s: %w", name, err)
		}
		out = append(out, vg)
	}
	return out, nil
}

func buildVG(name, text string, found []*PV) (*VG, error) {
	_, root, err := parseConfig(text)
	if err != nil {
		return nil, err
	}
	vgSec := root.section(name)
	if vgSec == nil {
		return nil, fmt.Errorf("metadata lacks the vg section")
	}
	vg := &VG{Name: name, pvs: map[string]pvRef{}}
	vg.UUID, _ = vgSec.str("id")
	extSectors, err := vgSec.int("extent_size")
	if err != nil || extSectors <= 0 {
		return nil, fmt.Errorf("bad extent_size")
	}
	vg.ExtentSize = extSectors * sector

	byUUID := map[string]*PV{}
	for _, pv := range found {
		byUUID[strings.ReplaceAll(pv.UUID, "-", "")] = pv
	}
	pvsSec := vgSec.section("physical_volumes")
	if pvsSec == nil {
		return nil, fmt.Errorf("metadata lacks physical_volumes")
	}
	for _, pvName := range pvsSec.subsections() {
		ps := pvsSec.section(pvName)
		// The fields that place bytes fail FAST: a zero-value fallback here
		// would silently assemble the wrong offsets on corrupt metadata.
		id, ok := ps.str("id")
		if !ok || id == "" {
			return nil, fmt.Errorf("pv %s: metadata lacks its id", pvName)
		}
		peStart, err := ps.int("pe_start") // sectors
		if err != nil || peStart < 0 {
			return nil, fmt.Errorf("pv %s: bad pe_start in metadata", pvName)
		}
		pv := byUUID[strings.ReplaceAll(id, "-", "")]
		if pv == nil {
			vg.Missing = append(vg.Missing, pvName)
			continue
		}
		vg.pvs[pvName] = pvRef{pv: pv, peStart: peStart * sector}
	}

	lvsSec := vgSec.section("logical_volumes")
	if lvsSec == nil {
		return vg, nil
	}
	for _, lvName := range lvsSec.subsections() {
		ls := lvsSec.section(lvName)
		lv := LV{Name: lvName}
		lv.UUID, _ = ls.str("id") // cosmetic: identify output only
		nSegs, err := ls.int("segment_count")
		if err != nil || nSegs <= 0 {
			return nil, fmt.Errorf("lv %s: bad segment_count in metadata", lvName)
		}
		for i := int64(1); i <= nSegs; i++ {
			ss := ls.section(fmt.Sprintf("segment%d", i))
			if ss == nil {
				return nil, fmt.Errorf("lv %s missing segment%d", lvName, i)
			}
			// Byte-placing fields again: fail fast, never map from zeros.
			seg := Segment{}
			if seg.StartExtent, err = ss.int("start_extent"); err != nil || seg.StartExtent < 0 {
				return nil, fmt.Errorf("lv %s segment%d: bad start_extent", lvName, i)
			}
			if seg.ExtentCount, err = ss.int("extent_count"); err != nil || seg.ExtentCount <= 0 {
				return nil, fmt.Errorf("lv %s segment%d: bad extent_count", lvName, i)
			}
			var ok bool
			if seg.Type, ok = ss.str("type"); !ok || seg.Type == "" {
				return nil, fmt.Errorf("lv %s segment%d: missing type", lvName, i)
			}
			stripeSectors, _ := ss.int("stripe_size") // Reader validates it where striping needs it
			seg.StripeSize = stripeSectors * sector
			stripes, err := ss.stripes()
			if err != nil {
				return nil, fmt.Errorf("lv %s segment%d: %w", lvName, i, err)
			}
			seg.Stripes = stripes
			lv.Segments = append(lv.Segments, seg)
			if end := seg.StartExtent + seg.ExtentCount; end > lv.Extents {
				lv.Extents = end
			}
		}
		vg.LVs = append(vg.LVs, lv)
	}
	sort.Slice(vg.LVs, func(i, j int) bool { return vg.LVs[i].Name < vg.LVs[j].Name })
	return vg, nil
}

// Reader assembles the LV's byte view. It errors when the LV touches a
// PV the image did not provide, or a segment type this reader does not
// map (thin, cache, RAID targets are later phases).
func (vg *VG) Reader(lv LV) (io.ReaderAt, int64, error) {
	for _, seg := range lv.Segments {
		switch seg.Type {
		case "striped", "linear":
		default:
			return nil, 0, fmt.Errorf("lv %s: segment type %q not supported", lv.Name, seg.Type)
		}
		if len(seg.Stripes) == 0 {
			return nil, 0, fmt.Errorf("lv %s: segment without stripes", lv.Name)
		}
		if seg.Type == "striped" && len(seg.Stripes) > 1 && seg.StripeSize <= 0 {
			return nil, 0, fmt.Errorf("lv %s: striped segment without stripe_size", lv.Name)
		}
		for _, st := range seg.Stripes {
			if _, ok := vg.pvs[st.PVName]; !ok {
				return nil, 0, fmt.Errorf("lv %s: pv %s not present in the image", lv.Name, st.PVName)
			}
		}
	}
	return &lvReader{vg: vg, lv: lv}, lv.Extents * vg.ExtentSize, nil
}

type lvReader struct {
	vg *VG
	lv LV
}

func (r *lvReader) ReadAt(p []byte, off int64) (int, error) {
	size := r.lv.Extents * r.vg.ExtentSize
	if off >= size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) && off < size {
		n, err := r.readOnce(p[total:], off)
		if n == 0 && err == nil {
			err = io.ErrNoProgress
		}
		total += n
		off += int64(n)
		if err != nil {
			return total, err
		}
	}
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

// readOnce maps one contiguous run at LV offset off.
func (r *lvReader) readOnce(p []byte, off int64) (int, error) {
	eb := r.vg.ExtentSize
	ext := off / eb
	for _, seg := range r.lv.Segments {
		if ext < seg.StartExtent || ext >= seg.StartExtent+seg.ExtentCount {
			continue
		}
		segOff := off - seg.StartExtent*eb
		if len(seg.Stripes) == 1 {
			st := seg.Stripes[0]
			ref := r.vg.pvs[st.PVName]
			pvOff := ref.peStart + st.StartPE*eb + segOff
			run := seg.ExtentCount*eb - segOff
			return boundedRead(ref.pv.ra, ref.pv.Size, pvOff, p, run)
		}
		// striped: stripe_size chunks round-robin across the legs; each
		// leg holds extent_count/len(stripes) extents.
		n := int64(len(seg.Stripes))
		cs := seg.StripeSize
		chunk := segOff / cs
		inChunk := segOff % cs
		leg := seg.Stripes[chunk%n]
		legChunk := chunk / n
		ref := r.vg.pvs[leg.PVName]
		pvOff := ref.peStart + leg.StartPE*eb + legChunk*cs + inChunk
		run := cs - inChunk
		if max := seg.ExtentCount*eb - segOff; run > max {
			run = max
		}
		return boundedRead(ref.pv.ra, ref.pv.Size, pvOff, p, run)
	}
	return 0, fmt.Errorf("lvm: lv %s: extent %d unmapped", r.lv.Name, ext)
}

func boundedRead(ra io.ReaderAt, pvSize, pvOff int64, p []byte, run int64) (int, error) {
	if int64(len(p)) < run {
		run = int64(len(p))
	}
	if pvOff < 0 || pvOff+run > pvSize {
		return 0, fmt.Errorf("lvm: mapped read outside its PV")
	}
	return io.NewSectionReader(ra, pvOff, run).Read(p[:run])
}

// ---- the LVM2 text-config parser ---------------------------------------------

// node is one parsed config section: values and subsections in order.
type node struct {
	values map[string]any // string, int64, or []any
	subs   map[string]*node
	order  []string
}

func newNode() *node { return &node{values: map[string]any{}, subs: map[string]*node{}} }

func (n *node) section(name string) *node {
	if n == nil {
		return nil
	}
	return n.subs[name]
}

func (n *node) subsections() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, k := range n.order {
		if _, ok := n.subs[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

func (n *node) str(key string) (string, bool) {
	if n == nil {
		return "", false
	}
	s, ok := n.values[key].(string)
	return s, ok
}

func (n *node) int(key string) (int64, error) {
	if n == nil {
		return 0, fmt.Errorf("no section")
	}
	v, ok := n.values[key].(int64)
	if !ok {
		return 0, fmt.Errorf("%s: not an integer", key)
	}
	return v, nil
}

// stripes decodes the `stripes = ["pv0", 0, "pv1", 0]` pair list.
func (n *node) stripes() ([]Stripe, error) {
	if n == nil {
		return nil, fmt.Errorf("no section")
	}
	raw, ok := n.values["stripes"].([]any)
	if !ok {
		return nil, fmt.Errorf("stripes: missing")
	}
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("stripes: odd list")
	}
	var out []Stripe
	for i := 0; i < len(raw); i += 2 {
		name, ok1 := raw[i].(string)
		pe, ok2 := raw[i+1].(int64)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("stripes: bad pair at %d", i)
		}
		out = append(out, Stripe{PVName: name, StartPE: pe})
	}
	return out, nil
}

// parseConfig parses the LVM2 text format and returns the VG name (the
// single top-level section) and the root node.
func parseConfig(text string) (string, *node, error) {
	p := &parser{s: text}
	root := newNode()
	if err := p.parseInto(root, 0); err != nil {
		return "", nil, err
	}
	for _, k := range root.order {
		if _, ok := root.subs[k]; ok {
			return k, root, nil
		}
	}
	return "", nil, fmt.Errorf("no vg section found")
}

type parser struct {
	s   string
	pos int
}

func (p *parser) parseInto(n *node, depth int) error {
	if depth > 16 {
		return fmt.Errorf("config nested too deep")
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.s) {
			return nil
		}
		if p.s[p.pos] == '}' {
			p.pos++
			return nil
		}
		ident := p.ident()
		if ident == "" {
			return fmt.Errorf("expected identifier at %d", p.pos)
		}
		p.skipSpace()
		if p.pos < len(p.s) && p.s[p.pos] == '{' {
			p.pos++
			child := newNode()
			if err := p.parseInto(child, depth+1); err != nil {
				return err
			}
			n.subs[ident] = child
			n.order = append(n.order, ident)
			continue
		}
		if p.pos >= len(p.s) || p.s[p.pos] != '=' {
			return fmt.Errorf("expected '=' after %q at %d", ident, p.pos)
		}
		p.pos++
		p.skipSpace()
		v, err := p.value()
		if err != nil {
			return err
		}
		n.values[ident] = v
		n.order = append(n.order, ident)
	}
}

func (p *parser) skipSpace() {
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == '#' {
			for p.pos < len(p.s) && p.s[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			p.pos++
			continue
		}
		return
	}
}

func (p *parser) ident() string {
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '=' ||
			c == '{' || c == '}' || c == ',' || c == '[' || c == ']' || c == '"' {
			break
		}
		p.pos++
	}
	return p.s[start:p.pos]
}

func (p *parser) value() (any, error) {
	if p.pos >= len(p.s) {
		return nil, fmt.Errorf("expected value at end")
	}
	switch p.s[p.pos] {
	case '"':
		return p.quoted()
	case '[':
		p.pos++
		var list []any
		for {
			p.skipSpace()
			if p.pos >= len(p.s) {
				return nil, fmt.Errorf("unterminated list")
			}
			if p.s[p.pos] == ']' {
				p.pos++
				return list, nil
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
	default:
		tok := p.ident()
		iv, err := strconv.ParseInt(tok, 10, 64)
		if err != nil {
			return tok, nil // bare word (status flags etc.)
		}
		return iv, nil
	}
}

func (p *parser) quoted() (string, error) {
	p.pos++ // opening quote
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != '"' {
		p.pos++
	}
	if p.pos >= len(p.s) {
		return "", fmt.Errorf("unterminated string")
	}
	s := p.s[start:p.pos]
	p.pos++
	return s, nil
}
