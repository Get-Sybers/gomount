package lzfse

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// lzvn streams built by hand from the opcode grammar: what a decoder must
// produce is fixed by the format, no reference encoder needed.
func TestLZVNHandEncoded(t *testing.T) {
	// "hello, hello, hello!" as: a 7-byte literal, a match of 7 at distance
	// 7 through the previous-distance op, then a 1-byte literal and eos.
	src := []byte{
		0xe7, 'h', 'e', 'l', 'l', 'o', ',', ' ', // sml_l: 7 literal bytes
		0x20, 0x07, // sml_d: L=0 (bits 7-6=00), M=4+3=7 (bits 5-3=100), D=(000<<8)|0x07=7
		0xf5,      // sml_m: M=5 at the previous distance -> "hello"
		0xe1, '!', // sml_l: 1 literal byte
		0x06, // eos
	}
	dst := make([]byte, 64)
	n, err := DecodeLZVN(dst, src)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(dst[:n]); got != "hello, hello, hello!" {
		t.Fatalf("got %q", got)
	}
	// destination sized exactly: the decoder stops without overrunning
	exact := make([]byte, 20)
	if n, err := DecodeLZVN(exact, src); err != nil || n != 20 {
		t.Fatalf("exact-size decode: %d %v", n, err)
	}
	// a match reaching before the output is an error, never a read out of range
	bad := []byte{0x20, 0x50, 0x06} // D = 0x50 with nothing written yet
	if _, err := DecodeLZVN(make([]byte, 16), bad); err == nil {
		t.Fatal("distance beyond the output must error")
	}
	// truncated: no eos and the literal cut short
	if _, err := DecodeLZVN(make([]byte, 16), []byte{0xe7, 'h', 'e'}); err == nil {
		t.Fatal("a truncated literal must error")
	}
}

func TestLZVNOpcodeClasses(t *testing.T) {
	cases := map[byte]lzvnOp{
		0x00: opSmlD, 0x05: opSmlD, 0x06: opEOS, 0x07: opLrgD, 0x0e: opNop, 0x16: opNop,
		0x1e: opUndef, 0x3e: opUndef, 0x46: opPreD, 0x6f: opLrgD, 0x70: opUndef, 0x7f: opUndef,
		0x86: opPreD, 0xa0: opMedD, 0xbf: opMedD, 0xc6: opPreD, 0xcf: opLrgD, 0xd0: opUndef,
		0xdf: opUndef, 0xe0: opLrgL, 0xe1: opSmlL, 0xef: opSmlL, 0xf0: opLrgM, 0xf1: opSmlM, 0xff: opSmlM,
	}
	for opc, want := range cases {
		if got := lzvnOpcode(opc); got != want {
			t.Errorf("opcode %#x: class %d, want %d", opc, got, want)
		}
	}
}

func TestLZFSEContainerBlocks(t *testing.T) {
	// bvx- (raw) block, then a bvxn block wrapping the lzvn stream above,
	// then bvx$
	lzvn := []byte{0xe7, 'h', 'e', 'l', 'l', 'o', ',', ' ', 0x20, 0x07, 0xf5, 0xe1, '!', 0x06}
	var src bytes.Buffer
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr, magicUncompressed)
	binary.LittleEndian.PutUint32(hdr[4:], 6)
	src.Write(hdr)
	src.WriteString("raw...")
	h2 := make([]byte, 12)
	binary.LittleEndian.PutUint32(h2, magicLZVN)
	binary.LittleEndian.PutUint32(h2[4:], 20)
	binary.LittleEndian.PutUint32(h2[8:], uint32(len(lzvn)))
	src.Write(h2)
	src.Write(lzvn)
	end := make([]byte, 4)
	binary.LittleEndian.PutUint32(end, magicEndOfStream)
	src.Write(end)

	dst := make([]byte, 26)
	n, err := Decode(dst, src.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(dst[:n]); got != "raw...hello, hello, hello!" {
		t.Fatalf("got %q", got)
	}
	if _, err := Decode(make([]byte, 8), []byte{1, 2, 3, 4}); err == nil {
		t.Fatal("an unknown magic must error")
	}
}

// The blocks of one LZFSE stream share a history: a match in a later block
// may reach into the output of an earlier one (Apple's decoder bounds the
// distance by the start of the whole output). A DMG's LZFSE chunk — 1 MiB
// in several blocks — depends on it; APFS's 64 KiB decmpfs chunks never did.
func TestLZFSEMatchAcrossBlocks(t *testing.T) {
	var src bytes.Buffer
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr, magicUncompressed)
	binary.LittleEndian.PutUint32(hdr[4:], 6)
	src.Write(hdr)
	src.WriteString("raw...")
	// sml_d: L=0, M=3+3=6 (bits 5-3 = 011), D=6 — entirely the raw block's bytes
	lzvn := []byte{0x18, 0x06, 0x06}
	h2 := make([]byte, 12)
	binary.LittleEndian.PutUint32(h2, magicLZVN)
	binary.LittleEndian.PutUint32(h2[4:], 6)
	binary.LittleEndian.PutUint32(h2[8:], uint32(len(lzvn)))
	src.Write(h2)
	src.Write(lzvn)
	end := make([]byte, 4)
	binary.LittleEndian.PutUint32(end, magicEndOfStream)
	src.Write(end)
	dst := make([]byte, 12)
	n, err := Decode(dst, src.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(dst[:n]); got != "raw...raw..." {
		t.Fatalf("got %q", got)
	}
	// but never before the start of the whole output
	if _, err := DecodeLZVN(make([]byte, 6), []byte{0x18, 0x07, 0x06}); err == nil {
		t.Fatal("a match before the output start must error")
	}
}

// The FSE tables: a frequency table spread over the states decodes every
// symbol back — checked by the invariant the encoder relies on, that each
// state's entry consumes k bits and lands on a valid next state.
func TestFSEDecoderTables(t *testing.T) {
	freq := make([]uint16, litSymbols)
	freq['a'], freq['b'], freq['c'] = 512, 384, 128 // sums to 1024 states
	table, err := initDecoderTable(litStates, litSymbols, freq)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[uint8]int{}
	for s, e := range table {
		counts[e.symbol]++
		next := int(e.delta) + (1 << e.k) - 1 // the largest next state this entry can reach
		if next >= litStates || int(e.delta) < 0 {
			t.Fatalf("state %d: delta %d k %d reaches %d", s, e.delta, e.k, next)
		}
	}
	if counts['a'] != 512 || counts['b'] != 384 || counts['c'] != 128 {
		t.Fatalf("symbol spread: %v", counts)
	}
	over := make([]uint16, litSymbols)
	over[0] = litStates + 1
	if _, err := initDecoderTable(litStates, litSymbols, over); err == nil {
		t.Fatal("a frequency table over the state count must error")
	}
	lfreq := make([]uint16, lSymbols)
	copy(lfreq, []uint16{32, 16, 8, 4, 2, 1, 1})
	vt := initValueDecoderTable(lStates, lSymbols, lfreq, lExtraBits[:], lBaseValue[:])
	if len(vt) != lStates || vt[0].vbase != 0 {
		t.Fatalf("value table: %d entries, first %+v", len(vt), vt[0])
	}
}
