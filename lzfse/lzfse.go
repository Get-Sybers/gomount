package lzfse

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// The bvx block container: a stream is a sequence of blocks, each opening
// with a magic, ending with bvx$.
const (
	magicEndOfStream  = 0x24787662 // bvx$
	magicUncompressed = 0x2d787662 // bvx-
	magicCompressedV1 = 0x31787662 // bvx1: lzfse, uncompressed tables
	magicCompressedV2 = 0x32787662 // bvx2: lzfse, compressed tables
	magicLZVN         = 0x6e787662 // bvxn: lzvn payload

	lSymbols, mSymbols, dSymbols, litSymbols = 20, 20, 64, 256
	lStates, mStates, dStates, litStates     = 64, 64, 256, 1024
	matchesPerBlock                          = 10000
	literalsPerBlock                         = 4 * matchesPerBlock

	headerV1Size = 772 // sizeof(lzfse_compressed_block_header_v1), tail-padded
)

var (
	lExtraBits = [lSymbols]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8}
	lBaseValue = [lSymbols]int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60}
	mExtraBits = [mSymbols]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11}
	mBaseValue = [mSymbols]int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312}
	dExtraBits = [dSymbols]uint8{
		0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
		8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
		12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15}
	dBaseValue = [dSymbols]int32{
		0, 1, 2, 3, 4, 6, 8, 10, 12, 16,
		20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
		124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
		764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
		4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
		24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684,
		131068, 163836, 196604, 229372}

	freqNbitsTable = [32]int8{2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14}
	freqValueTable = [32]int8{0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
		0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1}
)

// blockHeader is the v1 form every compressed block decodes to.
type blockHeader struct {
	nRawBytes, nLiterals, nMatches    uint32
	nLiteralPayloadBytes, nLMDPayload uint32
	literalBits, lmdBits              int32
	literalState                      [4]uint16
	lState, mState, dState            uint16
	lFreq                             [lSymbols]uint16
	mFreq                             [mSymbols]uint16
	dFreq                             [dSymbols]uint16
	literalFreq                       [litSymbols]uint16
}

// Decode decodes one LZFSE stream from src into dst and returns the number
// of bytes written. dst must be sized for the uncompressed data; decoding
// stops when the stream ends (bvx$) or dst is full.
func Decode(dst, src []byte) (int, error) {
	sp, dp := 0, 0
	for {
		if dp >= len(dst) {
			return dp, nil
		}
		if sp+4 > len(src) {
			return dp, fmt.Errorf("lzfse: source truncated at block magic (%d bytes in)", sp)
		}
		magic := binary.LittleEndian.Uint32(src[sp:])
		switch magic {
		case magicEndOfStream:
			return dp, nil
		case magicUncompressed:
			if sp+8 > len(src) {
				return dp, fmt.Errorf("lzfse: truncated uncompressed block header")
			}
			n := int(binary.LittleEndian.Uint32(src[sp+4:]))
			sp += 8
			if n > len(src)-sp {
				n = len(src) - sp
			}
			if n > len(dst)-dp {
				n = len(dst) - dp
			}
			copy(dst[dp:dp+n], src[sp:sp+n])
			sp += n
			dp += n
		case magicLZVN:
			if sp+12 > len(src) {
				return dp, fmt.Errorf("lzfse: truncated lzvn block header")
			}
			nRaw := int(binary.LittleEndian.Uint32(src[sp+4:]))
			nPayload := int(binary.LittleEndian.Uint32(src[sp+8:]))
			sp += 12
			if nPayload > len(src)-sp {
				return dp, fmt.Errorf("lzfse: lzvn payload %d exceeds source", nPayload)
			}
			if nRaw > len(dst)-dp {
				nRaw = len(dst) - dp
			}
			n, err := decodeLZVNAt(dst[:dp+nRaw], dp, src[sp:sp+nPayload])
			if err != nil {
				return dp + n, err
			}
			dp += n
			sp += nPayload
		case magicCompressedV1, magicCompressedV2:
			var h blockHeader
			var headerSize int
			var err error
			if magic == magicCompressedV2 {
				if sp+32 > len(src) {
					return dp, fmt.Errorf("lzfse: truncated v2 block header")
				}
				headerSize = int(binary.LittleEndian.Uint32(src[sp+24:])) // packed_fields[2] low 32 bits
				if headerSize < 32 || sp+headerSize > len(src) {
					return dp, fmt.Errorf("lzfse: v2 header size %d out of range", headerSize)
				}
				h, err = decodeHeaderV2(src[sp : sp+headerSize])
			} else {
				if sp+headerV1Size > len(src) {
					return dp, fmt.Errorf("lzfse: truncated v1 block header")
				}
				headerSize = headerV1Size
				h, err = decodeHeaderV1(src[sp : sp+headerV1Size])
			}
			if err != nil {
				return dp, err
			}
			if err := h.check(); err != nil {
				return dp, err
			}
			blockStart := sp + headerSize
			litEnd := blockStart + int(h.nLiteralPayloadBytes)
			lmdEnd := litEnd + int(h.nLMDPayload)
			if lmdEnd > len(src) {
				return dp, fmt.Errorf("lzfse: block payload exceeds source")
			}
			n, err := decodeBlock(dst, dp, src, &h, blockStart, litEnd, lmdEnd)
			dp += n
			if err != nil {
				return dp, err
			}
			sp = lmdEnd
		default:
			return dp, fmt.Errorf("lzfse: unknown block magic %#x at %d", magic, sp)
		}
	}
}

func decodeHeaderV1(b []byte) (blockHeader, error) {
	le := binary.LittleEndian
	var h blockHeader
	h.nRawBytes = le.Uint32(b[4:])
	h.nLiterals = le.Uint32(b[12:])
	h.nMatches = le.Uint32(b[16:])
	h.nLiteralPayloadBytes = le.Uint32(b[20:])
	h.nLMDPayload = le.Uint32(b[24:])
	h.literalBits = int32(le.Uint32(b[28:]))
	for i := range h.literalState {
		h.literalState[i] = le.Uint16(b[32+2*i:])
	}
	h.lmdBits = int32(le.Uint32(b[40:]))
	h.lState, h.mState, h.dState = le.Uint16(b[44:]), le.Uint16(b[46:]), le.Uint16(b[48:])
	off := 50
	for i := range h.lFreq {
		h.lFreq[i] = le.Uint16(b[off+2*i:])
	}
	off += 2 * lSymbols
	for i := range h.mFreq {
		h.mFreq[i] = le.Uint16(b[off+2*i:])
	}
	off += 2 * mSymbols
	for i := range h.dFreq {
		h.dFreq[i] = le.Uint16(b[off+2*i:])
	}
	off += 2 * dSymbols
	for i := range h.literalFreq {
		h.literalFreq[i] = le.Uint16(b[off+2*i:])
	}
	return h, nil
}

// decodeHeaderV2 unpacks the bit-packed v2 header and its compressed
// frequency tables into the v1 form.
func decodeHeaderV2(b []byte) (blockHeader, error) {
	le := binary.LittleEndian
	var h blockHeader
	h.nRawBytes = le.Uint32(b[4:])
	v0, v1, v2 := le.Uint64(b[8:]), le.Uint64(b[16:]), le.Uint64(b[24:])
	field := func(v uint64, off, n uint) uint32 { return uint32((v >> off) & (1<<n - 1)) }
	h.nLiterals = field(v0, 0, 20)
	h.nLiteralPayloadBytes = field(v0, 20, 20)
	h.literalBits = int32(field(v0, 60, 3)) - 7
	h.literalState = [4]uint16{uint16(field(v1, 0, 10)), uint16(field(v1, 10, 10)), uint16(field(v1, 20, 10)), uint16(field(v1, 30, 10))}
	h.nMatches = field(v0, 40, 20)
	h.nLMDPayload = field(v1, 40, 20)
	h.lmdBits = int32(field(v1, 60, 3)) - 7
	h.lState = uint16(field(v2, 32, 10))
	h.mState = uint16(field(v2, 42, 10))
	h.dState = uint16(field(v2, 52, 10))

	// the frequency tables, packed with a small prefix code
	src := b[32:]
	if len(src) == 0 {
		return h, nil // tables omitted
	}
	freqs := make([]uint16, 0, lSymbols+mSymbols+dSymbols+litSymbols)
	var accum uint32
	var accumBits int
	pos := 0
	for i := 0; i < lSymbols+mSymbols+dSymbols+litSymbols; i++ {
		for pos < len(src) && accumBits+8 <= 32 {
			accum |= uint32(src[pos]) << accumBits
			accumBits += 8
			pos++
		}
		low := accum & 31
		n := int(freqNbitsTable[low])
		var v uint32
		switch n {
		case 8:
			v = 8 + (accum>>4)&0xf
		case 14:
			v = 24 + (accum>>4)&0x3ff
		default:
			v = uint32(freqValueTable[low])
		}
		if n > accumBits {
			return h, fmt.Errorf("lzfse: v2 frequency table truncated")
		}
		accum >>= n
		accumBits -= n
		freqs = append(freqs, uint16(v))
	}
	if accumBits >= 8 || pos != len(src) {
		return h, fmt.Errorf("lzfse: v2 frequency table not consumed exactly")
	}
	copy(h.lFreq[:], freqs[:lSymbols])
	copy(h.mFreq[:], freqs[lSymbols:lSymbols+mSymbols])
	copy(h.dFreq[:], freqs[lSymbols+mSymbols:lSymbols+mSymbols+dSymbols])
	copy(h.literalFreq[:], freqs[lSymbols+mSymbols+dSymbols:])
	return h, nil
}

func (h *blockHeader) check() error {
	if h.nLiterals > literalsPerBlock || h.nMatches > matchesPerBlock {
		return fmt.Errorf("lzfse: block counts out of range")
	}
	for _, s := range h.literalState {
		if s >= litStates {
			return fmt.Errorf("lzfse: literal state out of range")
		}
	}
	if h.lState >= lStates || h.mState >= mStates || h.dState >= dStates {
		return fmt.Errorf("lzfse: lmd state out of range")
	}
	sum := func(f []uint16) int {
		n := 0
		for _, x := range f {
			n += int(x)
		}
		return n
	}
	if sum(h.lFreq[:]) > lStates || sum(h.mFreq[:]) > mStates || sum(h.dFreq[:]) > dStates || sum(h.literalFreq[:]) > litStates {
		return fmt.Errorf("lzfse: frequency table exceeds its state count")
	}
	return nil
}

// ---- FSE tables ------------------------------------------------------------

// decoderEntry is a literal decoder entry: bits to read, symbol, state delta.
type decoderEntry struct {
	k      uint8
	symbol uint8
	delta  int16
}

func initDecoderTable(nstates, nsymbols int, freq []uint16) ([]decoderEntry, error) {
	t := make([]decoderEntry, 0, nstates)
	nclz := bits.LeadingZeros32(uint32(nstates))
	sum := 0
	for i := 0; i < nsymbols; i++ {
		f := int(freq[i])
		if f == 0 {
			continue
		}
		sum += f
		if sum > nstates {
			return nil, fmt.Errorf("lzfse: frequencies exceed %d states", nstates)
		}
		k := bits.LeadingZeros32(uint32(f)) - nclz
		j0 := ((2 * nstates) >> k) - f
		for j := 0; j < f; j++ {
			if j < j0 {
				t = append(t, decoderEntry{k: uint8(k), symbol: uint8(i), delta: int16(((f + j) << k) - nstates)})
			} else {
				t = append(t, decoderEntry{k: uint8(k - 1), symbol: uint8(i), delta: int16((j - j0) << (k - 1))})
			}
		}
	}
	for len(t) < nstates {
		t = append(t, decoderEntry{})
	}
	return t, nil
}

// valueEntry decodes an L, M or D value: state bits plus extra value bits.
type valueEntry struct {
	totalBits uint8
	valueBits uint8
	delta     int16
	vbase     int32
}

func initValueDecoderTable(nstates, nsymbols int, freq []uint16, vbits []uint8, vbase []int32) []valueEntry {
	t := make([]valueEntry, 0, nstates)
	nclz := bits.LeadingZeros32(uint32(nstates))
	for i := 0; i < nsymbols; i++ {
		f := int(freq[i])
		if f == 0 {
			continue
		}
		k := bits.LeadingZeros32(uint32(f)) - nclz
		j0 := ((2 * nstates) >> k) - f
		for j := 0; j < f; j++ {
			e := valueEntry{valueBits: vbits[i], vbase: vbase[i]}
			if j < j0 {
				e.totalBits = uint8(k) + e.valueBits
				e.delta = int16(((f + j) << k) - nstates)
			} else {
				e.totalBits = uint8(k-1) + e.valueBits
				e.delta = int16((j - j0) << (k - 1))
			}
			t = append(t, e)
		}
	}
	for len(t) < nstates {
		t = append(t, valueEntry{})
	}
	return t
}

// ---- the backward bit stream ---------------------------------------------------

// inStream reads bits backwards from the end of a payload, the way the
// encoder wrote them: a 64-bit accumulator refilled a byte at a time from
// decreasing addresses.
type inStream struct {
	src       []byte
	start     int // no byte before this may be read
	pos       int // next refill reads the bytes just before pos
	accum     uint64
	accumBits int
}

func (s *inStream) load8(at int) uint64 {
	var b [8]byte
	end := at + 8
	if end > len(s.src) {
		end = len(s.src)
	}
	if at < 0 || at >= end {
		return 0
	}
	copy(b[:], s.src[at:end])
	return binary.LittleEndian.Uint64(b[:])
}

// init positions the stream: n is the header's bit count in [-7, 0].
func (s *inStream) init(n int32, end int) error {
	s.pos = end
	if n != 0 {
		if s.pos < s.start+8 {
			return fmt.Errorf("lzfse: bit stream shorter than its header claims")
		}
		s.pos -= 8
		s.accum = s.load8(s.pos)
		s.accumBits = int(n) + 64
	} else {
		if s.pos < s.start+7 {
			return fmt.Errorf("lzfse: bit stream shorter than its header claims")
		}
		s.pos -= 7
		s.accum = s.load8(s.pos) & 0xffffffffffffff
		s.accumBits = int(n) + 56
	}
	if s.accumBits < 56 || s.accumBits >= 64 || s.accum>>uint(s.accumBits) != 0 {
		return fmt.Errorf("lzfse: bit stream header inconsistent")
	}
	return nil
}

// flush refills the accumulator to at least 56 bits.
func (s *inStream) flush() error {
	nbits := (63 - s.accumBits) &^ 7
	at := s.pos - nbits>>3
	if at < s.start {
		return fmt.Errorf("lzfse: bit stream underrun")
	}
	s.pos = at
	incoming := s.load8(at)
	s.accum = s.accum<<uint(nbits) | incoming&(1<<uint(nbits)-1)
	s.accumBits += nbits
	return nil
}

func (s *inStream) pull(n int) uint64 {
	s.accumBits -= n
	result := s.accum >> uint(s.accumBits)
	s.accum &= 1<<uint(s.accumBits) - 1
	return result
}

func (s *inStream) decode(state *uint16, t []decoderEntry) uint8 {
	e := t[*state]
	*state = uint16(int(e.delta) + int(s.pull(int(e.k))))
	return e.symbol
}

func (s *inStream) valueDecode(state *uint16, t []valueEntry) int32 {
	e := t[*state]
	v := uint32(s.pull(int(e.totalBits)))
	*state = uint16(int(e.delta) + int(v>>e.valueBits))
	return e.vbase + int32(v&(1<<e.valueBits-1))
}

// decodeBlock decodes one lzfse compressed block's literals then its
// (L, M, D) triples into dst from position start on and returns the bytes
// written past start. A match may reach back into dst[:start]: an LZFSE
// stream's blocks share one history (the reference decoder bounds D by the
// start of the whole output, not of the block), which a multi-block stream
// such as a DMG's 1 MiB LZFSE chunk relies on.
func decodeBlock(dst []byte, start int, src []byte, h *blockHeader, blockStart, litEnd, lmdEnd int) (int, error) {
	litTable, err := initDecoderTable(litStates, litSymbols, h.literalFreq[:])
	if err != nil {
		return 0, err
	}
	lTable := initValueDecoderTable(lStates, lSymbols, h.lFreq[:], lExtraBits[:], lBaseValue[:])
	mTable := initValueDecoderTable(mStates, mSymbols, h.mFreq[:], mExtraBits[:], mBaseValue[:])
	dTable := initValueDecoderTable(dStates, dSymbols, h.dFreq[:], dExtraBits[:], dBaseValue[:])

	// literals: four interleaved FSE states, read backwards from the end of
	// the literal payload (which may reach back to the start of the source)
	literals := make([]byte, int(h.nLiterals)+64)
	in := inStream{src: src, start: 0}
	if err := in.init(h.literalBits, litEnd); err != nil {
		return 0, err
	}
	st := h.literalState
	for i := 0; i < int(h.nLiterals); i += 4 {
		if err := in.flush(); err != nil {
			return 0, err
		}
		literals[i] = in.decode(&st[0], litTable)
		literals[i+1] = in.decode(&st[1], litTable)
		literals[i+2] = in.decode(&st[2], litTable)
		literals[i+3] = in.decode(&st[3], litTable)
	}

	// the L/M/D stream, read backwards from the end of the lmd payload
	lmd := inStream{src: src, start: litEnd}
	if err := lmd.init(h.lmdBits, lmdEnd); err != nil {
		return 0, err
	}
	lState, mState, dState := h.lState, h.mState, h.dState
	lit, dp := 0, start
	D := int32(-1)
	for n := h.nMatches; n > 0; n-- {
		if err := lmd.flush(); err != nil {
			return dp - start, err
		}
		L := int(lmd.valueDecode(&lState, lTable))
		if lit+L > int(h.nLiterals) { // the declared count, not the padded buffer
			return dp - start, fmt.Errorf("lzfse: literal run exceeds the block's literals")
		}
		M := int(lmd.valueDecode(&mState, mTable))
		if nd := lmd.valueDecode(&dState, dTable); nd != 0 {
			D = nd
		}
		if int(D) > dp+L {
			return dp - start, fmt.Errorf("lzfse: match distance %d reaches before the output", D)
		}
		// literal run
		if L > len(dst)-dp {
			L = len(dst) - dp
		}
		copy(dst[dp:dp+L], literals[lit:lit+L])
		dp += L
		lit += L
		if dp >= len(dst) {
			return dp - start, nil
		}
		// match
		if M > len(dst)-dp {
			M = len(dst) - dp
		}
		d := int(D)
		for i := 0; i < M; i++ {
			dst[dp+i] = dst[dp+i-d]
		}
		dp += M
		if dp >= len(dst) {
			return dp - start, nil
		}
	}
	return dp - start, nil
}
