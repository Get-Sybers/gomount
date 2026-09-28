// Package lzfse decodes Apple's LZFSE and LZVN streams — the compressors
// behind APFS decmpfs (types 7/8 LZVN, 11/12 LZFSE), Apple archives and
// the LZFSE container's bvx blocks. Pure Go ports of Apple's reference
// implementation (github.com/lzfse/lzfse, Copyright (c) 2015-2016 Apple
// Inc., BSD-3-Clause — the licence is reproduced in the repository's
// THIRD_PARTY_NOTICES.md); decode only, whole-buffer: the caller knows the
// uncompressed size, so every routine fills a caller-sized destination and
// reports how much of it was written.
package lzfse

import (
	"errors"
	"fmt"
)

// ErrTruncated is returned when the source ends before the stream does.
var ErrTruncated = errors.New("lzvn: source truncated")

// DecodeLZVN decodes one LZVN stream from src into dst and returns the
// number of bytes written. A stream ends at its end-of-stream opcode (0x06)
// or when dst is full; a match reaching before the start of dst, or an
// undefined opcode, is an error.
func DecodeLZVN(dst, src []byte) (int, error) { return decodeLZVNAt(dst, 0, src) }

// decodeLZVNAt decodes into dst from position start on and returns the
// bytes written past start; matches may reach back into dst[:start], the
// output of the earlier blocks of the same LZFSE stream (the reference
// decoder's dst_begin is the start of the whole stream's output).
func decodeLZVNAt(dst []byte, start int, src []byte) (int, error) {
	var (
		sp     int     // position in src
		dp     = start // position in dst
		d      int     // distance of the last match
		L, M   int     // literal and match lengths of the current op
		opcLen int     // bytes the opcode itself occupies
	)
	extract := func(v byte, lsb, width uint) int { return int((v >> lsb) & (1<<width - 1)) }

	copyLiteral := func() error {
		// the opcode's literal follows it; the source must also hold the
		// first byte of the next opcode (a valid stream ends in eos)
		if len(src)-sp <= opcLen+L {
			return ErrTruncated
		}
		sp += opcLen
		if L > len(dst)-dp {
			L = len(dst) - dp // destination full: take what fits
		}
		copy(dst[dp:dp+L], src[sp:sp+L])
		dp += L
		sp += L
		return nil
	}
	copyMatch := func() error {
		if d == 0 || d > dp {
			return fmt.Errorf("lzvn: match distance %d out of range at %d", d, dp)
		}
		if M > len(dst)-dp {
			M = len(dst) - dp
		}
		for i := 0; i < M; i++ { // byte-wise: overlapping matches splat
			dst[dp+i] = dst[dp+i-d]
		}
		dp += M
		return nil
	}

	for {
		if dp >= len(dst) {
			return dp - start, nil
		}
		if sp >= len(src) {
			return dp - start, ErrTruncated
		}
		opc := src[sp]
		switch kind := lzvnOpcode(opc); kind {
		case opEOS:
			return dp - start, nil
		case opNop:
			sp++
			continue
		case opUndef:
			return dp - start, fmt.Errorf("lzvn: undefined opcode %#x at %d", opc, sp)
		case opSmlD:
			// LLMMMDDD DDDDDDDD LITERAL
			opcLen = 2
			L = extract(opc, 6, 2)
			M = extract(opc, 3, 3) + 3
			if len(src)-sp <= opcLen+L {
				return dp - start, ErrTruncated
			}
			d = extract(opc, 0, 3)<<8 | int(src[sp+1])
		case opMedD:
			// 101LLMMM DDDDDDMM DDDDDDDD LITERAL
			opcLen = 3
			L = extract(opc, 3, 2)
			if len(src)-sp <= opcLen+L {
				return dp - start, ErrTruncated
			}
			opc23 := int(src[sp+1]) | int(src[sp+2])<<8
			M = (extract(opc, 0, 3)<<2 | (opc23 & 3)) + 3
			d = (opc23 >> 2) & 0x3fff
		case opLrgD:
			// LLMMM111 DDDDDDDD DDDDDDDD LITERAL
			opcLen = 3
			L = extract(opc, 6, 2)
			M = extract(opc, 3, 3) + 3
			if len(src)-sp <= opcLen+L {
				return dp - start, ErrTruncated
			}
			d = int(src[sp+1]) | int(src[sp+2])<<8
		case opPreD:
			// LLMMM110 LITERAL — the previous distance again
			opcLen = 1
			L = extract(opc, 6, 2)
			M = extract(opc, 3, 3) + 3
			if len(src)-sp <= opcLen+L {
				return dp - start, ErrTruncated
			}
		case opSmlM:
			// 1111MMMM: a match at the previous distance
			if len(src)-sp <= 1 {
				return dp - start, ErrTruncated
			}
			M = extract(opc, 0, 4)
			sp++
			if err := copyMatch(); err != nil {
				return dp - start, err
			}
			continue
		case opLrgM:
			// 11110000 MMMMMMMM: [16,271] at the previous distance
			if len(src)-sp <= 2 {
				return dp - start, ErrTruncated
			}
			M = int(src[sp+1]) + 16
			sp += 2
			if err := copyMatch(); err != nil {
				return dp - start, err
			}
			continue
		case opSmlL:
			// 1110LLLL LITERAL
			opcLen = 1
			L = extract(opc, 0, 4)
			if err := copyLiteral(); err != nil {
				return dp - start, err
			}
			continue
		case opLrgL:
			// 11100000 LLLLLLLL LITERAL: [16,271]
			if len(src)-sp <= 2 {
				return dp - start, ErrTruncated
			}
			opcLen = 2
			L = int(src[sp+1]) + 16
			if err := copyLiteral(); err != nil {
				return dp - start, err
			}
			continue
		}
		// literal + match ops
		if err := copyLiteral(); err != nil {
			return dp - start, err
		}
		if dp >= len(dst) {
			return dp - start, nil
		}
		if err := copyMatch(); err != nil {
			return dp - start, err
		}
	}
}

type lzvnOp uint8

const (
	opSmlD lzvnOp = iota
	opMedD
	opLrgD
	opPreD
	opSmlM
	opLrgM
	opSmlL
	opLrgL
	opNop
	opEOS
	opUndef
)

// lzvnOpcode classifies an opcode byte — the reference's 256-entry jump
// table, expressed by the bit patterns that define it.
func lzvnOpcode(opc byte) lzvnOp {
	switch {
	case opc == 0x06:
		return opEOS
	case opc == 0x0e || opc == 0x16:
		return opNop
	case opc >= 0x70 && opc <= 0x7f, opc >= 0xd0 && opc <= 0xdf:
		return opUndef
	case opc >= 0xa0 && opc <= 0xbf:
		return opMedD
	case opc == 0xe0:
		return opLrgL
	case opc >= 0xe1 && opc <= 0xef:
		return opSmlL
	case opc == 0xf0:
		return opLrgM
	case opc >= 0xf1:
		return opSmlM
	}
	// the LLMMMxxx family: low three bits 111 = large distance, 110 =
	// previous distance (undefined below 0x40), anything else small distance
	switch opc & 7 {
	case 7:
		return opLrgD
	case 6:
		if opc < 0x40 {
			return opUndef
		}
		return opPreD
	}
	return opSmlD
}
