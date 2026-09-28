// Apple Data Compression (ADC), the LZ77 scheme of UDCO disk images, decode
// only. Written from the format's public description; gomount's own code.
//
// An ADC stream is a sequence of opcodes, each told apart by its first byte:
//
//	1xxxxxxx                     literal: the next (x+1) bytes, 1..128
//	01xxxxxx hhhhhhhh llllllll   match: (x+4) bytes, 4..67, from distance
//	                             (h<<8|l)+1 back in the output
//	00xxxxyy llllllll            match: (x+3) bytes, 3..18, from distance
//	                             (y<<8|l)+1 back in the output
//
// A match may overlap the bytes it produces (distance 1 repeats one byte).
package image

import (
	"errors"
	"fmt"
)

var errADCTruncated = errors.New("adc: source truncated")

// adcDecode decodes an ADC stream from src into dst and returns the number of
// bytes written. Decoding stops when src is exhausted or dst is full; a match
// reaching before the start of dst, or output that would overrun dst, is an
// error — never a panic.
func adcDecode(dst, src []byte) (int, error) {
	sp, dp := 0, 0
	for sp < len(src) && dp < len(dst) {
		op := src[sp]
		var n, dist int
		switch {
		case op&0x80 != 0: // literal run
			n = int(op&0x7f) + 1
			sp++
			if sp+n > len(src) {
				return dp, errADCTruncated
			}
			if dp+n > len(dst) {
				return dp, fmt.Errorf("adc: literal of %d bytes overruns the output at %d", n, dp)
			}
			copy(dst[dp:], src[sp:sp+n])
			sp += n
			dp += n
			continue
		case op&0x40 != 0: // three-byte match
			if sp+3 > len(src) {
				return dp, errADCTruncated
			}
			n = int(op&0x3f) + 4
			dist = (int(src[sp+1])<<8 | int(src[sp+2])) + 1
			sp += 3
		default: // two-byte match
			if sp+2 > len(src) {
				return dp, errADCTruncated
			}
			n = int(op>>2&0x0f) + 3
			dist = (int(op&0x03)<<8 | int(src[sp+1])) + 1
			sp += 2
		}
		if dist > dp {
			return dp, fmt.Errorf("adc: match distance %d reaches before the output start (at %d)", dist, dp)
		}
		if dp+n > len(dst) {
			return dp, fmt.Errorf("adc: match of %d bytes overruns the output at %d", n, dp)
		}
		for i := 0; i < n; i++ { // byte by byte: a match may overlap itself
			dst[dp+i] = dst[dp-dist+i]
		}
		dp += n
	}
	return dp, nil
}
