// Package decmpfs decodes Apple's transparent file compression, shared by
// the APFS and HFS+ backends: a file flagged UF_COMPRESSED keeps its bytes in
// the "com.apple.decmpfs" extended attribute — a 16-byte header, then inline
// data for the chunk types — or in the "com.apple.ResourceFork" attribute as
// a table of 64 KiB chunks (zlib, LZVN, LZFSE or raw). Each chunk is decoded
// on demand, so a multi-gigabyte compressed file never lands in memory whole.
// The filesystem hands over the attribute bytes and a lazy opener for the
// resource fork; everything else is format.
package decmpfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/get-sybers/gomount/lzfse"
)

const (
	// Magic is the header signature: "fpmc" as stored, "cmpf" little-endian.
	Magic = 0x636d7066
	// HeaderSize is the fixed header: magic, type, uncompressed size.
	HeaderSize = 16

	TypeUncompressed   = 1
	TypeZlibInline     = 3
	TypeZlibRsrc       = 4
	TypeZeros          = 5
	TypeLZVNInline     = 7
	TypeLZVNRsrc       = 8
	TypeRawInline      = 9
	TypeRawRsrc        = 10
	TypeLZFSEInline    = 11
	TypeLZFSERsrc      = 12
	TypeLZBitmapInline = 13
	TypeLZBitmapRsrc   = 14

	// AttrName and RsrcName are the two attributes the format lives in.
	AttrName = "com.apple.decmpfs"
	RsrcName = "com.apple.ResourceFork"

	chunkSize     = 65536
	zlibRsrcTable = 0x104 // where the zlib resource fork's chunk table sits
)

// Header is the parsed decmpfs attribute.
type Header struct {
	Type   uint32
	Size   int64  // uncompressed size
	Inline []byte // the bytes after the header (the inline types' payload)
}

// Parse reads the attribute; ok is false when the bytes are not a decmpfs
// header at all (then the file's data fork is its content).
func Parse(attr []byte) (h Header, ok bool) {
	if len(attr) < HeaderSize || binary.LittleEndian.Uint32(attr) != Magic {
		return Header{}, false
	}
	return Header{
		Type:   binary.LittleEndian.Uint32(attr[4:]),
		Size:   int64(binary.LittleEndian.Uint64(attr[8:])),
		Inline: attr[HeaderSize:],
	}, true
}

// InRsrc reports whether the type keeps its chunks in the resource fork.
func (h Header) InRsrc() bool {
	switch h.Type {
	case TypeZlibRsrc, TypeLZVNRsrc, TypeRawRsrc, TypeLZFSERsrc, TypeLZBitmapRsrc:
		return true
	}
	return false
}

// Reader returns the decompressed content as an io.ReaderAt of Size bytes.
// fork opens the resource fork (its reader and size) and is called only for
// the resource-fork types.
func (h Header) Reader(fork func() (io.ReaderAt, int64, error)) (io.ReaderAt, int64, error) {
	if h.Size < 0 {
		return nil, 0, fmt.Errorf("decmpfs: negative size")
	}
	switch h.Type {
	case TypeUncompressed, TypeRawInline:
		return bytes.NewReader(clip(h.Inline, h.Size)), int64(len(clip(h.Inline, h.Size))), nil
	case TypeZeros:
		return zeros{size: h.Size}, h.Size, nil
	case TypeZlibInline, TypeLZVNInline, TypeLZFSEInline:
		out, err := DecodeChunk(h.Type, h.Inline, h.Size)
		if err != nil {
			return nil, 0, err
		}
		return bytes.NewReader(out), int64(len(out)), nil
	case TypeZlibRsrc, TypeLZVNRsrc, TypeRawRsrc, TypeLZFSERsrc:
		if fork == nil {
			return nil, 0, fmt.Errorf("decmpfs: compressed into a resource fork it does not have")
		}
		ra, size, err := fork()
		if err != nil {
			return nil, 0, err
		}
		cr, err := NewChunkReader(h.Type, ra, size, h.Size)
		if err != nil {
			return nil, 0, err
		}
		return cr, h.Size, nil
	case TypeLZBitmapInline, TypeLZBitmapRsrc:
		return nil, 0, fmt.Errorf("decmpfs: LZBITMAP compression is not supported")
	}
	return nil, 0, fmt.Errorf("decmpfs: unknown type %d", h.Type)
}

// zeros is the content of a type-5 file: Size zero bytes.
type zeros struct{ size int64 }

func (z zeros) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("decmpfs: negative offset")
	}
	if off >= z.size {
		return 0, io.EOF
	}
	n := len(p)
	if rem := z.size - off; rem < int64(n) {
		n = int(rem)
	}
	for i := range p[:n] {
		p[i] = 0
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// DecodeChunk decodes one chunk of the given family into at most size
// bytes. Each family marks an uncompressed chunk with a leading byte.
func DecodeChunk(typ uint32, b []byte, size int64) ([]byte, error) {
	if size > chunkSize*16 && (typ == TypeLZVNInline || typ == TypeLZFSEInline || typ == TypeZlibInline) {
		// an inline chunk is a small file; a huge claimed size is corruption
		return nil, fmt.Errorf("decmpfs: inline chunk claims %d bytes", size)
	}
	if size < 0 {
		return nil, fmt.Errorf("decmpfs: negative chunk size")
	}
	if len(b) == 0 {
		return []byte{}, nil
	}
	switch typ {
	case TypeZlibInline, TypeZlibRsrc:
		if b[0]&0x0f == 0x0f {
			return clip(b[1:], size), nil
		}
		zr, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("decmpfs zlib: %w", err)
		}
		defer zr.Close()
		out := make([]byte, size)
		n, err := io.ReadFull(zr, out)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return nil, fmt.Errorf("decmpfs zlib: %w", err)
		}
		return out[:n], nil
	case TypeLZVNInline, TypeLZVNRsrc:
		if b[0] == 0x06 {
			return clip(b[1:], size), nil
		}
		out := make([]byte, size)
		n, err := lzfse.DecodeLZVN(out, b)
		if err != nil {
			return nil, fmt.Errorf("decmpfs lzvn: %w", err)
		}
		return out[:n], nil
	case TypeLZFSEInline, TypeLZFSERsrc:
		if b[0] == 0xff {
			return clip(b[1:], size), nil
		}
		out := make([]byte, size)
		n, err := lzfse.Decode(out, b)
		if err != nil {
			return nil, fmt.Errorf("decmpfs lzfse: %w", err)
		}
		return out[:n], nil
	case TypeRawInline, TypeRawRsrc:
		if b[0] == 0xcc {
			return clip(b[1:], size), nil
		}
		return clip(b, size), nil
	}
	return nil, fmt.Errorf("decmpfs: type %d has no chunk decoder", typ)
}

func clip(b []byte, size int64) []byte {
	if size < 0 {
		return b[:0]
	}
	if int64(len(b)) > size {
		return b[:size]
	}
	return b
}

// ChunkReader decodes a resource fork's 64 KiB chunks on demand.
type ChunkReader struct {
	typ    uint32
	fork   io.ReaderAt
	size   int64      // uncompressed file size
	chunks [][2]int64 // (offset, length) of each compressed chunk in the fork
	last   int
	cache  []byte
}

// NewChunkReader parses the fork's chunk table for the family typ.
func NewChunkReader(typ uint32, fork io.ReaderAt, forkSize, size int64) (*ChunkReader, error) {
	cr := &ChunkReader{typ: typ, fork: fork, size: size, last: -1}
	le := binary.LittleEndian
	nChunks := int((size + chunkSize - 1) / chunkSize)
	switch typ {
	case TypeZlibRsrc:
		// the resource fork: a 256-byte big-endian header, then at 0x100 the
		// data length and at 0x104 the chunk table (count, then offset/size
		// pairs relative to the table), little-endian
		hdr := make([]byte, 8)
		if _, err := fork.ReadAt(hdr, zlibRsrcTable-4); err != nil {
			return nil, fmt.Errorf("decmpfs zlib fork: read table: %w", err)
		}
		n := int(le.Uint32(hdr[4:]))
		if n <= 0 || n > 1<<20 || n < nChunks {
			return nil, fmt.Errorf("decmpfs zlib fork: %d chunks for %d bytes", n, size)
		}
		tbl := make([]byte, 8*n)
		if _, err := fork.ReadAt(tbl, zlibRsrcTable+4); err != nil && err != io.EOF {
			return nil, fmt.Errorf("decmpfs zlib fork: read table: %w", err)
		}
		for i := 0; i < n; i++ {
			off := int64(le.Uint32(tbl[8*i:])) + zlibRsrcTable
			ln := int64(le.Uint32(tbl[8*i+4:]))
			if off < 0 || ln < 0 || off+ln > forkSize {
				return nil, fmt.Errorf("decmpfs zlib fork: chunk %d out of range", i)
			}
			cr.chunks = append(cr.chunks, [2]int64{off, ln})
		}
	default:
		// LZVN/LZFSE/raw forks: a table of little-endian offsets, the first
		// being the table's own size; chunk i spans [off[i], off[i+1])
		first := make([]byte, 4)
		if _, err := fork.ReadAt(first, 0); err != nil {
			return nil, fmt.Errorf("decmpfs fork: read table: %w", err)
		}
		tblLen := int64(le.Uint32(first))
		n := int(tblLen/4) - 1
		if tblLen < 8 || tblLen > forkSize || n <= 0 || n > 1<<20 || n < nChunks {
			return nil, fmt.Errorf("decmpfs fork: %d chunks for %d bytes", n, size)
		}
		tbl := make([]byte, tblLen)
		if _, err := fork.ReadAt(tbl, 0); err != nil && err != io.EOF {
			return nil, fmt.Errorf("decmpfs fork: read table: %w", err)
		}
		for i := 0; i < n; i++ {
			off := int64(le.Uint32(tbl[4*i:]))
			end := int64(le.Uint32(tbl[4*i+4:]))
			if off < 0 || end < off || end > forkSize {
				return nil, fmt.Errorf("decmpfs fork: chunk %d out of range", i)
			}
			cr.chunks = append(cr.chunks, [2]int64{off, end - off})
		}
	}
	return cr, nil
}

func (cr *ChunkReader) chunk(i int) ([]byte, error) {
	if i == cr.last {
		return cr.cache, nil
	}
	if i < 0 || i >= len(cr.chunks) {
		return nil, fmt.Errorf("decmpfs: chunk %d of %d", i, len(cr.chunks))
	}
	want := int64(chunkSize)
	if rem := cr.size - int64(i)*chunkSize; rem < want {
		want = rem
	}
	raw := make([]byte, cr.chunks[i][1])
	if _, err := cr.fork.ReadAt(raw, cr.chunks[i][0]); err != nil && err != io.EOF {
		return nil, fmt.Errorf("decmpfs: read chunk %d: %w", i, err)
	}
	out, err := DecodeChunk(cr.typ, raw, want)
	if err != nil {
		return nil, fmt.Errorf("chunk %d: %w", i, err)
	}
	cr.last, cr.cache = i, out
	return out, nil
}

// ReadAt implements io.ReaderAt over the decoded content.
func (cr *ChunkReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("decmpfs: negative offset")
	}
	total := 0
	for len(p) > 0 {
		if off >= cr.size {
			return total, io.EOF
		}
		i := int(off / chunkSize)
		within := int(off % chunkSize)
		c, err := cr.chunk(i)
		if err != nil {
			return total, err
		}
		if within >= len(c) {
			// a chunk decoded short: the rest of it is unrecoverable
			return total, fmt.Errorf("decmpfs: chunk %d decoded to %d bytes, %d wanted", i, len(c), within+1)
		}
		n := copy(p, c[within:])
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}
