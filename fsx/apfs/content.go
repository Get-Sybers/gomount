package apfs

import (
	"bytes"
	"fmt"
	"io"

	"github.com/get-sybers/gomount/fsx/decmpfs"
)

// File content: a data fork is the file extents of the inode's private
// (data-stream) id, holes reading as zeros. A decmpfs-compressed file
// (bsd_flags UF_COMPRESSED) keeps its bytes in the "com.apple.decmpfs"
// attribute or the "com.apple.ResourceFork" attribute's data stream; the
// shared fsx/decmpfs package decodes them (zlib, LZVN, LZFSE, raw).
const maxInlineStream = 64 << 20 // an inline attribute held in a data stream is read whole, up to this

// extentReader serves a data stream's extents as one io.ReaderAt.
type extentReader struct {
	v    *Volume
	exts []extent
	size int64
}

func (r *extentReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("apfs: negative offset")
	}
	total := 0
	bs := r.v.c.blockSize
	for len(p) > 0 {
		if off >= r.size {
			return total, io.EOF
		}
		n := int64(len(p))
		if off+n > r.size {
			n = r.size - off
		}
		// the extent covering off; a gap between extents is a hole
		var e *extent
		var next int64 = r.size
		for i := range r.exts {
			x := &r.exts[i]
			if uint64(off) >= x.logical && uint64(off) < x.logical+x.length {
				e = x
				break
			}
			if x.logical > uint64(off) && int64(x.logical) < next {
				next = int64(x.logical)
			}
		}
		if e == nil {
			if next-off < n {
				n = next - off
			}
			for i := range p[:n] {
				p[i] = 0
			}
		} else {
			within := off - int64(e.logical)
			if int64(e.length)-within < n {
				n = int64(e.length) - within
			}
			if e.paddr == 0 {
				for i := range p[:n] {
					p[i] = 0
				}
			} else {
				got, err := r.v.c.br.ra.ReadAt(p[:n], int64(e.paddr)*bs+within)
				if err != nil && int64(got) < n {
					return total + got, fmt.Errorf("apfs: read extent at block %d: %w", e.paddr, err)
				}
			}
		}
		total += int(n)
		p = p[n:]
		off += n
	}
	return total, nil
}

// streamReader opens a data stream (an inode's private id or an
// attribute's stream id) of a known size.
func (v *Volume) streamReader(streamID uint64, size int64) (io.ReaderAt, error) {
	exts, err := v.extents(streamID)
	if err != nil {
		return nil, err
	}
	return &extentReader{v: v, exts: exts, size: size}, nil
}

// readStream reads a whole (bounded) data stream into memory.
func (v *Volume) readStream(streamID uint64, size, limit int64) ([]byte, error) {
	if size < 0 || size > limit {
		return nil, fmt.Errorf("apfs: stream %d of %d bytes exceeds the %d-byte limit", streamID, size, limit)
	}
	ra, err := v.streamReader(streamID, size)
	if err != nil {
		return nil, err
	}
	b := make([]byte, size)
	if _, err := ra.ReadAt(b, 0); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}

// contentReader returns the file's bytes as an io.ReaderAt and their size,
// decompressing a decmpfs file transparently.
func (v *Volume) contentReader(in *inode) (io.ReaderAt, int64, error) {
	if in.bsdFlags&ufCompressed != 0 {
		if ra, size, err := v.decmpfsReader(in); err == nil {
			return ra, size, nil
		} else if x, xerr := v.xattr(in.id, xattrDecmpfs); xerr != nil {
			return nil, 0, xerr // the attribute could not even be read
		} else if x != nil {
			return nil, 0, err // it IS compressed and we could not decode it: say so
		}
		// the flag without the attribute: fall through to the data fork
	}
	if v.info.Encrypted {
		return nil, 0, fmt.Errorf("apfs: volume %q is encrypted (FileVault); file content is not readable", v.info.Name)
	}
	ra, err := v.streamReader(in.privateID, in.size)
	if err != nil {
		return nil, 0, err
	}
	return ra, in.size, nil
}

// decmpfsAttr returns the decmpfs attribute's bytes (embedded or streamed).
func (v *Volume) decmpfsAttr(in *inode) ([]byte, error) {
	x, err := v.xattr(in.id, xattrDecmpfs)
	if err != nil {
		return nil, err
	}
	if x == nil {
		return nil, fmt.Errorf("apfs: inode %d is flagged compressed but has no decmpfs attribute", in.id)
	}
	if x.data != nil {
		return x.data, nil
	}
	return v.readStream(x.streamID, x.size, maxInlineStream)
}

// compressedSize reads the uncompressed size off the decmpfs header.
func (v *Volume) compressedSize(in *inode) (int64, bool) {
	b, err := v.decmpfsAttr(in)
	if err != nil {
		return 0, false
	}
	h, ok := decmpfs.Parse(b)
	if !ok {
		return 0, false
	}
	return h.Size, true
}

func (v *Volume) decmpfsReader(in *inode) (io.ReaderAt, int64, error) {
	attr, err := v.decmpfsAttr(in)
	if err != nil {
		return nil, 0, err
	}
	h, ok := decmpfs.Parse(attr)
	if !ok {
		return nil, 0, fmt.Errorf("apfs: inode %d: decmpfs attribute without the cmpf header", in.id)
	}
	fork := func() (io.ReaderAt, int64, error) {
		x, err := v.xattr(in.id, xattrRsrc)
		if err != nil {
			return nil, 0, err
		}
		if x == nil {
			return nil, 0, fmt.Errorf("apfs: inode %d: compressed into a resource fork it does not have", in.id)
		}
		if x.data != nil {
			return bytes.NewReader(x.data), int64(len(x.data)), nil
		}
		ra, err := v.streamReader(x.streamID, x.size)
		if err != nil {
			return nil, 0, err
		}
		return ra, x.size, nil
	}
	ra, size, err := h.Reader(fork)
	if err != nil {
		return nil, 0, fmt.Errorf("apfs: inode %d: %w", in.id, err)
	}
	return ra, size, nil
}
