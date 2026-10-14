package uac

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSpoolWriteFailureIsNotTruncation: a spool that cannot be written (a
// full TMPDIR) fails Open outright, where a gzip stream that ends early
// still indexes what landed and says so (TestTruncatedTarGz). Passing the
// first off as the second would hand materialise a partial tree with a
// clean exit.
func TestSpoolWriteFailureIsNotTruncation(t *testing.T) {
	saved := spoolTemp
	t.Cleanup(func() { spoolTemp = saved })
	// an unwritable spool: a real temp file, opened read-only
	spoolTemp = func() (*os.File, error) {
		p := filepath.Join(t.TempDir(), "spool.tar")
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			return nil, err
		}
		return os.Open(p)
	}
	b := writeTar(t, fixtures(noisyLog(64<<10)), true)
	a, err := Open(bytes.NewReader(b), int64(len(b)))
	if err == nil {
		a.Close()
		t.Fatal("Open succeeded on an unwritable spool")
	}
	if !strings.Contains(err.Error(), "spool") {
		t.Errorf("error = %v, want the spool named", err)
	}
}

// TestSpoolCopyTellsReadFromWrite: the copy reports a cut gzip stream on
// the read side and a full sink on the write side, never one for the other.
func TestSpoolCopyTellsReadFromWrite(t *testing.T) {
	whole := writeTar(t, fixtures(noisyLog(64<<10)), true)
	zr, err := gzip.NewReader(bytes.NewReader(whole[:len(whole)/2]))
	if err != nil {
		t.Fatal(err)
	}
	n, rerr, werr := spoolCopy(io.Discard, zr)
	if werr != nil || rerr == nil || n == 0 {
		t.Errorf("cut stream: n=%d read=%v write=%v", n, rerr, werr)
	}
	zr, err = gzip.NewReader(bytes.NewReader(whole))
	if err != nil {
		t.Fatal(err)
	}
	n, rerr, werr = spoolCopy(&fullWriter{room: 10}, zr)
	if rerr != nil || werr == nil || n != 10 {
		t.Errorf("full sink: n=%d read=%v write=%v", n, rerr, werr)
	}
	// a whole stream into a roomy sink: neither
	zr, _ = gzip.NewReader(bytes.NewReader(whole))
	if n, rerr, werr = spoolCopy(io.Discard, zr); rerr != nil || werr != nil || n == 0 {
		t.Errorf("whole stream: n=%d read=%v write=%v", n, rerr, werr)
	}
}

// fullWriter accepts room bytes, then fails like a full filesystem.
type fullWriter struct{ room int }

func (w *fullWriter) Write(p []byte) (int, error) {
	if len(p) > w.room {
		n := w.room
		w.room = 0
		return n, errors.New("write: no space left on device")
	}
	w.room -= len(p)
	return len(p), nil
}

// TestInfoNamesTheVolume: the host's tree is `uac`, the collector's output
// `uac-meta` — the names identify gives the two volumes.
func TestInfoNamesTheVolume(t *testing.T) {
	a := openFixture(t, containers[1])
	if got := a.Root().Info().Type; got != FSTypeRoot {
		t.Errorf("Root().Info().Type = %q, want %q", got, FSTypeRoot)
	}
	if got := a.Meta().Info().Type; got != FSTypeMeta {
		t.Errorf("Meta().Info().Type = %q, want %q", got, FSTypeMeta)
	}
}
