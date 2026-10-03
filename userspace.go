// Userspace backend: pure in-process NTFS parsing with go-ntfs, no mount, no
// FUSE, no kernel driver, no privilege. These verbs (ls, cat, stat, tree,
// browse, stream) open the image O_RDONLY and read the NTFS filesystem through
// the volumeFS contract (ntfsfs.FS in production, a stub in tests); a parser bug
// is a Go panic, not host code execution, and the whole path runs in an
// unprivileged container with neither /dev/fuse nor /dev/kvm. The `mount`
// subcommand is the other backend: the direct ntfs-3g + FUSE mount.
//
// The verbs speak to volumeFS and fileEntry, this package's own view of the
// filesystem, so the operator/tool logic and its stub tests do not move when the
// ntfsfs backend struct does; ntfsbind.go is the single adapter onto ntfsfs.
package main

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// fileEntry is the CLI's view of one volume entry, decoupled from the
// concrete backends (ntfsfs on the Windows side, the fsx backends on the
// Linux side). A named alternate data stream is carried in Streams (and
// read as "file:stream"); the POSIX identity fields stay zero on NTFS,
// and Streams stays empty on the Linux filesystems — honest nulls both
// ways.
type fileEntry struct {
	Name    string   // leaf name (long name preferred over the 8.3 short name)
	Path    string   // full "/"-separated path from the volume root
	IsDir   bool     // a directory
	Size    int64    // logical byte length of the default (unnamed) content
	MFTID   string   // MFT/inode identity, rendered so the CLI is agnostic to its form
	Deleted bool     // an unallocated (unlinked/deleted) entry
	Streams []string // named alternate data streams on this file, if any

	Btime time.Time // created (crtime)
	Mtime time.Time // file-altered (modified)
	Ctime time.Time // metadata changed
	Atime time.Time // file-accessed

	// the POSIX side (fsx backends; zero on NTFS)
	UID        uint32
	GID        uint32
	Mode       uint32
	Inode      uint64
	Nlink      uint32
	LinkTarget string // symlink target, unfollowed
}

// volumeFS is the read-only NTFS contract the userspace verbs consume. The
// ntfsbind adapter satisfies it over a real image; the test stub satisfies it in
// memory. Open opens a file (or, via a "path:stream" suffix, a named ADS). Walk
// streams every regular file to fn with a lazy opener, returning a *walkPartial
// when the backend skipped unreadable records.
type volumeFS interface {
	ReadDir(dir string) ([]fileEntry, error)
	Stat(p string) (fileEntry, error)
	Open(p string) (io.ReadCloser, error)
	Walk(fn func(e fileEntry, open func() (io.ReadCloser, error)) error) error
}

// walkPartial reports that a Walk finished but skipped some unreadable entries.
// The stream verb folds its count into the run summary rather than failing.
type walkPartial struct {
	count int
	msg   string
}

func (w *walkPartial) Error() string { return w.msg }

// ---- ls ---------------------------------------------------------------------

func runLs(argv []string) int {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	long := fs.Bool("l", false, "long listing: type, size, mtime, name")
	deleted := fs.Bool("deleted", false, "also list unallocated (deleted) entries")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "gomount ls: usage: ls [--volume N] [-l] [--deleted] <image> [path]")
		return 1
	}
	dir := "/"
	if fs.NArg() == 2 {
		dir = fs.Arg(1)
	}
	fsys, closer, err := openVolumeFS(fs.Arg(0), *volume, *lvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closer()
	if err := listDir(os.Stdout, fsys, dir, *long, *deleted); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	return 0
}

// listDir prints the directory listing, sorted by name for stable output. Each
// named ADS is shown on its own line as name:stream. Deleted entries are shown
// (and marked) only when showDeleted is set.
func listDir(w io.Writer, fsys volumeFS, dir string, long, showDeleted bool) error {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return err
	}
	sortEntries(entries)
	for _, e := range entries {
		if e.Deleted && !showDeleted {
			continue
		}
		lsLines(w, e, long)
	}
	return nil
}

// lsLines writes the entry and its ADS lines, long or short.
func lsLines(w io.Writer, e fileEntry, long bool) {
	if long {
		fmt.Fprintf(w, "%s %12d  %s  %s\n", typeCol(e), e.Size, tsCol(e.Mtime), nameCol(e))
		for _, s := range e.Streams {
			// Per-stream size is not carried on fileEntry; "-" is an honest unknown.
			fmt.Fprintf(w, "%s %12s  %s  %s\n", "-", "-", tsCol(e.Mtime), e.Name+":"+s)
		}
		return
	}
	fmt.Fprintln(w, nameCol(e))
	for _, s := range e.Streams {
		fmt.Fprintln(w, e.Name+":"+s)
	}
}

// ---- cat --------------------------------------------------------------------

func runCat(argv []string) int {
	fs := flag.NewFlagSet("cat", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "gomount cat: usage: cat [--volume N] <image> <path[:stream]>")
		return 1
	}
	fsys, closer, err := openVolumeFS(fs.Arg(0), *volume, *lvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closer()
	if err := catFile(os.Stdout, fsys, fs.Arg(1)); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	return 0
}

// catFile streams a file's (or named ADS's) bytes to w. io.Copy bounds memory to
// its internal buffer regardless of file size.
func catFile(w io.Writer, fsys volumeFS, p string) error {
	r, err := fsys.Open(p)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = io.Copy(w, r)
	return err
}

// ---- stat -------------------------------------------------------------------

func runStat(argv []string) int {
	fs := flag.NewFlagSet("stat", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "gomount stat: usage: stat [--volume N] <image> <path>")
		return 1
	}
	fsys, closer, err := openVolumeFS(fs.Arg(0), *volume, *lvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closer()
	e, err := fsys.Stat(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	printStat(os.Stdout, e)
	return 0
}

// printStat writes one metadata field per line.
func printStat(w io.Writer, e fileEntry) {
	kind := "file"
	if e.IsDir {
		kind = "directory"
	}
	fmt.Fprintf(w, "Path:       %s\n", e.Path)
	fmt.Fprintf(w, "Name:       %s\n", e.Name)
	fmt.Fprintf(w, "Type:       %s\n", kind)
	fmt.Fprintf(w, "Size:       %d\n", e.Size)
	fmt.Fprintf(w, "MFTId:      %s\n", e.MFTID)
	if e.Deleted {
		fmt.Fprintln(w, "Deleted:    true")
	}
	fmt.Fprintf(w, "Created:    %s\n", tsCol(e.Btime))
	fmt.Fprintf(w, "Modified:   %s\n", tsCol(e.Mtime))
	fmt.Fprintf(w, "Accessed:   %s\n", tsCol(e.Atime))
	fmt.Fprintf(w, "MFTChanged: %s\n", tsCol(e.Ctime))
	if len(e.Streams) > 0 {
		fmt.Fprintf(w, "Streams:    %s\n", strings.Join(e.Streams, ", "))
	}
}

// ---- tree -------------------------------------------------------------------

func runTree(argv []string) int {
	fs := flag.NewFlagSet("tree", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	depth := fs.Int("depth", -1, "maximum recursion depth (default -1 = unlimited)")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "gomount tree: usage: tree [--volume N] [--depth D] <image> [path]")
		return 1
	}
	dir := "/"
	if fs.NArg() == 2 {
		dir = fs.Arg(1)
	}
	fsys, closer, err := openVolumeFS(fs.Arg(0), *volume, *lvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closer()
	if err := treeDir(os.Stdout, fsys, dir, 0, *depth, ""); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	return 0
}

// treeDir prints an indented recursive listing, stopping at maxDepth (< 0 =
// unlimited). A per-directory read error is reported inline and does not abort
// siblings already printed above it. A named ADS shows as "file:stream".
func treeDir(w io.Writer, fsys volumeFS, dir string, depth, maxDepth int, prefix string) error {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(w, "%s[unreadable: %v]\n", prefix, err)
		return nil
	}
	sortEntries(entries)
	for _, e := range entries {
		fmt.Fprintf(w, "%s%s\n", prefix, nameCol(e))
		for _, s := range e.Streams {
			fmt.Fprintf(w, "%s%s\n", prefix, e.Name+":"+s)
		}
		if e.IsDir && (maxDepth < 0 || depth < maxDepth) {
			if err := treeDir(w, fsys, path.Join(dir, e.Name), depth+1, maxDepth, prefix+"  "); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- browse -----------------------------------------------------------------

func runBrowse(argv []string) int {
	fs := flag.NewFlagSet("browse", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gomount browse: usage: browse [--volume N] <image>")
		return 1
	}
	fsys, closer, err := openVolumeFS(fs.Arg(0), *volume, *lvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closer()
	return browse(fsys, os.Stdin, os.Stdout, os.Stderr)
}

// browse is a dependency-light REPL over the volume: ls, cd, cat, stat, get,
// pwd, help, quit. Paths are resolved against the current directory. Pure
// stdin/stdout — no terminal control, no TUI library.
func browse(fsys volumeFS, in io.Reader, out, errOut io.Writer) int {
	cwd := "/"
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	fmt.Fprint(out, "gomount browse — userspace NTFS, read-only. Type `help`.\n")
	fmt.Fprintf(out, "%s> ", cwd)
	for sc.Scan() {
		// A single path argument is the whole remainder of the line — NTFS names
		// carry spaces ("Program Files", "Documents and Settings") — so a path
		// verb takes the rest verbatim, no quoting needed.
		cmd, rest := splitFirst(sc.Text())
		if cmd == "" {
			fmt.Fprintf(out, "%s> ", cwd)
			continue
		}
		quit := false
		switch cmd {
		case "quit", "exit", "q":
			quit = true
		case "help", "?":
			browseHelp(out)
		case "pwd":
			fmt.Fprintln(out, cwd)
		case "ls":
			target := cwd
			if rest != "" {
				target = resolvePath(cwd, rest)
			}
			if err := listDir(out, fsys, target, true, true); err != nil {
				fmt.Fprintf(errOut, "ls: %v\n", err)
			}
		case "cd":
			if rest == "" {
				fmt.Fprintln(errOut, "cd: usage: cd <dir>")
				break
			}
			target := resolvePath(cwd, rest)
			e, err := fsys.Stat(target)
			if err != nil {
				fmt.Fprintf(errOut, "cd: %v\n", err)
				break
			}
			if !e.IsDir {
				fmt.Fprintf(errOut, "cd: %s: not a directory\n", target)
				break
			}
			cwd = target
		case "cat":
			if rest == "" {
				fmt.Fprintln(errOut, "cat: usage: cat <file[:stream]>")
				break
			}
			if err := catFile(out, fsys, resolvePath(cwd, rest)); err != nil {
				fmt.Fprintf(errOut, "cat: %v\n", err)
			}
		case "stat":
			if rest == "" {
				fmt.Fprintln(errOut, "stat: usage: stat <path>")
				break
			}
			e, err := fsys.Stat(resolvePath(cwd, rest))
			if err != nil {
				fmt.Fprintf(errOut, "stat: %v\n", err)
				break
			}
			printStat(out, e)
		case "get":
			// Two arguments: quote a source or local path that holds spaces.
			args := splitArgs(rest)
			if len(args) != 2 {
				fmt.Fprintln(errOut, "get: usage: get <file[:stream]> <localpath>  (quote paths with spaces)")
				break
			}
			n, err := getFile(fsys, resolvePath(cwd, args[0]), args[1])
			if err != nil {
				fmt.Fprintf(errOut, "get: %v\n", err)
				break
			}
			fmt.Fprintf(out, "wrote %d bytes to %s\n", n, args[1])
		default:
			fmt.Fprintf(errOut, "unknown command %q (try `help`)\n", cmd)
		}
		if quit {
			break
		}
		fmt.Fprintf(out, "%s> ", cwd)
	}
	fmt.Fprintln(out)
	return 0
}

func browseHelp(out io.Writer) {
	fmt.Fprint(out, `commands:
  ls [dir]            list a directory (deleted entries included; ADS as name:stream)
  cd <dir>            change directory
  cat <file[:stream]> write a file (or ADS) to the screen
  stat <path>         show entry metadata
  get <file> <local>  export a file to a local path
  pwd                 print the current directory
  help                this help
  quit                leave (also: exit, q)
`)
}

// getFile exports a volume file to a local path (the local path is on the host;
// the image is only ever read).
func getFile(fsys volumeFS, src, localPath string) (int64, error) {
	r, err := fsys.Open(src)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	out, err := os.Create(localPath)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(out, r)
	closeErr := out.Close()
	if copyErr != nil {
		return n, copyErr
	}
	return n, closeErr
}

// ---- stream -----------------------------------------------------------------

// streamRecord is one --jsonl line: the tool-facing per-file record.
type streamRecord struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mtime string `json:"mtime"`
	MFTID string `json:"mftid"`
}

// streamSummary is the one-line stderr summary printed when a stream finishes.
type streamSummary struct {
	Files  int   `json:"files"`
	Bytes  int64 `json:"bytes"`
	Errors int   `json:"errors"`
}

func runStream(argv []string) int {
	fs := flag.NewFlagSet("stream", flag.ExitOnError)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	filter := fs.String("filter", "", "glob over the base name, or over the path when it contains '/' (default: all files)")
	jsonl := fs.Bool("jsonl", false, "emit one JSON object per file instead of a tar stream")
	fs.Usage = usage
	_ = fs.Parse(argv)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gomount stream: usage: stream [--volume N] [--filter GLOB] [--jsonl] <image>")
		return 1
	}
	if _, err := path.Match(*filter, ""); err != nil {
		fmt.Fprintf(os.Stderr, "gomount stream: invalid --filter pattern %q: %v\n", *filter, err)
		return 1
	}
	fsys, closer, err := openVolumeFS(fs.Arg(0), *volume, *lvName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	defer closer()
	sum, err := streamVolume(os.Stdout, os.Stderr, fsys, *filter, *jsonl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}
	line, _ := json.Marshal(sum)
	fmt.Fprintln(os.Stderr, string(line))
	if sum.Errors > 0 {
		return 2
	}
	return 0
}

// streamVolume walks every regular file in the volume and feeds the (filtered)
// files to a downstream tool: as a tar stream on w, or as one JSON object per
// line when jsonl is set. It keeps going past a per-file error, counting it, and
// returns the running totals. Memory is bounded — files stream through, never
// buffered whole. A backend that skipped unreadable records (walkPartial) folds
// into Errors rather than failing.
func streamVolume(w, errOut io.Writer, fsys volumeFS, filter string, jsonl bool) (streamSummary, error) {
	var sum streamSummary
	var tw *tar.Writer
	if !jsonl {
		tw = tar.NewWriter(w)
	}
	enc := json.NewEncoder(w)

	walkErr := fsys.Walk(func(e fileEntry, open func() (io.ReadCloser, error)) error {
		if !matchGlob(filter, e.Path) {
			return nil
		}
		if jsonl {
			if err := enc.Encode(streamRecord{Path: e.Path, Size: e.Size, Mtime: tsCol(e.Mtime), MFTID: e.MFTID}); err != nil {
				return err // a stdout write failure is fatal to the stream
			}
			sum.Files++
			sum.Bytes += e.Size
			return nil
		}
		n, err := tarFile(tw, open, e)
		if err != nil {
			sum.Errors++
			fmt.Fprintf(errOut, "gomount stream: %s: %v\n", e.Path, err)
			return nil
		}
		sum.Files++
		sum.Bytes += n
		return nil
	})
	if tw != nil {
		if err := tw.Close(); err != nil && walkErr == nil {
			walkErr = err
		}
	}
	// A partial walk (records the backend could not read) is not fatal: fold its
	// count into the summary and let the stream stand.
	var wp *walkPartial
	if errors.As(walkErr, &wp) {
		sum.Errors += wp.count
		fmt.Fprintf(errOut, "gomount stream: %s\n", wp.msg)
		walkErr = nil
	}
	return sum, walkErr
}

// tarFile writes one file into the tar stream and returns the bytes declared.
// The entry is read-only (mode 0400). The body is written to exactly the entry's
// reported size — over-long content is truncated by the LimitReader and a short
// stream is zero-padded — so one odd file cannot desynchronise the tar stream.
func tarFile(tw *tar.Writer, open func() (io.ReadCloser, error), e fileEntry) (int64, error) {
	r, err := open()
	if err != nil {
		return 0, err
	}
	defer r.Close()
	hdr := &tar.Header{
		Name:    strings.TrimPrefix(e.Path, "/"),
		Size:    e.Size,
		Mode:    0o400,
		ModTime: e.Mtime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return 0, err
	}
	written, err := io.Copy(tw, io.LimitReader(r, e.Size))
	if err != nil {
		return written, err
	}
	if written < e.Size {
		if perr := padZeros(tw, e.Size-written); perr != nil {
			return written, perr
		}
	}
	return e.Size, nil
}

// padZeros writes n zero bytes to w in bounded chunks (never allocating n).
func padZeros(w io.Writer, n int64) error {
	var zero [32 * 1024]byte
	for n > 0 {
		chunk := int64(len(zero))
		if chunk > n {
			chunk = n
		}
		m, err := w.Write(zero[:chunk])
		if err != nil {
			return err
		}
		n -= int64(m)
	}
	return nil
}

// matchGlob reports whether p passes filter. An empty filter passes everything;
// a filter with a '/' matches the whole path, otherwise the base name. Matching
// is case-insensitive and accepts Windows-style "\" separators, matching NTFS
// name semantics.
func matchGlob(filter, p string) bool {
	if filter == "" {
		return true
	}
	filter = strings.ToLower(strings.ReplaceAll(filter, "\\", "/"))
	p = strings.ToLower(p)
	if strings.ContainsRune(filter, '/') {
		ok, _ := path.Match(filter, strings.TrimPrefix(p, "/"))
		return ok
	}
	ok, _ := path.Match(filter, path.Base(p))
	return ok
}

// ---- shared formatting ------------------------------------------------------

func sortEntries(entries []fileEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
}

func typeCol(e fileEntry) string {
	if e.IsDir {
		return "d"
	}
	return "-"
}

func nameCol(e fileEntry) string {
	if e.Deleted {
		return e.Name + "  (deleted)"
	}
	return e.Name
}

// tsCol renders a timestamp as RFC3339 UTC, or "-" when zero (an honest null,
// never a fabricated epoch).
func tsCol(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// resolvePath resolves a browse argument against the current directory: an
// absolute path stands alone, a relative one joins onto cwd, and ".." works.
func resolvePath(cwd, arg string) string {
	arg = strings.ReplaceAll(arg, "\\", "/")
	if strings.HasPrefix(arg, "/") {
		return path.Clean(arg)
	}
	return path.Clean(path.Join(cwd, arg))
}

// splitFirst splits a REPL line into its first whitespace-delimited command word
// and the trimmed remainder (a single path argument, spaces and all).
func splitFirst(line string) (cmd, rest string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

// splitArgs splits a line into fields, honouring double quotes so a path with
// spaces survives as one argument (used by `get`, which takes two).
func splitArgs(line string) []string {
	var args []string
	var cur strings.Builder
	inQuote, has := false, false
	flush := func() {
		if has {
			args = append(args, cur.String())
			cur.Reset()
			has = false
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			has = true
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	flush()
	return args
}
