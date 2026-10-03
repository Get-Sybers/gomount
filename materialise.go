// materialise — copy TARGETED forensic artefacts (and their named siblings) out
// of an NTFS volume into a real output directory, so the model-B go* tools
// (gore, goamcache, goappcompat, gosbe, goese, gowxt) consume them from a plain
// directory with their existing -d <dir>, unchanged. It is a pure addition to
// the userspace backend: read-only, no FUSE, no mount, no privilege. It reuses
// the same in-process pipeline (openVolumeFS) as ls/cat/stat/tree/browse/stream
// and never writes to the source image.
//
// The artefact sets it knows are DATA, not code: they live in the embedded
// materialise-sets.yml and are read at run time, so a new set or sibling suffix
// is added by editing that file, never this one.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Get-Sybers/gopinfo/framework"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	yaml "github.com/Velocidex/yaml/v2"

	"github.com/Get-Sybers/gomount/fsx"
)

// materialiseSetsYAML is the embedded artefact-set catalogue. Keeping the set
// definitions in a data file (not in Go) satisfies the no-hardcoded-static-refs
// rule: the code reads the YAML rather than carrying the paths inline.
//
//go:embed materialise-sets.yml
var materialiseSetsYAML []byte

// artefactSet is one named group of primary artefacts plus the sibling suffixes
// that travel with each primary (registry transaction logs, SQLite WAL/SHM).
// Primaries are volume-relative path patterns; a "*" path component matches
// every immediate child (a user profile, a CDP profile, a *.mdb leaf).
type artefactSet struct {
	Primaries []string `yaml:"primaries"`
	Siblings  []string `yaml:"siblings"`
}

// artefactCatalogue is the whole materialise-sets.yml document.
type artefactCatalogue struct {
	Sets map[string]artefactSet `yaml:"sets"`
}

// loadArtefactSets decodes the embedded catalogue.
func loadArtefactSets() (map[string]artefactSet, error) {
	var cat artefactCatalogue
	if err := yaml.Unmarshal(materialiseSetsYAML, &cat); err != nil {
		return nil, fmt.Errorf("materialise-sets.yml: %w", err)
	}
	if len(cat.Sets) == 0 {
		return nil, fmt.Errorf("materialise-sets.yml: no artefact sets defined")
	}
	return cat.Sets, nil
}

// materialiseRecord is one manifest line — the ORIGIN RECORD of rule 2
// (docs/linux §5.4): every pulled file carries the chain the pinfo
// runtime joins onto parser records as Origin/Snapshot/Residue. The
// legacy fields (path/size/mtime/mftid) keep their names so existing
// consumers read on; the chain fields are omitted when a backend has no
// value for them (honest nulls).
type materialiseRecord struct {
	Path   string           `json:"path"`
	Size   int64            `json:"size"`
	Mtime  string           `json:"mtime,omitempty"`
	MFTID  string           `json:"mftid,omitempty"`
	Image  string           `json:"image,omitempty"`
	Volume string           `json:"volume,omitempty"` // "p1" | "vg0/root" | "disk"
	FSUUID string           `json:"fsuuid,omitempty"`
	Label  string           `json:"label,omitempty"`
	Inode  uint64           `json:"inode,omitempty"`
	Staged string           `json:"staged,omitempty"` // stage-relative path when != path
	Skip   string           `json:"skip,omitempty"`   // why a file was NOT pulled
	Res    *manifestResidue `json:"residue,omitempty"`
}

type manifestResidue struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

// multiFlag collects a repeatable string flag (--set, --select).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// version is stamped by the build (-ldflags "-X main.version=…").
var version = "dev"

func runMaterialise(argv []string) int {
	started := time.Now()
	sum := framework.Summary{Tool: "gomount", Subtool: "materialise", Version: version,
		Outputs: []string{}, Started: started.UTC().Format("2006-01-02T15:04:05Z")}
	finish := func(status string, code int) int {
		sum.Status, sum.Exit = status, code
		sum.DurationS = float64(time.Since(started).Milliseconds()) / 1000
		b, _ := json.Marshal(sum)
		fmt.Fprintln(os.Stdout, string(b))
		return code
	}
	configErr := func(msg string) int {
		fmt.Fprintln(os.Stderr, "gomount materialise: "+msg)
		sum.Error = msg
		return finish("config_error", 2)
	}

	fs := flag.NewFlagSet("materialise", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	volume := fs.Int("volume", 0, "1-based volume in the resolved stack (default 0 = auto-select)")
	lvName := fs.String("lv", "", "address an LVM logical volume as vg/lv")
	out := fs.String("out", "", "output directory for the pulled artefacts (required, writable)")
	siblings := fs.Bool("siblings", true, "also pull each artefact's named siblings (transaction logs, WAL/SHM)")
	manifest := fs.Bool("manifest", false, "write <out>/materialise.jsonl listing every pulled file")
	maxSize := fs.Int64("max-file-size", 0, "skip files larger than this many bytes (0 = no limit); every skip lands in the manifest")
	withResidue := fs.Bool("residue", false, "also stage recoverable residue content under residue/<kind>/<id>/ (Linux backends)")
	var sets, selects multiFlag
	fs.Var(&sets, "set", "named artefact set to pull (repeatable)")
	fs.Var(&selects, "select", "ad-hoc volume-path glob to pull (repeatable)")
	fs.Usage = usage
	if err := fs.Parse(argv); err != nil {
		return configErr(err.Error())
	}

	if fs.NArg() != 1 {
		return configErr("usage: materialise [--volume N | --lv vg/lv] --out DIR [--set NAME]... [--select GLOB]... [--siblings=true] [--manifest] [--max-file-size N] [--residue] <image>")
	}
	if *out == "" {
		return configErr("--out DIR is required")
	}
	if len(sets) == 0 && len(selects) == 0 {
		return configErr("nothing to do: give at least one --set or --select")
	}

	catalogue, err := loadArtefactSets()
	if err != nil {
		return configErr(err.Error())
	}
	// A set that matches no files is fine; a set name that does not exist is an
	// operator typo, so fail loudly before touching the image.
	for _, name := range sets {
		if _, ok := catalogue[name]; !ok {
			return configErr(fmt.Sprintf("unknown --set %q (known: %s)", name, strings.Join(sortedSetNames(catalogue), ", ")))
		}
	}
	for _, g := range selects {
		// Validate the normalised form the matcher uses (Windows "\" separators
		// become "/"), so a valid selector is not rejected as a bad pattern.
		if _, err := path.Match(strings.ReplaceAll(g, "\\", "/"), ""); err != nil {
			return configErr(fmt.Sprintf("invalid --select pattern %q: %v", g, err))
		}
	}

	sum.Inputs = 1
	sum.Outputs = []string{*out}
	fsys, rawFS, ref, closer, err := openVolume(fs.Arg(0), *volume, *lvName)
	if err != nil {
		// the one item failed before a byte was read: partial, like a
		// dispatcher's failed item, never a silent zero
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		sum.Failed = 1
		sum.Failures = []framework.Failure{{Item: fs.Arg(0), Error: err.Error()}}
		return finish("partial", 3)
	}
	defer closer()

	// The manifest rows' origin chain (rule 2): the image, the volume's
	// place in the stack, and the filesystem's durable identity.
	origin := materialiseRecord{Image: filepath.Base(fs.Arg(0)), Volume: ref.Source}
	if rawFS != nil {
		info := rawFS.Info()
		origin.FSUUID, origin.Label = info.UUID, info.Label
	}

	// Resolve every selector to a de-duplicated, path-sorted set of volume files.
	targets := newTargetSet()
	for _, name := range sets {
		resolveSet(fsys, catalogue[name], *siblings, targets)
	}
	walkErrs := 0
	for _, glob := range selects {
		if err := resolveSelect(fsys, glob, targets); err != nil {
			// A partial walk still yields what it could read; surface it so the
			// operator knows the --select result may be incomplete.
			fmt.Fprintf(os.Stderr, "gomount materialise: --select %q incomplete: %v\n", glob, err)
			walkErrs++
		}
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return configErr(fmt.Sprintf("create --out dir: %v", err))
	}

	newRecord := func(e fileEntry) materialiseRecord {
		r := origin
		r.Path, r.Size, r.Mtime, r.MFTID, r.Inode = e.Path, e.Size, tsCol(e.Mtime), e.MFTID, e.Inode
		return r
	}

	var records []materialiseRecord
	var files, errCount int
	var bytesCopied int64
	for _, e := range targets.sorted() {
		if *maxSize > 0 && e.Size > *maxSize {
			// Skipped, never silently: the manifest says so (§5.4).
			r := newRecord(e)
			r.Skip = fmt.Sprintf("max-file-size (%d > %d)", e.Size, *maxSize)
			records = append(records, r)
			fmt.Fprintf(os.Stderr, "gomount materialise: %s: skipped, %d bytes over --max-file-size\n", e.Path, e.Size)
			continue
		}
		n, err := materialiseFile(fsys, e, *out)
		if err != nil {
			errCount++
			fmt.Fprintf(os.Stderr, "gomount materialise: %s: %v\n", e.Path, err)
			continue
		}
		files++
		bytesCopied += n
		records = append(records, newRecord(e))
	}

	if *withResidue {
		n, recs, rerr := materialiseResidue(rawFS, *out, origin, *maxSize)
		records = append(records, recs...)
		files += n
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "gomount materialise: residue: %v\n", rerr)
			errCount++
		}
	}

	if *manifest {
		if err := writeManifest(filepath.Join(*out, "materialise.jsonl"), records); err != nil {
			fmt.Fprintf(os.Stderr, "gomount materialise: write manifest: %v\n", err)
			errCount++
		}
	}

	fmt.Fprintf(os.Stderr, "gomount materialise: %d file(s), %d byte(s) -> %s\n", files, bytesCopied, *out)
	sum.Records = files
	switch {
	case errCount+walkErrs > 0:
		// the one item failed in part: failed=1 (what drives "partial" in
		// the batch runtimes), processed=1 when some of it landed
		sum.Failed = 1
		if files > 0 {
			sum.Processed = 1
		}
		sum.Failures = []framework.Failure{{Item: fs.Arg(0), Error: fmt.Sprintf("%d file(s) failed to copy or walk (see stderr)", errCount+walkErrs)}}
		return finish("partial", 3)
	case files == 0:
		return finish("nothing", 1)
	default:
		sum.Processed = 1
		return finish("ok", 0)
	}
}

// targetSet de-duplicates resolved files by their canonical volume path — the
// same file can be named by several sets or selects (SYSTEM by both
// registry-core and shimcache) — and yields them in a stable path order.
type targetSet struct {
	byPath map[string]fileEntry
}

func newTargetSet() *targetSet { return &targetSet{byPath: map[string]fileEntry{}} }

func (t *targetSet) add(e fileEntry) {
	if e.IsDir || e.Path == "" {
		return
	}
	if _, ok := t.byPath[e.Path]; !ok {
		t.byPath[e.Path] = e
	}
}

func (t *targetSet) sorted() []fileEntry {
	out := make([]fileEntry, 0, len(t.byPath))
	for _, e := range t.byPath {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// resolveSet resolves one artefact set: every primary pattern, plus (when
// siblings is set) each primary's named siblings from the SAME parent directory.
// A primary or sibling that does not exist is skipped best-effort, so a set that
// matches nothing is not an error.
func resolveSet(fsys volumeFS, set artefactSet, siblings bool, targets *targetSet) {
	for _, pattern := range set.Primaries {
		for _, primary := range matchPrimaries(fsys, pattern) {
			targets.add(primary)
			if !siblings {
				continue
			}
			for _, suffix := range set.Siblings {
				siblingPath := path.Join(path.Dir(primary.Path), primary.Name+suffix)
				if s, err := fsys.Stat(siblingPath); err == nil && !s.IsDir {
					targets.add(s)
				}
			}
		}
	}
}

// resolveSelect pulls every regular file whose volume path matches the ad-hoc
// glob, reusing the same matchGlob semantics as the stream verb (base name, or
// the whole path when the glob contains "/"). Ad-hoc selects carry no sibling
// rule.
func resolveSelect(fsys volumeFS, glob string, targets *targetSet) error {
	return fsys.Walk(func(e fileEntry, _ func() (io.ReadCloser, error)) error {
		if matchGlob(glob, e.Path) {
			targets.add(e)
		}
		return nil
	})
}

// matchPrimaries resolves a volume-path pattern (with "\" or "/" separators) to
// the files it names. A literal path is Stat'd directly; a path component that
// carries glob metacharacters ("*", "?", "[") is expanded by ReadDir, one
// directory level per component, so "\Users\*\NTUSER.DAT" fans out across every
// user profile and "...\SUM\*.mdb" across every database. A "**" component
// matches zero or more directory levels: "var/log/**" pulls a whole tree,
// "home/*/.ssh/**" every user's key material. Directories, and paths that do
// not exist, yield nothing.
func matchPrimaries(fsys volumeFS, pattern string) []fileEntry {
	norm := strings.Trim(strings.ReplaceAll(pattern, "\\", "/"), "/")
	if norm == "" {
		return nil
	}
	comps := strings.Split(norm, "/")
	var out []fileEntry
	var walk func(dir string, idx, depth int)
	var collectAll func(dir string, depth int)
	collectAll = func(dir string, depth int) {
		if depth > 64 {
			return
		}
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			child := path.Join(dir, e.Name)
			if e.IsDir {
				collectAll(child, depth+1)
				continue
			}
			if se, err := fsys.Stat(child); err == nil && !se.IsDir {
				out = append(out, se)
			}
		}
	}
	walk = func(dir string, idx, depth int) {
		if depth > 64 { // the collectAll bound: a crafted tree stops here
			return
		}
		comp := comps[idx]
		last := idx == len(comps)-1
		if comp == "**" {
			if last {
				collectAll(dir, 0)
				return
			}
			walk(dir, idx+1, depth) // ** matches zero levels
			entries, err := fsys.ReadDir(dir)
			if err != nil {
				return
			}
			for _, e := range entries {
				if e.IsDir {
					walk(path.Join(dir, e.Name), idx, depth+1) // and one more level
				}
			}
			return
		}
		if !hasGlobMeta(comp) {
			child := path.Join(dir, comp)
			if last {
				if e, err := fsys.Stat(child); err == nil && !e.IsDir {
					out = append(out, e)
				}
				return
			}
			walk(child, idx+1, depth)
			return
		}
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if ok, _ := path.Match(strings.ToLower(comp), strings.ToLower(e.Name)); !ok {
				continue
			}
			if last {
				if !e.IsDir {
					if se, err := fsys.Stat(path.Join(dir, e.Name)); err == nil && !se.IsDir {
						out = append(out, se)
					}
				}
				continue
			}
			if e.IsDir {
				walk(path.Join(dir, e.Name), idx+1, depth+1)
			}
		}
	}
	walk("/", 0, 0)
	return out
}

func hasGlobMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

// materialiseFile copies one volume file to <outRoot>/<volume-relative-path>
// (leading "/" stripped, "\"-normalised — the same layout the stream verb's tar
// uses). The image is only ever read; nothing is written back to the source.
func materialiseFile(fsys volumeFS, e fileEntry, outRoot string) (int64, error) {
	r, err := fsys.Open(e.Path)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	rel := filepath.FromSlash(strings.TrimPrefix(strings.ReplaceAll(e.Path, "\\", "/"), "/"))
	n, err := stageWrite(outRoot, rel, r)
	if err != nil {
		return n, err
	}
	if !e.Mtime.IsZero() {
		// the staged copy carries the volume's modification time: a parser
		// anchoring a yearless log stamp on the file's mtime, and the
		// SourceModified it records, then speak of the evidence, not of
		// the pull — so a copy that cannot carry it is a failed stage
		if err := os.Chtimes(filepath.Join(outRoot, rel), e.Mtime, e.Mtime); err != nil {
			return n, fmt.Errorf("set mtime: %w", err)
		}
	}
	return n, nil
}

// stageWrite streams r to <outRoot>/<rel>, creating parents and the file
// at mode 0o400. The copy goes through io.Copy so a multi-gigabyte
// database never buffers in memory; symlink traversal is refused end to
// end and nothing can land outside outRoot.
func stageWrite(outRoot, rel string, r io.Reader) (int64, error) {
	dest := filepath.Join(outRoot, rel)

	// Defence in depth against a crafted volume path: never write outside --out.
	absOut, err := filepath.Abs(outRoot)
	if err != nil {
		return 0, err
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return 0, err
	}
	if absDest != absOut && !strings.HasPrefix(absDest, absOut+string(os.PathSeparator)) {
		return 0, fmt.Errorf("refusing to write outside --out: %s", rel)
	}

	if err := ensureDirBeneath(absOut, filepath.Dir(absDest)); err != nil {
		return 0, err
	}
	// Remove any prior pull first: a 0o400 file cannot be re-opened O_WRONLY, so
	// this keeps a re-run idempotent.
	_ = os.Remove(dest)
	w, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o400)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(w, r)
	closeErr := w.Close()
	if copyErr != nil {
		return n, copyErr
	}
	if closeErr != nil {
		return n, closeErr
	}
	// Pin the mode to 0o400 regardless of the process umask.
	if err := os.Chmod(dest, 0o400); err != nil {
		return n, err
	}
	return n, nil
}

// materialiseResidue stages recoverable residue content (docs/linux
// §5.5) under residue/<kind>/<id>/<volume-path>, one manifest row per
// item with the residue kind and detail on it — so a recovered auth.log
// is parsed by the same sub-tools as its live sibling, provenance
// intact. NTFS (no fsx seam) and backends without recovery contribute
// nothing, silently.
func materialiseResidue(rawFS fsx.FS, outRoot string, origin materialiseRecord, maxSize int64) (int, []materialiseRecord, error) {
	rr, ok := rawFS.(fsx.Residuer)
	if rawFS == nil || !ok {
		return 0, nil, nil
	}
	var files int
	var records []materialiseRecord
	err := rr.Residues(func(r fsx.Residue, open func() (io.ReadCloser, error)) error {
		if open == nil {
			return nil // no addressable content: timeline --residue still reports it
		}
		e := r.Entry
		rec := origin
		rec.Path, rec.Size, rec.Mtime, rec.Inode = e.Path, e.Size, tsCol(e.Mtime), e.Inode
		rec.Res = &manifestResidue{Kind: r.Kind, Detail: r.Detail}
		if maxSize > 0 && e.Size > maxSize {
			rec.Skip = fmt.Sprintf("max-file-size (%d > %d)", e.Size, maxSize)
			records = append(records, rec)
			return nil
		}
		rel := path.Join("residue", r.Kind, sanitizeComponent(r.ID),
			strings.TrimPrefix(strings.ReplaceAll(e.Path, "\\", "/"), "/"))
		rc, oerr := open()
		if oerr != nil {
			rec.Skip = "unreadable: " + oerr.Error()
			records = append(records, rec)
			return nil
		}
		defer rc.Close()
		if _, werr := stageWrite(outRoot, filepath.FromSlash(rel), rc); werr != nil {
			rec.Skip = "stage failed: " + werr.Error()
			records = append(records, rec)
			return nil
		}
		rec.Staged = rel
		records = append(records, rec)
		files++
		return nil
	})
	return files, records, err
}

// sanitizeComponent keeps a residue id usable as ONE path component.
func sanitizeComponent(s string) string {
	out := []byte(s)
	for i, c := range out {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_':
		default:
			out[i] = '_'
		}
	}
	// "." and ".." pass the character filter but are path syntax, not
	// names: path.Join would collapse them out of residue/<kind>/<id>/.
	if s := string(out); s != "" && s != "." && s != ".." {
		return s
	}
	return "_"
}

// ensureDirBeneath creates dir and any missing parents under base, refusing to
// traverse or create through a pre-existing symlink so a crafted volume path or a
// symlinked output tree cannot redirect a write outside base. base must be an
// existing real directory (the created --out). Combined with O_NOFOLLOW on the
// file open, the whole path from base to the file is symlink-free.
func ensureDirBeneath(base, dir string) error {
	rel, err := filepath.Rel(base, dir)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to write outside --out: %s", dir)
	}
	cur := base
	for _, comp := range strings.Split(rel, string(os.PathSeparator)) {
		if comp == "" {
			continue
		}
		cur = filepath.Join(cur, comp)
		switch fi, err := os.Lstat(cur); {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to write through symlink: %s", cur)
			}
			if !fi.IsDir() {
				return fmt.Errorf("output path component is not a directory: %s", cur)
			}
		case os.IsNotExist(err):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

// writeManifest writes one JSON object per pulled file to dest (newline-
// delimited), in the path order the files were copied.
func writeManifest(dest string, records []materialiseRecord) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// sortedSetNames returns the catalogue's set names in stable order for a usage
// message.
func sortedSetNames(m map[string]artefactSet) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
