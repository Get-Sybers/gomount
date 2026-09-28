// gomount — present ONE NTFS volume from a disk image as a real, browsable,
// READ-ONLY mount, UNPRIVILEGED.
//
// Pipeline (all in-process except the final hop):
//
//	image (E01/raw, O_RDONLY)
//	  -> io.ReaderAt + size                           [image.OpenImage]
//	  -> partitions, pick the NTFS volume             [partition.Partitions / SelectNTFSVolume]
//	  -> read the BPB for the EXACT volume length     [ntfsvol.ReadNTFSGeometry]
//	  -> bounded io.ReaderAt (offset, exact length)   [ntfsvol.VolumeReader]
//	  -> single regular file volume.img over FUSE     [vfile.Mount]   (Getattr = EXACT size)
//	  -> ntfs-3g -o ro mounts that regular file       [ntfs3g.MountRO] (separate process, NEVER linked)
//
// It is unprivileged because ntfs-3g mounts a *regular file* (kernel mount type
// "fuse", FS_USERNS_MOUNT — not "fuseblk") and gomount runs root-inside-a-user-
// namespace (userns.Ensure). No CAP_SYS_ADMIN, no loop device, no --privileged.
//
// Usage:
//
//	gomount mount  [--read-only] [--mount-point PATH] [--volume N] [--work PATH]
//	               [--no-self-unshare] [--foreground] <image>
//	gomount umount [--mount-point PATH] [--work PATH]
//
// `mount` runs in the foreground holding the mount up; Ctrl-C (SIGINT/SIGTERM)
// tears it down inner-before-outer. `umount` tears it down from another process
// in the SAME mount namespace (rootless-podman / outer-unshare deployments); on
// a bare-host self-bootstrap the mount is private to the `mount` process, so
// stop it with Ctrl-C.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/get-sybers/gomount/image"
	"github.com/get-sybers/gomount/ntfs3g"
	"github.com/get-sybers/gomount/ntfsvol"
	"github.com/get-sybers/gomount/partition"
	"github.com/get-sybers/gomount/userns"
	"github.com/get-sybers/gomount/vfile"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "mount":
		os.Exit(runMount(os.Args[2:]))
	case "umount", "unmount":
		os.Exit(runUmount(os.Args[2:]))
	case "ls":
		os.Exit(runLs(os.Args[2:]))
	case "cat":
		os.Exit(runCat(os.Args[2:]))
	case "stat":
		os.Exit(runStat(os.Args[2:]))
	case "tree":
		os.Exit(runTree(os.Args[2:]))
	case "browse":
		os.Exit(runBrowse(os.Args[2:]))
	case "stream":
		os.Exit(runStream(os.Args[2:]))
	case "materialise":
		os.Exit(runMaterialise(os.Args[2:]))
	case "identify":
		os.Exit(runIdentify(os.Args[2:]))
	case "timeline":
		os.Exit(runTimeline(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "gomount: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gomount — read ONE NTFS volume from a disk image, read-only, unprivileged

Two backends read the same image (E01/Ex01 segmented, or raw/dd/img, O_RDONLY):

DIRECT backend — a real, browsable kernel mount via ntfs-3g + FUSE (needs /dev/fuse):
  gomount mount  [--read-only] [--mount-point PATH] [--volume N] [--work PATH] \
                 [--no-self-unshare] [--foreground] <image>
  gomount umount [--mount-point PATH] [--work PATH]

USERSPACE backend — pure in-process go-ntfs parsing, no mount, no FUSE, no privilege:
  gomount ls     [--volume N] [-l] [--deleted] <image> [path]
  gomount cat    [--volume N] <image> <path[:stream]>
  gomount stat   [--volume N] <image> <path>
  gomount tree   [--volume N] [--depth D] <image> [path]
  gomount browse [--volume N] <image>
  gomount stream [--volume N] [--filter GLOB] [--jsonl] <image>
  gomount materialise [--volume N] --out DIR [--set NAME]... [--select GLOB]... \
                 [--siblings=true] [--manifest] <image>
  gomount identify <image>
  gomount timeline [--volume N | --lv vg/lv] [--residue] [--hash] <image>

  The userspace verbs read NTFS, the Linux filesystems (ext2/3/4, XFS,
  vfat), APFS and HFS+/HFSX through one resolved volume stack: partitions
  (MBR, GPT, Apple Partition Map), LVM2 volume groups (--lv vg/lv addresses
  a logical volume), the volumes of an APFS container (identify lists them
  as <partition>/apfsN; a sealed System volume and decmpfs-compressed
  content read transparently, FileVault content does not), an HFS+ volume
  (also inside its classic HFS wrapper; hard links, decmpfs), or a bare
  whole-disk filesystem.
  identify prints that stack as one JSON document; timeline emits one JSONL
  row per (file, timestamp kind) with allocation state (--residue adds the
  recovered rows, --hash content digests).

  <image>       a disk image, opened read-only and detected by content: E01/Ex01
                (segmented), raw/dd/img, VMDK (sparse, streamOptimized, descriptor
                + flat/split extents, snapshot chains), VHDX, VHD, QCOW2, VDI, DMG
                (UDIF: zero/raw/ADC/zlib/bzip2/LZFSE chunks; not LZMA), a
                .sparseimage, or a .sparsebundle directory
  --volume N    1-based volume in the resolved stack; 0 = auto (largest NTFS,
                else a Mac's APFS Data volume, else the HFS+ volume holding
                SystemVersion.plist, else the volume holding /etc/os-release,
                else largest known)
  --lv vg/lv    address an LVM2 logical volume by name
  -l            ls long listing: type, size, mtime, name
  --deleted     ls also carves directory-index slack for unlinked entries
  --depth D     tree recursion depth (default -1 = unlimited)
  path[:stream] an alternate data stream is addressed as name:stream
  --filter GLOB stream: glob the base name, or the path when it holds '/' (default: all)
  --jsonl       stream: one JSON object per file {path,size,mtime,mftid} instead of a tar
  --out DIR     materialise: output directory for the pulled artefacts (required)
  --set NAME    materialise: named artefact set to pull, repeatable (windows-core,
                registry-core, amcache, shimcache, ntuser, usrclass, srum, sum,
                timeline, winevt, prefetch, mft, recent, recyclebin, linux-core,
                macos-core, macos-system)
  --select GLOB materialise: ad-hoc volume-path glob to pull, repeatable
  --siblings    materialise: also pull each artefact's named siblings (default true)
  --manifest    materialise: write <out>/materialise.jsonl for the pulled files

  browse is an interactive REPL (ls, cd, cat, stat, get, pwd, help, quit); stream
  writes a tar of the filtered files to stdout for a downstream tool (e.g. goyara),
  a per-file {path,size,mtime,mftid} JSONL with --jsonl, and a {files,bytes,errors}
  summary on stderr. materialise copies targeted artefacts (and their siblings)
  to <out>/<volume-path> at mode 0400 for the model-B go* tools' -d <dir>, and
  prints ONE JSON summary line on stdout (the batch contract: 0 ok, 1 nothing
  pulled, 2 config error, 3 partial). Every verb opens the image read-only and
  never writes to it.

  DIRECT-backend flags: --mount-point (default /mnt/ntfs), --read-only (default true),
  --work PATH (FUSE work dir), --no-self-unshare, --foreground (default true).
`)
}

// runMount opens the image, selects and bounds the NTFS volume, publishes it as
// a single regular file over FUSE, mounts that file with ntfs-3g, and holds the
// mount up until signalled or externally unmounted.
func runMount(argv []string) int {
	fs := flag.NewFlagSet("mount", flag.ExitOnError)
	readOnly := fs.Bool("read-only", true, "mount read-only (default true)")
	mountPoint := fs.String("mount-point", "/mnt/ntfs", "where to expose the browsable NTFS mount")
	volume := fs.Int("volume", 0, "1-based volume to mount; 0 = auto (largest NTFS volume)")
	work := fs.String("work", "", "FUSE work dir for volume.img (default: derived from --mount-point)")
	noSelfUnshare := fs.Bool("no-self-unshare", false, "do not create a user namespace; assume already root-in-userns")
	foreground := fs.Bool("foreground", true, "hold the mount up in the foreground until unmount (default true)")
	fs.Usage = usage
	_ = fs.Parse(argv)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gomount mount: exactly one <image> argument is required")
		usage()
		return 1
	}
	if !*readOnly {
		fmt.Fprintln(os.Stderr, "gomount: read-only is the only supported mode; --read-only=false is not accepted")
		return 1
	}
	if !*foreground {
		fmt.Fprintln(os.Stderr, "gomount: only foreground operation is supported; --foreground=false is not accepted")
		return 1
	}
	imgPath := fs.Arg(0)

	// --volume is 1-based and operator-facing; partition.SelectNTFSVolume takes a
	// 0-based index, or a negative value to auto-select the largest NTFS volume.
	prefer := -1
	if *volume > 0 {
		prefer = *volume - 1
	}

	// Become root-inside-a-userns so the FUSE mounts need no real privilege. On
	// the bare-host path this re-execs and never returns in the parent. When the
	// caller has already established a suitable userns (rootless podman, or the
	// integration test's `unshare -U -m -r`), --no-self-unshare skips the re-exec
	// so the mount lands in the caller's namespace and stays visible there.
	if !*noSelfUnshare {
		if err := userns.Ensure(); err != nil {
			fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
			return 1
		}
	}
	if err := ntfs3g.Available(); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}

	workDir := *work
	if workDir == "" {
		workDir = workDirFor(*mountPoint)
	}

	// 1. Open the image O_RDONLY (decoding EWF on demand) as random-access bytes.
	ra, size, closeImage, err := image.OpenImage(imgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: open image: %v\n", err)
		return 1
	}
	defer closeImage()

	// 2. Parse the partition table and select the NTFS volume to mount.
	parts, err := partition.Partitions(ra, size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: read partitions: %v\n", err)
		return 1
	}
	sel, idx, err := partition.SelectNTFSVolume(parts, prefer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: select NTFS volume: %v\n", err)
		return 1
	}

	// 3. Read the BPB for the EXACT volume byte length (the load-bearing size
	//    ntfs-3g reads back via fstat/lseek).
	geom, err := ntfsvol.ReadNTFSGeometry(ra, sel.Offset, sel.Size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: read NTFS geometry: %v\n", err)
		return 1
	}
	if geom.Note != "" {
		fmt.Fprintf(os.Stderr, "gomount: note: %s\n", geom.Note)
	}

	// 4. Bound the volume to [offset, offset+VolumeSize): a ReaderAt whose Size()
	//    is exactly the volume length.
	vr := ntfsvol.VolumeReader(ra, sel.Offset, geom)

	// 5. Publish it as the single regular file volume.img over FUSE.
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: work dir: %v\n", err)
		return 1
	}
	srv, err := vfile.Mount(workDir, vr, geom.VolumeSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gomount: publish volume.img: %v\n", err)
		return 1
	}
	volFile := filepath.Join(workDir, vfile.VolumeName)

	// 6. ntfs-3g mounts that regular file read-only (separate process).
	if err := ntfs3g.MountRO(volFile, *mountPoint, ntfs3g.DefaultOpts()); err != nil {
		_ = srv.Unmount() // nothing consumes volume.img now: drop the FUSE layer.
		_ = os.Remove(workDir)
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		return 1
	}

	via := "fusermount3 helper"
	if srv.DirectMount {
		via = "direct mount(2)"
	}
	fmt.Fprintf(os.Stderr, "gomount: %s volume %d (%d bytes, %s) mounted read-only at %s\n",
		filepath.Base(imgPath), idx+1, geom.VolumeSize, via, *mountPoint)
	fmt.Fprintf(os.Stderr, "gomount: browse it there; Ctrl-C (or `gomount umount --mount-point %s`) to unmount\n", *mountPoint)

	// 7. Hold the mount up until signalled or externally unmounted, then tear
	//    down inner-before-outer: ntfs-3g first (release the CONSUMER of
	//    volume.img), then the vfile FUSE (its SERVER) — otherwise volume.img is
	//    busy and its unmount fails EBUSY.
	teardown := func() {
		if err := ntfs3g.Umount(*mountPoint); err != nil {
			fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		}
		if err := srv.Unmount(); err != nil {
			fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		}
		_ = os.Remove(workDir)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	served := make(chan struct{})
	go func() { srv.Wait(); close(served) }() // returns if vfile is unmounted out-of-process

	select {
	case <-sig:
		teardown()
	case <-served:
		// `gomount umount` already dropped the vfile layer (after ntfs-3g);
		// make sure the ntfs-3g layer is gone too, then clean up.
		_ = ntfs3g.Umount(*mountPoint)
		_ = os.Remove(workDir)
	}
	return 0
}

// runUmount tears a mount down from a separate process. It does NOT create a
// user namespace: it must act in the mount namespace that holds the mount, so it
// only works when the `mount` process shares this namespace (rootless podman /
// outer `unshare -U -m -r`). Order matches the mount teardown: ntfs-3g (the
// consumer of volume.img) first, then the vfile FUSE that serves it — both are
// FUSE mounts torn down by the same fusermount3 cascade (ntfs3g.Umount).
func runUmount(argv []string) int {
	fs := flag.NewFlagSet("umount", flag.ExitOnError)
	mountPoint := fs.String("mount-point", "/mnt/ntfs", "the browsable NTFS mount to tear down")
	work := fs.String("work", "", "vfile work dir (default: derived from --mount-point)")
	fs.Usage = usage
	_ = fs.Parse(argv)

	workDir := *work
	if workDir == "" {
		workDir = workDirFor(*mountPoint)
	}
	rc := 0
	if err := ntfs3g.Umount(*mountPoint); err != nil {
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		rc = 1
	}
	if err := ntfs3g.Umount(workDir); err != nil { // the vfile FUSE layer
		fmt.Fprintf(os.Stderr, "gomount: %v\n", err)
		rc = 1
	}
	_ = os.Remove(workDir)
	if rc == 0 {
		fmt.Fprintf(os.Stderr, "gomount: unmounted %s\n", *mountPoint)
	}
	return rc
}

// workDirFor derives a stable FUSE work directory for a mount point, so `mount`
// and a later `umount` agree without any on-disk state. It hashes the absolute
// mount point under the runtime base (XDG_RUNTIME_DIR, else the temp dir).
func workDirFor(mountPoint string) string {
	abs, err := filepath.Abs(mountPoint)
	if err != nil {
		abs = mountPoint
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(runtimeBase(), "gomount", hex.EncodeToString(sum[:8]))
}

func runtimeBase() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return os.TempDir()
}
