# `get-sybers/gomount` — read a disk image's volumes, read-only, unprivileged

## Backends

gomount reads the volumes of a disk image in-process, and can additionally
FUSE-mount an NTFS volume. The image container is detected by content, never
by name: E01/Ex01 (segmented), raw/dd/img, **VMDK** (monolithic and split
sparse extents, streamOptimized, text descriptors with flat/zero extents,
snapshot chains through `parentFileNameHint`), **VHDX** and **VHD** (fixed,
dynamic, differencing), **QCOW2** (with backing files and compressed
clusters) and **VDI** (dynamic and differencing). The VM-disk decoders are
ported from [VMkatz](https://github.com/nikaiw/VMkatz) (MIT, Nicolas
Devillers) — see `image/`. Apple's disk images are read by gomount's own
clean-room [`image/dmg.go`](image/dmg.go) and [`image/sparse.go`](image/sparse.go):
a **DMG** (UDIF — the `koly` trailer in the last 512 bytes, its `mish` block
tables from the XML plist or the classic resource fork) is presented as the
raw disk it holds, its chunks decoded on demand — zero-fill, raw, **ADC**,
**zlib** (UDZO), **bzip2** (UDBZ) and **LZFSE** (ULFO) — so the partition
layer and the HFS+/APFS backends read it unchanged; an **LZMA** (ULMO) chunk
is refused with a clear error (no LZMA decoder is carried), as are
segmented `.dmgpart` sets and encrypted (`encrcdsa`) images. A
**.sparseimage** (`sprs` band table) and a **.sparsebundle** directory
(`Info.plist` + `bands/<hex>`; pass the directory as `<image>`) read the
same way, unwritten bands as zeros. An uncompressed `.dmg` without a
trailer is simply a raw image.

The **userspace backend** parses filesystems in-process and mounts nothing:
no FUSE, no kernel driver, no privilege. NTFS is read with
[go-ntfs](https://www.velocidex.com/golang/go-ntfs); the Linux filesystems —
**ext2/3/4, XFS v5 and vfat** — and the Mac filesystems — **APFS** and
**HFS+/HFSX** — with gomount's own clean-room [`fsx`](fsx) backends
(docs/linux §5.1), and every verb resolves ONE volume stack first
(docs/linux §5.2): partitions (MBR, GPT, **Apple Partition Map**), **LVM2
volume groups** (linear and striped LVs, addressed as `--lv vg/lv`), the
volumes of an **APFS container** (`identify` lists each as
`<partition>/apfsN` with its name, role and UUID; `--volume 0` prefers the
Data volume), or a bare whole-disk filesystem. The HFS+ backend
([`fsx/hfsplus`](fsx/hfsplus)) reads the volume header — directly or
through the classic HFS wrapper Apple's tools always wrote — the catalog,
extents-overflow and attributes B-trees, file and directory hard links
through the private metadata directories, symlinks, extended attributes
and decmpfs content; its fixtures are built by
[`fsx/hfsplus/hfstest`](fsx/hfsplus/hfstest) (`go run
./fsx/hfsplus/hfstest/mkhfs -o hfs.img [-hfsx] [-wrapper] [-apm]`), since
no Linux build host can format one, and both Mac backends are also tested
against volumes Apple's tools wrote (Homebrew's cask fixtures, reassembled
under `fsx/testdata/`). The APFS backend ([`fsx/apfs`](fsx/apfs)) reads the newest
checkpoint, the object maps, the fixed and variable B-trees, the sealed
(hashed, headerless) file-system tree of a System volume with its extents
in the fext tree, and file content including **decmpfs** compression —
zlib, LZVN and LZFSE (Apple's compressors ported in [`lzfse`](lzfse),
BSD-3), inline or in the resource fork. A FileVault volume lists but its
content does not read; snapshots, Fusion containers and LZBITMAP are out of
scope. It serves
the volume's contents straight from the parser through read verbs — `ls`,
`cat`, `stat`, `tree`, and `browse` for an operator, `stream` and
`materialise` for tools, `identify` for the lane's routing document, and
`timeline` for the fs:stat rows (allocation state on every row; `--residue`
adds the recovered rows of §5.5, `--hash` content digests). A malformed
filesystem surfaces as a Go error rather than a kernel fault, and the
backend runs anywhere a Go binary runs, including containers with no
`/dev/fuse`.

```
gomount ls     <image> [path]      list a directory (default: the volume root)
gomount cat    <image> <path>      write a file's bytes to stdout
gomount stat   <image> <path>      print one entry's metadata
gomount tree   <image> [path]      list a subtree
gomount browse <image>             navigate the volume interactively
gomount identify <image>           print the resolved volume stack as JSON
gomount timeline <image>           one JSONL row per (file, timestamp kind)
gomount stream [--jsonl] <image>   walk the whole filesystem for tools
gomount materialise --out DIR [--set NAME]... [--select GLOB]... [--siblings] [--manifest] <image>
```

`materialise` copies targeted artefacts out of the volume into a real directory,
so a downstream tool consumes them from a plain `-d <dir>`. `--set` names a
built-in artefact set (`windows-core` — every Windows set in one —
`registry-core`, `amcache`, `shimcache`, `ntuser`, `usrclass`, `srum`, `sum`,
`timeline`, `winevt`, `prefetch`, `mft`, `recent`, `recyclebin`, and
`linux-core`, `macos-core` — what godaemonhunter reads off a Mac's Data volume — and `macos-system`, the sealed System volume's version plist and Apple's launchd jobs); `--select` adds an ad-hoc volume-path glob. Each file lands at `<out>/<volume-path>` at mode `0400`. `--siblings`
(default `true`) also copies each artefact's named siblings — a hive's
`.LOG1`/`.LOG2`, a SQLite `-wal`/`-shm` — from the same directory. `--manifest`
writes `<out>/materialise.jsonl` when `--manifest` is given — each row an
**origin record** (docs/linux §5.4): `path/size/mtime` plus the image, the
volume's place in the stack (`p1` | `vg/lv` | `disk`), the filesystem UUID
and label, the inode/mftid, a `staged` path when it differs, a `skip`
reason for files held back by `--max-file-size`, and the residue
kind/detail on `--residue` rows.
The artefact sets are defined in `materialise-sets.yml`, embedded at build
time (`go:embed`) — adding a set or a sibling suffix is a data edit, never a
Go change. Each named set lists one or more **primary** artefacts to copy
out of a volume, plus the **sibling** suffixes that must travel with each
primary (registry transaction logs, SQLite WAL/SHM) so the downstream go*
tool sees a complete artefact. Paths are volume-relative; `\` and `/`
separators are both accepted and matching is case-insensitive. A `*` path
component matches every immediate child (a profile under `\Users`, a
`*.mdb` leaf); `**` pulls a whole tree (the `linux-core` set of docs/linux
§5.4 uses it for the daemon parsers' artefact surface).
A selector that matches nothing copies nothing and is not an error.

The **direct backend** is the `mount` subcommand: it exports the volume as one
regular file over FUSE and execs the distro `ntfs-3g -o ro` onto that file,
producing a real, browsable, read-only mount at a mountpoint. It needs `/dev/fuse`
and unprivileged user namespaces; the rest of this document describes it.

Standalone Go binary that presents a single NTFS volume from a disk image as a
real, browsable, read-only mount without any elevated privilege. It opens the
image `O_RDONLY`, decodes it (raw/dd/img directly, or E01/Ex01 through the
pure-Go [go-ewf](https://github.com/Velocidex/go-ewf) reader), parses the MBR or
GPT partition table clean-room to select the NTFS volume (a partitionless
superfloppy is the whole image), reads the NTFS boot sector via
[go-ntfs](https://www.velocidex.com/golang/go-ntfs) for the exact volume byte
length, and exports that volume as one regular file `volume.img` over FUSE
([go-fuse](https://github.com/hanwen/go-fuse)). `volume.img` reports the exact
volume size in `Getattr`, serves reads straight from the bounded `io.ReaderAt`,
and rejects every write with `EROFS`.

The distro `ntfs-3g` binary then mounts that regular file `-o ro`. `ntfs-3g`
runs as a separate process; gomount execs it and never links `libntfs-3g`, so
gomount stays permissively licensed. Because the backing object is a regular
file rather than a block or loop device, the kernel mount type is `fuse`
(`FS_USERNS_MOUNT`), not `fuseblk`. gomount runs root-inside-a-user-namespace —
it re-execs itself with `CLONE_NEWUSER|CLONE_NEWNS` (the pure-Go equivalent of
`unshare -U -m -r`), or honours an existing user namespace from rootless podman.
No `CAP_SYS_ADMIN`, no loop device, no `--privileged`; the mount needs only
`/dev/fuse` and a kernel that permits unprivileged user namespaces.

The runtime image is `debian:trixie-slim` with `fuse3` and `ntfs-3g`, a
declared deviation from the `FROM scratch` sibling tool images because the
operator mount execs the distro `ntfs-3g` and its `fusermount3` helper. The Go
binary itself is static (CGO off). The image is hardened the same way as the
rest of the matrix: the package manager, sudo/su and the account tools are
removed, every setuid/setgid bit is stripped, uid 0 is renamed and locked, and
it runs as uid 2000; `sh` ships with the base and is declared
(`/etc/dfir-hardened`: `shell=true python=false pkg_mgr=false`).

```sh
docker build -t get-sybers/gomount:latest -f gomount/Dockerfile gomount
# golang:trixie / debian:trixie-slim track the latest stable toolchain and base;
# the build's apt-get update pulls the latest patched ntfs-3g + fuse3 (mkntfs
# ships inside ntfs-3g on trixie — there is no separate ntfsprogs package)

# rootless podman (the container is already a user namespace):
podman run --rm -it --device /dev/fuse -v "$PWD/evidence:/evidence:ro" \
  get-sybers/gomount:latest mount --mount-point /mnt/ntfs /evidence/disk.E01

# rootful docker (gomount self-bootstraps the user namespace):
docker run --rm -it --device /dev/fuse \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  -v "$PWD/evidence:/evidence:ro" \
  get-sybers/gomount:latest mount /evidence/disk.E01
```

```
gomount mount  [--read-only] [--mount-point PATH] [--volume N] [--work PATH] \
               [--no-self-unshare] [--foreground] <image>
gomount umount [--mount-point PATH] [--work PATH]
```

`--volume` is 1-based; `0` auto-selects the largest NTFS volume (the
userspace verbs then prefer a Mac's APFS Data volume, then an HFS+ system
volume, then the Linux root).
`--no-self-unshare` assumes the caller already established the user namespace.

## Contract

gomount is driven by argv, not by an environment batch loop
([`contract.yml`](contract.yml): `entrypoint: argv`, a declared deviation —
its verbs are streaming and interactive). It reads no `GOMOUNT_*` variables.

## Input

The disk image named in argv, mounted read-only (`/evidence` by convention);
the `mount` verb additionally needs `--device /dev/fuse`.

## Output

- `stream`: a tar archive on stdout, one regular-file entry per volume file (entry name = the file's volume path), or one JSON object per file with `--jsonl`.
- `materialise`: `<out>/<volume-path>` at mode `0400` per pulled file, `residue/<kind>/<id>/<volume-path>` with `--residue`, plus `<out>/materialise.jsonl` with `--manifest`; ONE JSON summary line on stdout (`tool, subtool, version, status, inputs, processed, skipped, failed, records, outputs, exit, started, duration_s`, the batch contract every DX_DFIR lane gates on).
- `mount`: a read-only NTFS mount at `--mount-point` held in the foreground until `umount`.
- `ls`/`cat`/`stat`/`tree`/`browse`: the listing or bytes on stdout.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | read/stream verbs: usage or fatal error (unknown verb, missing image, unreadable volume, mount failure); `materialise`: nothing pulled (no artefact of the sets on the volume) |
| 2 | `materialise`: config error (usage, unknown `--set`, bad `--select`, unwritable `--out`) |
| 3 | `materialise`: partial — the image could not be opened, or some files failed to copy (see stderr and the summary's `failures`) |

## Run

```sh
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/evidence:/evidence:ro" \
  get-sybers/gomount:latest stream --filter '*.pf' /evidence/disk.E01 | gowindowlicker goprefetch --tar
```

`test/contract_test.sh` builds the image and asserts the label set, the
self-declaration against the filesystem, and the argv modes (usage on no
arguments, a non-zero exit with nothing on stdout for a missing image);
`test/mount-test.sh` and `test/userspace-test.sh` exercise the verbs on a
host that provides `/dev/fuse` and `mkntfs`.

Both integration tests build their NTFS fixture with `mkntfs` (a
partitionless superfloppy in a plain file), so no real evidence image is
ever needed, and both prove the source image's sha256 unchanged across every
operation (the read-only proof). `GOMOUNT_BIN` overrides the binary under
test; otherwise the scripts use `gomount` on PATH or build it from the
checkout.

- **`mount-test.sh`** proves the whole unprivileged mount stack: decode →
  volume ReaderAt → single-file FUSE export → exec'd `ntfs-3g -o ro` → a
  real, browsable, read-only mount. It asserts the mount appears as fs type
  `fuse`/`fuse.ntfs-3g` and **not** `fuseblk` (fuseblk = block/loop device =
  privileged; fuse over a regular file is what `FS_USERNS_MOUNT` allows
  unprivileged), that the seeded file lists and reads through the mount, and
  the sha256 proof. The container's default caps exclude `CAP_SYS_ADMIN`,
  so the script re-execs its mount phase inside one fresh user+mount
  namespace (`unshare -U -m -r`) where the process holds `CAP_SYS_ADMIN`
  over its own mount namespace (kernel ≥ 4.18); owning ONE namespace for the
  whole phase keeps the mount visible to the `ls`/`stat`/`umount` that
  follow. `--no-self-unshare` tells gomount the script already owns a
  suitable userns. Exit 3 = the environment cannot provide unprivileged
  FUSE (an environment report says why — not a gomount bug); the unprivileged
  recipe is `docker run --rm --device /dev/fuse --security-opt
  apparmor=unconfined --security-opt seccomp=unconfined
  get-sybers/gomount:latest bash /test/mount-test.sh`.
- **`userspace-test.sh`** proves the pure-userspace path (`ls`/`cat`/`stat`/
  `stream` straight from the in-process parser): no mount, no FUSE, no
  separate process, no privilege — a parser bug is a Go panic, never host
  RCE. Because it runs anywhere a Go program runs, it has **no environment
  SKIP path**: given `ntfs-3g` (for the fixture builders) it must reach a
  verdict, in CI included. It asserts `ls -l` (exact size), byte-identical
  `cat`, sane `stat`, `stream --jsonl` records, and the sha256 proof.
