# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Evidence-asset identity in the manifest and `identify`.** gomount already
  read, but dropped, several disk/volume/image identifiers; they now surface so
  a downstream row can be keyed to a resolved asset (the producer half of a
  lockstep change with gopinfo's `Origin`). `materialise --manifest` emits the
  volume-scoped keys `volume_guid`, `part_guid` and `part_offset` on every
  per-file row (like `fsuuid`), and the image-level keys `disk_serial`,
  `disk_id` and — with the new opt-in `--hash` — `image_sha256` on a leading
  path-less metadata row; `identify` surfaces the same fields, and gains its own
  `--hash`. All keys are additive `lower_snake`, omitted when absent (honest
  nulls). Coverage by format/filesystem:
  - `disk_serial`: E01 (EWF `sn` header), VMDK (`ddb.uuid.image` / `CID`),
    VHDX (Virtual Disk ID), VHD (footer Unique Id), VDI (image uuid); raw/dd,
    QCOW2 and the Apple images carry none.
  - `disk_id` / `part_guid`: a GPT disk carries both (disk GUID, per-partition
    unique GUID); an MBR disk carries `disk_id` only (the disk signature, hex);
    a superfloppy / APM disk carries neither.
  - `volume_guid`: the filesystem UUID of an ext/XFS/APFS/HFS+ volume (a
    canonical 128-bit id); empty for vfat's 32-bit serial and for NTFS.
  - NTFS volumes, which have no filesystem UUID, now carry their `$Boot` serial
    (hex) as `fsuuid` in the manifest and as `uuid` in `identify`.

## [0.3.1] - 2026-10-15

### Fixed
- **A hard link to a symlink is that symlink.** On a merged-usr host
  `/usr/lib/systemd/system/x.service` and `/lib/systemd/system/x.service`
  are one symlink inode; GNU tar stores the first and links the second, so a
  UAC collection carries hard links whose target is a symlink (89 of the 400
  hard links in a real LS24 collection, every one a systemd unit). The `uac`
  package resolved a hard link to its target's *bytes* alone, so those came
  out as empty regular files — `stat` said a file, `materialise` staged an
  empty unit and gounit parsed nothing. They now come out as the symlink,
  target and all (a hard link to a directory stays a directory).

## [0.3.0] - 2026-10-15

### Fixed
- **Fedora/RHEL volume groups assemble.** The LVM2 metadata text parser
  honours the two escapes LVM writes inside quoted strings (`\"` and `\\`),
  so a VG whose `description` carries an escaped `--config` argument — every
  anaconda-made VG — parses instead of stopping at the first `\"`
  (`expected identifier`), and its LVs appear in `identify` and the volume
  stack (#7).
- **A PV whose metadata fails to parse is no longer dropped silently.** The
  volume stays in the resolved stack as `lvm2-pv` and `identify` carries the
  probe error on its `note`, where the stack used to look healthy with the
  root volume missing.

### Added
- **UAC collections read as images.** The archive the Unix-like Artifacts
  Collector ([tclahr/uac](https://github.com/tclahr/uac)) writes —
  `uac-<host>-<os>-<ts>.tar.gz`, `.tar` or `.zip` — is detected by content
  (container magic, then UAC's own layout: `uac.log` among the first members
  or a `[root]/` member) and resolved as a two-volume stack by the new
  [`uac`](uac) package: volume 1 `[root]` is the host's files at their own
  paths (auto-selected, so `ls`/`cat`/`stat`/`tree`/`browse`, `stream`,
  `timeline` and `materialise --set linux-core` read a collection exactly as
  they read a disk image's root volume, origin rows naming the archive and
  `[root]`), volume 2 `uac` is the collector's output (`uac.log`,
  `bodyfile/`, `hash_executables/`, `live_response/`, …). `identify` adds a
  `collection` block from `uac.log` (version, hostname, OS, time zone, mount
  point, acquisition start/finish, command line, member counts, a
  `truncated` note for an interrupted collection) and labels the container
  (`image.format`: `zip`, `gzip` or `tar`). Symlinks keep their targets
  (`stat` now prints `Type: symlink` and the `Target:`), hard links read
  their target's bytes, and a gzip'd tar is spooled once into an unlinked
  temp file under `TMPDIR`. The archive's members carry no inode, so the
  `MFTId`/`mftid` column is left empty for them instead of a fabricated 0.
- **`stream --all`: the whole tree.** Beside the default stream (regular
  files, mode `0400`, the mtime alone — the go* tools' `--tar` pipe), `--all`
  emits every entry of the Linux and Mac filesystems — directories and
  symlinks too — with the volume's own uid, gid, mode and access/change
  times in PAX headers, so `gomount stream --all image | tar -x` extracts
  into a browsable root tree: what an offline collector such as UAC's
  `--mount-point` mode is pointed at. A `--filter` narrows the files, never
  the directories; NTFS (no POSIX identity) refuses the flag. `--jsonl`
  rows gain `type` and `link_target` on the non-file entries.
- The `linux-core` artefact set pulls `etc/lsb-release` too: the LSB identity
  Debian and Ubuntu keep beside `os-release`, and the OS identity a UAC
  collection still carries when its `etc/os-release` is a dangling symlink
  into `/usr/lib` (the collector copied `/etc` alone).
- `identify`'s OS guess follows `/etc/os-release` when it is a symlink (every
  modern distribution links it into `/usr/lib`), so a Linux root reports
  `linux (ubuntu)` rather than a bare `linux`.
- **`identify` names a truncated capture.** When a VG's metadata places more
  extents on a PV than the image holds (the Fedora image of #7 is 2.9 GB of a
  15 GB disk), the VG reports the PV under `lvm.vgs[].short_pvs`, each of its
  LVs carries a `note` saying reads past the present bytes will fail, and the
  read error itself says so (`… PV holds N: a truncated capture?`) instead of
  a bare "mapped read outside its PV". The LVs still assemble: what the image
  holds reads. An LV of such a VG that does not probe as a filesystem keeps
  that note beside `no recognised filesystem` in `identify`, not under it.
- The conformance gate of the get-sybers standard (DX_DFIR
  `docs/reference/build-and-test.md`): `make conform` (gofmt, vet, build,
  shuffled tests with coverage, `go mod tidy -diff`, a `go:generate` drift
  check and `scripts/structlint.sh`), `make lint` (golangci-lint v2,
  `.golangci.yml`) and `make vuln` (govulncheck), run by the `CI` workflow on
  pull requests and `main` — on amd64 and arm64 — with `all_green` as the
  one required status check.
- Repository hygiene: `.editorconfig`, `.gitattributes`, `.shellcheckrc`,
  Dependabot (actions and Go modules, weekly, grouped), `CODEOWNERS`, a
  security policy and a pull-request template.

### Changed
- The findings the new lint gate surfaced, none of which changes behaviour:
  `errors.Is` for the `io.EOF` comparisons and `errors.As` for the
  `*WalkErrors` assertion; deferred and error-path closers explicitly
  discarded; local names that shadowed the `min` and `max` builtins renamed;
  the HFS+ volume-label lookup flattened out of its `else`; the filesystem
  registries pass their `probe`/`Open` functions directly instead of through
  wrapping closures; test fixtures built with `slices.Concat`.

### Removed
- Dead code the gate's `unused` check found: the HFS+ `xattr.size`,
  `xattr.readerAt`, `bytesReaderAt`, `btree.first` and `FS.readAt` helpers,
  the `treeNode` type of the HFS+ test builder, the unused VHDX `head`
  signature and `vhdxParentBasename`.

## [0.2.1] - 2026-10-03

The last release before this changelog was started; see the git history for
this and the earlier tags.

## [0.2.0] - 2026-10-03

## [0.1.0] - 2026-09-28

[Unreleased]: https://github.com/Get-Sybers/gomount/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Get-Sybers/gomount/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Get-Sybers/gomount/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Get-Sybers/gomount/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Get-Sybers/gomount/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Get-Sybers/gomount/releases/tag/v0.1.0
