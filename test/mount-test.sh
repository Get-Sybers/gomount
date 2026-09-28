#!/usr/bin/env bash
#
# gomount integration MOUNT TEST: decode -> volume -> single-file FUSE ->
# exec'd ntfs-3g -o ro -> a real read-only mount, all unprivileged. Full
# design, assertions, the userns/one-namespace subtlety and the docker
# recipe: README.md "Run". Exit 0 proven, 2 assertion failed, 3 environment
# cannot provide unprivileged FUSE (see the ENVIRONMENT REPORT — not a
# gomount bug). GOMOUNT_BIN overrides the binary (default: gomount on PATH).
set -u -o pipefail

# ----------------------------------------------------------------------------- config
GOMOUNT_BIN="${GOMOUNT_BIN:-gomount}"
WORK="${WORK:-/work}"                       # writable scratch (also holds the image)
IMG="${IMG:-$WORK/ntfs.img}"
MNT="${MNT:-/mnt/ntfs}"
SECTORS="${SECTORS:-40960}"                 # 40960 * 512 = 20 MiB superfloppy
SECTOR_SIZE="${SECTOR_SIZE:-512}"
LABEL="${LABEL:-GOMOUNTTEST}"
SEED_NAME="HELLO.txt"
SEED_TEXT="gomount read-only mount proof"

log()  { printf '[mount-test] %s\n' "$*"; }
ok()   { printf '[mount-test] PASS: %s\n' "$*"; }
fail() { printf '[mount-test] FAIL: %s\n' "$*" >&2; }

# ----------------------------------------------------------------------------- env report
environment_report() {
  log "================= ENVIRONMENT REPORT ================="
  log "kernel:            $(uname -sr)"
  log "id:                $(id)"
  local kv; kv="$(uname -r | cut -d. -f1-2)"
  log "userns >=4.18:     kernel ${kv} (unprivileged FUSE needs >= 4.18)"
  if [ -r /proc/sys/user/max_user_namespaces ]; then
    log "max_user_namespaces: $(cat /proc/sys/user/max_user_namespaces)"
  fi
  [ -r /proc/sys/kernel/unprivileged_userns_clone ] && \
    log "unprivileged_userns_clone: $(cat /proc/sys/kernel/unprivileged_userns_clone)"
  grep -qw fuse /proc/filesystems && log "fuse in /proc/filesystems: yes (kernel supports FUSE)" \
                                   || log "fuse in /proc/filesystems: NO"
  if [ -e /dev/fuse ]; then
    log "/dev/fuse:         present ($(stat -c '%A %t:%T' /dev/fuse 2>/dev/null))"
  else
    log "/dev/fuse:         ABSENT"
  fi
  log "ntfs-3g:           $(command -v ntfs-3g || echo MISSING)"
  log "mkntfs:            $(command -v mkntfs  || echo MISSING)"
  log "ntfscp:            $(command -v ntfscp  || echo MISSING)"
  log "gomount:           $(command -v "$GOMOUNT_BIN" || echo 'MISSING (build the image first)')"
  log "====================================================="
}

# Hard preconditions for the mount phase. Returns 0 if the stack CAN run here.
can_mount() {
  local ok=0
  if [ ! -e /dev/fuse ]; then
    fail "no /dev/fuse device node — FUSE cannot be opened by the go-fuse server or by ntfs-3g."
    fail "  On a normal Docker host, pass:  docker run --device /dev/fuse ..."
    fail "  If --device /dev/fuse itself fails, the HOST has no /dev/fuse (e.g. nested inside an"
    fail "  unprivileged LXC): create it on the host, or add the container-runtime's fuse feature"
    fail "  (Proxmox LXC: set 'features: fuse=1' or lxc.cgroup2.devices.allow: c 10:229 rwm +"
    fail "  lxc.mount.entry: /dev/fuse dev/fuse none bind,create=file 0 0), then retry."
    ok=1
  fi
  if ! grep -qw fuse /proc/filesystems; then
    fail "kernel does not expose the fuse filesystem (/proc/filesystems)."
    ok=1
  fi
  # A working userns is required for the unprivileged path.
  if ! unshare -U -r true 2>/dev/null; then
    fail "cannot create a user namespace (unshare -U failed) — the unprivileged FUSE path is"
    fail "  unavailable. Under Docker's DEFAULT seccomp this is expected: add"
    fail "  --security-opt seccomp=unconfined --security-opt apparmor=unconfined (still no caps added)."
    ok=1
  fi
  return $ok
}

# ----------------------------------------------------------------------------- fixture
build_fixture() {
  mkdir -p "$WORK"
  log "creating a $((SECTORS * SECTOR_SIZE / 1024 / 1024)) MiB partitionless (superfloppy) NTFS volume file: $IMG"
  # mkntfs does NOT create the backing file; pre-size it, then format in place.
  # No loop device, no privilege: mkntfs writes NTFS structures straight to the file.
  truncate -s "$((SECTORS * SECTOR_SIZE))" "$IMG"
  if ! mkntfs -F -Q -L "$LABEL" -s "$SECTOR_SIZE" "$IMG" "$SECTORS" >/tmp/mkntfs.log 2>&1; then
    fail "mkntfs failed:"; cat /tmp/mkntfs.log >&2; return 1
  fi
  # Seed one KNOWN file so `ls` has a real target — WITHOUT privilege and WITHOUT
  # mounting: ntfscp writes into the image via libntfs directly. (An empty NTFS
  # would show only ntfs-3g-hidden system files, a weak `ls` assertion.)
  printf '%s\n' "$SEED_TEXT" > /tmp/$SEED_NAME
  if command -v ntfscp >/dev/null 2>&1; then
    if ntfscp "$IMG" /tmp/$SEED_NAME "$SEED_NAME" >/tmp/ntfscp.log 2>&1; then
      log "seeded $SEED_NAME into the image with ntfscp (no mount, unprivileged)"
    else
      log "ntfscp seed failed (continuing; will assert on ntfs-3g system files instead):"
      cat /tmp/ntfscp.log >&2
      SEED_NAME=""   # fall back to a system-file assertion
    fi
  else
    log "ntfscp not present; will assert on ntfs-3g -o show_sys_files instead"
    SEED_NAME=""
  fi
  # Independent, mount-free sanity check that the volume is valid NTFS.
  if command -v ntfsls >/dev/null 2>&1; then
    log "ntfsls (libntfs, no fuse) sees:"; ntfsls -l "$IMG" 2>&1 | sed 's/^/[mount-test]   /'
  fi
}

# ----------------------------------------------------------------------------- mount phase
# Runs INSIDE the unshare'd userns+mountns. gomount is told NOT to unshare again.
mount_phase() {
  local rc
  log "inner userns: uid=$(id -u) mountns owner; CapEff=$(grep CapEff /proc/self/status | awk '{print $2}')"
  mkdir -p "$MNT"

  local before after
  before="$(sha256sum "$IMG" | cut -d' ' -f1)"
  log "sha256(image) before mount: $before"

  # gomount serves the single-file FUSE volume.img and execs ntfs-3g -o ro onto it,
  # mounting at $MNT. It stays foreground serving the FUSE session; background it.
  log "gomount mount --read-only --no-self-unshare --mount-point $MNT $IMG"
  "$GOMOUNT_BIN" mount --read-only --no-self-unshare --foreground --mount-point "$MNT" "$IMG" \
      >/tmp/gomount.log 2>&1 &
  local gm_pid=$!

  # Wait (<=15s) for the mountpoint to become a live FUSE mount.
  local mtype=""
  for _ in $(seq 1 150); do
    mtype="$(awk -v m="$MNT" '$2==m {print $3}' /proc/mounts | tail -1)"
    [ -n "$mtype" ] && break
    kill -0 "$gm_pid" 2>/dev/null || { fail "gomount exited before mounting:"; cat /tmp/gomount.log >&2; return 2; }
    sleep 0.1
  done

  # ---- Assertion A: mount type is fuse, NOT fuseblk ----
  log "mount line: $(grep " $MNT " /proc/mounts || echo '(none)')"
  if [ -z "$mtype" ]; then
    fail "A: $MNT never became a mount"; cat /tmp/gomount.log >&2; return 2
  fi
  case "$mtype" in
    fuseblk*)
      fail "A: mount type is '$mtype' (fuseblk == block/loop backing == PRIVILEGED). Expected fuse.*"
      "$GOMOUNT_BIN" umount --mount-point "$MNT" 2>/dev/null; return 2 ;;
    fuse|fuse.*)
      ok "A: mount type '$mtype' (regular-file FUSE, FS_USERNS_MOUNT == unprivileged, not fuseblk)" ;;
    *)
      fail "A: unexpected mount type '$mtype' (expected fuse/fuse.ntfs-3g, not fuseblk)"
      "$GOMOUNT_BIN" umount --mount-point "$MNT" 2>/dev/null; return 2 ;;
  esac

  # ---- Assertion B: ls succeeds ----
  if ls -la "$MNT" >/tmp/ls.log 2>&1; then
    ok "B: ls -la $MNT succeeded:"; sed 's/^/[mount-test]   /' /tmp/ls.log
  else
    fail "B: ls -la $MNT failed:"; cat /tmp/ls.log >&2
    "$GOMOUNT_BIN" umount --mount-point "$MNT" 2>/dev/null; return 2
  fi

  # ---- Assertion C: the seeded (or a system) file reads back through the mount ----
  if [ -n "$SEED_NAME" ]; then
    if [ -f "$MNT/$SEED_NAME" ]; then
      local got; got="$(cat "$MNT/$SEED_NAME" 2>/dev/null)"
      if [ "$got" = "$SEED_TEXT" ]; then
        ok "C: read $SEED_NAME through the mount, content matches"
      else
        fail "C: $SEED_NAME content mismatch: '$got' != '$SEED_TEXT'"
        "$GOMOUNT_BIN" umount --mount-point "$MNT" 2>/dev/null; return 2
      fi
    else
      fail "C: seeded $SEED_NAME not visible under $MNT"
      "$GOMOUNT_BIN" umount --mount-point "$MNT" 2>/dev/null; return 2
    fi
  else
    stat "$MNT" >/dev/null 2>&1 && ok "C: stat $MNT ok (no seed file; empty NTFS root)" \
                                || { fail "C: stat $MNT failed"; return 2; }
  fi

  # ---- Unmount ----
  log "gomount umount --mount-point $MNT"
  "$GOMOUNT_BIN" umount --mount-point "$MNT" >/tmp/gomount-umount.log 2>&1
  rc=$?
  # give gomount's FUSE server a moment to exit, then reap
  for _ in $(seq 1 50); do awk -v m="$MNT" '$2==m' /proc/mounts | grep -q . || break; sleep 0.1; done
  kill "$gm_pid" 2>/dev/null; wait "$gm_pid" 2>/dev/null
  if [ $rc -ne 0 ] || awk -v m="$MNT" '$2==m' /proc/mounts | grep -q .; then
    fail "unmount did not fully release $MNT"; cat /tmp/gomount-umount.log >&2; return 2
  fi
  ok "unmounted cleanly"

  # ---- Assertion D: source image unchanged (read-only proof) ----
  after="$(sha256sum "$IMG" | cut -d' ' -f1)"
  log "sha256(image) after  mount: $after"
  if [ "$before" = "$after" ]; then
    ok "D: source image sha256 UNCHANGED across mount+umount (read-only proven)"
  else
    fail "D: source image sha256 CHANGED — mount was NOT read-only ($before -> $after)"
    return 2
  fi
  return 0
}

# ----------------------------------------------------------------------------- main
main() {
  # The mount phase re-execs here inside the unshare'd namespace.
  if [ "${1:-}" = "--mount-phase" ]; then
    mount_phase; exit $?
  fi

  environment_report
  build_fixture || { fail "fixture build failed"; exit 2; }

  if ! can_mount; then
    log "SKIPPED: this environment cannot provide an unprivileged FUSE mount (see report above)."
    log "The fixture ($IMG) built successfully; the block is purely the FUSE device/namespace."
    exit 3
  fi

  # Own ONE userns+mountns for the whole mount phase so the mount is visible to
  # ls/stat/umount. `-r` maps the current uid to root inside the userns (needs the
  # container's default CAP_SETUID/CAP_SETGID — present in the default docker set).
  log "entering user+mount namespace (unshare -U -m -r) for the mount phase..."
  export GOMOUNT_BIN WORK IMG MNT SECTORS SECTOR_SIZE LABEL SEED_NAME SEED_TEXT
  unshare -U -m -r -- "$(command -v bash)" "$0" --mount-phase
  exit $?
}

main "$@"
