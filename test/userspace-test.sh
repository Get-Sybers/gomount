#!/usr/bin/env bash
#
# gomount integration USERSPACE TEST: ls/cat/stat/stream straight from the
# in-process parser — no mount, no FUSE, no privilege, so NO environment
# SKIP path: it must reach a verdict wherever ntfs-3g (fixture builders) and
# the binary exist. Full design and assertions: README.md "Run". Exit 0
# proven, 2 failed. GOMOUNT_BIN overrides the binary; else PATH, else a Go
# toolchain builds it from this checkout.
set -u -o pipefail

# ----------------------------------------------------------------------------- config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"      # the gomount Go module root
GOMOUNT_BIN="${GOMOUNT_BIN:-}"                  # empty => discover or build below
WORK="${WORK:-/work}"                           # writable scratch (also holds the image)
IMG="${IMG:-$WORK/ntfs.img}"
SECTORS="${SECTORS:-40960}"                      # 40960 * 512 = 20 MiB superfloppy
SECTOR_SIZE="${SECTOR_SIZE:-512}"
LABEL="${LABEL:-GOMOUNTUS}"
SEED_NAME="HELLO.txt"
SEED_SRC="$WORK/seed.txt"
SEED_TEXT="gomount userspace read-only proof"

log()  { printf '[userspace-test] %s\n' "$*"; }
ok()   { printf '[userspace-test] PASS: %s\n' "$*"; }
fail() { printf '[userspace-test] FAIL: %s\n' "$*" >&2; }
die()  { fail "$*"; exit 2; }

# ----------------------------------------------------------------------------- env report
environment_report() {
  log "================= ENVIRONMENT REPORT ================="
  log "kernel:            $(uname -sr)"
  log "id:                $(id)"
  # The whole selling point: this backend needs NONE of these.
  [ -e /dev/fuse ] && log "/dev/fuse:         present (NOT USED by this backend)" \
                    || log "/dev/fuse:         absent  (NOT NEEDED — pure userspace)"
  [ -e /dev/kvm  ] && log "/dev/kvm:          present (NOT USED by this backend)" \
                    || log "/dev/kvm:          absent  (NOT NEEDED — pure userspace)"
  log "mkntfs:            $(command -v mkntfs || echo MISSING)"
  log "ntfscp:            $(command -v ntfscp || echo MISSING)"
  log "go toolchain:      $(command -v go || echo 'none (need a prebuilt gomount)')"
  log "====================================================="
}

# ----------------------------------------------------------------------------- prerequisites
require_tools() {
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found (coreutils)."
  command -v mkntfs   >/dev/null 2>&1 || die "mkntfs not found — install the ntfs-3g package (apt-get install ntfs-3g)."
  command -v ntfscp   >/dev/null 2>&1 || die "ntfscp not found — install the ntfs-3g package (apt-get install ntfs-3g)."
}

# ensure_gomount resolves a runnable gomount binary into GOMOUNT_BIN: an explicit
# override, else one on PATH, else built from this checkout with `go build`.
ensure_gomount() {
  if [ -n "$GOMOUNT_BIN" ]; then
    command -v "$GOMOUNT_BIN" >/dev/null 2>&1 || [ -x "$GOMOUNT_BIN" ] \
      || die "GOMOUNT_BIN=$GOMOUNT_BIN is not an executable."
    log "using gomount: $GOMOUNT_BIN"
    return 0
  fi
  if command -v gomount >/dev/null 2>&1; then
    GOMOUNT_BIN="gomount"; log "using gomount on PATH: $(command -v gomount)"; return 0
  fi
  if command -v go >/dev/null 2>&1; then
    GOMOUNT_BIN="$WORK/gomount"
    log "building gomount from $MODULE_DIR -> $GOMOUNT_BIN"
    ( cd "$MODULE_DIR" && CGO_ENABLED=0 go build -o "$GOMOUNT_BIN" . ) \
      || die "go build of gomount failed."
    return 0
  fi
  die "no gomount binary: set GOMOUNT_BIN, put gomount on PATH, or provide a Go toolchain."
}

# ----------------------------------------------------------------------------- fixture
build_fixture() {
  mkdir -p "$WORK"
  log "creating a $((SECTORS * SECTOR_SIZE / 1024 / 1024)) MiB partitionless (superfloppy) NTFS volume file: $IMG"
  # mkntfs does NOT create the backing file; pre-size it, then format in place.
  # No loop device, no privilege: mkntfs writes NTFS structures straight to the file.
  truncate -s "$((SECTORS * SECTOR_SIZE))" "$IMG"
  if ! mkntfs -F -Q -L "$LABEL" -s "$SECTOR_SIZE" "$IMG" "$SECTORS" >/tmp/mkntfs.log 2>&1; then
    fail "mkntfs failed:"; cat /tmp/mkntfs.log >&2; exit 2
  fi
  # Seed one KNOWN file so the read verbs have a real, verifiable target — WITHOUT
  # privilege and WITHOUT mounting: ntfscp writes into the image via libntfs
  # directly. (An empty NTFS root would show only $-prefixed system files.)
  printf '%s\n' "$SEED_TEXT" > "$SEED_SRC"
  if ! ntfscp "$IMG" "$SEED_SRC" "$SEED_NAME" >/tmp/ntfscp.log 2>&1; then
    fail "ntfscp seed of $SEED_NAME failed:"; cat /tmp/ntfscp.log >&2; exit 2
  fi
  SEED_SHA="$(sha256sum "$SEED_SRC" | cut -d' ' -f1)"
  SEED_SIZE="$(stat -c %s "$SEED_SRC")"
  log "seeded $SEED_NAME ($SEED_SIZE bytes, sha256 ${SEED_SHA:0:16}...) with ntfscp (no mount, unprivileged)"
  # Nested-dir seeding needs ntfsmkdir, which Debian's ntfs-3g package does not
  # ship; the whole-filesystem `stream` walk still descends the NTFS system
  # directories ($Extend and friends), so recursion is exercised regardless.
  command -v ntfsmkdir >/dev/null 2>&1 \
    || log "note: ntfsmkdir not present — nested-dir seed skipped; stream walks the system tree for recursion"
}

# ----------------------------------------------------------------------------- assertions
# Baseline hash BEFORE any gomount read, so the read-only proof covers every verb.
snapshot_before() {
  IMG_BEFORE="$(sha256sum "$IMG" | cut -d' ' -f1)"
  log "sha256(image) before any read: $IMG_BEFORE"
}

assert_ls() {
  # The long listing (-l) is the verb that carries the size column; a bare `ls`
  # prints names only, like the coreutils tool it mirrors.
  local out
  if ! out="$("$GOMOUNT_BIN" ls -l "$IMG" 2>/tmp/ls.err)"; then
    fail "A: gomount ls -l exited non-zero:"; cat /tmp/ls.err >&2; return 1
  fi
  local line
  line="$(printf '%s\n' "$out" | grep -F "$SEED_NAME" | head -1)"
  if [ -z "$line" ]; then
    fail "A: gomount ls -l did not list $SEED_NAME:"; printf '%s\n' "$out" | sed 's/^/[userspace-test]   /' >&2
    return 1
  fi
  if printf '%s' "$line" | grep -qw "$SEED_SIZE"; then
    ok "A: gomount ls -l lists $SEED_NAME with size $SEED_SIZE  ->  $line"
  else
    fail "A: gomount ls -l line for $SEED_NAME lacks the exact size $SEED_SIZE:  $line"; return 1
  fi
}

assert_cat() {
  if ! "$GOMOUNT_BIN" cat "$IMG" "$SEED_NAME" >/tmp/cat.out 2>/tmp/cat.err; then
    fail "B: gomount cat exited non-zero:"; cat /tmp/cat.err >&2; return 1
  fi
  local got; got="$(sha256sum /tmp/cat.out | cut -d' ' -f1)"
  if [ "$got" = "$SEED_SHA" ]; then
    ok "B: gomount cat $SEED_NAME is byte-identical to the seed (sha256 ${got:0:16}...)"
  else
    fail "B: gomount cat $SEED_NAME sha256 mismatch: got $got, want $SEED_SHA"
    log  "   got  $(wc -c </tmp/cat.out) bytes; seed $SEED_SIZE bytes"; return 1
  fi
}

assert_stat() {
  local out
  if ! out="$("$GOMOUNT_BIN" stat "$IMG" "$SEED_NAME" 2>/tmp/stat.err)"; then
    fail "C: gomount stat exited non-zero:"; cat /tmp/stat.err >&2; return 1
  fi
  # "sane metadata": the entry's own name AND its exact byte size both present.
  if printf '%s' "$out" | grep -qF "$SEED_NAME" && printf '%s' "$out" | grep -qw "$SEED_SIZE"; then
    ok "C: gomount stat $SEED_NAME prints the name and size $SEED_SIZE:"
    printf '%s\n' "$out" | sed 's/^/[userspace-test]   /'
  else
    fail "C: gomount stat $SEED_NAME missing name or size $SEED_SIZE:"
    printf '%s\n' "$out" | sed 's/^/[userspace-test]   /' >&2; return 1
  fi
}

assert_stream() {
  if ! "$GOMOUNT_BIN" stream --jsonl "$IMG" >/tmp/stream.jsonl 2>/tmp/stream.err; then
    fail "D: gomount stream --jsonl exited non-zero:"; cat /tmp/stream.err >&2; return 1
  fi
  if [ ! -s /tmp/stream.jsonl ]; then
    fail "D: gomount stream --jsonl produced no output"; return 1
  fi
  if grep -qF "$SEED_NAME" /tmp/stream.jsonl; then
    ok "D: gomount stream --jsonl lists $SEED_NAME ($(wc -l </tmp/stream.jsonl) records total)"
  else
    fail "D: gomount stream --jsonl did not include $SEED_NAME:"; head -5 /tmp/stream.jsonl >&2; return 1
  fi
}

assert_readonly() {
  local after; after="$(sha256sum "$IMG" | cut -d' ' -f1)"
  log "sha256(image) after all reads: $after"
  if [ "$IMG_BEFORE" = "$after" ]; then
    ok "E: source image sha256 UNCHANGED across ls/cat/stat/stream (read-only proven)"
  else
    fail "E: source image sha256 CHANGED — a read verb wrote to evidence ($IMG_BEFORE -> $after)"; return 1
  fi
}

# ----------------------------------------------------------------------------- main
main() {
  environment_report
  require_tools
  ensure_gomount
  build_fixture
  snapshot_before

  local rc=0
  assert_ls     || rc=2
  assert_cat    || rc=2
  assert_stat   || rc=2
  assert_stream || rc=2
  # Read-only is the invariant that must hold no matter what the verbs reported.
  assert_readonly || rc=2

  if [ "$rc" -eq 0 ]; then
    log "ALL ASSERTIONS PASSED — gomount userspace backend proven with no mount/fuse/kvm/privilege."
  else
    fail "one or more assertions failed (see above)."
  fi
  exit "$rc"
}

main "$@"
