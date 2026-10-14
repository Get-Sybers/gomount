#!/usr/bin/env bash
# ==============================================================================
# go-conform.sh — the Go conformance gate (go-standards.md §12, §14;
# build-and-test.md §3.2). One command, exit non-zero on any failure, run by
# CI and locally as `make conform`.
#
# For every module (the go.work modules, or the module at the repository
# root), in order:
#   gofmt -l            on the tracked Go files (never a cache or vendor tree)
#   go vet              (+ VET_FLAGS)
#   go build ./...
#   go test             (TEST_FLAGS: -count=1 -shuffle=on -cover)
#   go mod tidy -diff   go.mod / go.sum drift
#   BUILD_TAGS          each extra tag set must vet, build and test too (§9)
#   CROSS_TARGETS       each GOOS/GOARCH pair must build with CGO_ENABLED=0
#   go generate         then a drift check, when the module declares a directive (§5)
# then scripts/structlint.sh: module path, layout, naming, duplication and the
# must-have files.
#
# golangci-lint (.golangci.yml) and govulncheck are the `lint` and `vuln`
# targets; CI runs them beside this gate through the official actions.
#
# Usage: scripts/go-conform.sh [module-dir ...]   (default: every module)
# The knobs come from the Makefile, exported: VET_FLAGS TEST_FLAGS BUILD_TAGS
# CROSS_TARGETS.
# ==============================================================================
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.." || exit 2
ROOT="$PWD"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  OK=$'\033[38;5;172m' ERR=$'\033[38;5;167m' DIM=$'\033[38;5;245m' RST=$'\033[0m'
else
  OK='' ERR='' DIM='' RST=''
fi
pass=0 fail=0
ok() {
  printf '%s[ ok ]%s %s\n' "$OK" "$RST" "$*"
  pass=$((pass + 1))
}
bad() {
  printf '%s[fail]%s %s\n' "$ERR" "$RST" "$*" >&2
  fail=$((fail + 1))
}
note() { printf '       %s%s%s\n' "$DIM" "$*" "$RST"; }

TEST_FLAGS="${TEST_FLAGS:--count=1 -shuffle=on -cover}"
read -ra test_flags <<<"$TEST_FLAGS"
read -ra vet_flags <<<"${VET_FLAGS:-}"
read -ra build_tags <<<"${BUILD_TAGS:-}"
read -ra cross_targets <<<"${CROSS_TARGETS:-}"

# every module: the arguments given, else the go.work modules, else the root
modules() {
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@"
  elif [[ -f go.work ]]; then
    go work edit -json | sed -n 's/.*"DiskPath": "\(.*\)".*/\1/p'
  else
    echo .
  fi
}

# check <label> <dir> <command...> — passes on exit 0; on failure the first
# lines of the output (the per-package test noise filtered) are shown
check() {
  local label=$1 dir=$2 out
  shift 2
  if out=$(cd "$dir" && "$@" 2>&1); then
    ok "$label"
  else
    bad "$label"
    printf '%s\n' "$out" | grep -vE '^(ok|\?) ' | head -12 | sed 's/^/       /' >&2
  fi
}

mapfile -t MODS < <(modules "$@")
for m in "${MODS[@]}"; do
  rel="${m#./}"
  rel="${rel%/}"
  if [[ -z "$rel" || "$rel" == "." ]]; then
    d="$ROOT"
    name="$(basename "$ROOT")"
  else
    d="$ROOT/$rel"
    name="$rel"
  fi
  if [[ ! -f "$d/go.mod" ]]; then
    bad "$name: no go.mod"
    continue
  fi

  # gofmt on the tracked files; a parse error fails, never passes silently
  if ! unformatted=$(cd "$d" && git ls-files -z -- '*.go' | xargs -0 -r gofmt -l 2>&1); then
    bad "$name: gofmt errored:"
    printf '%s\n' "$unformatted" | head -6 | sed 's/^/       /' >&2
  elif [[ -n "$unformatted" ]]; then
    bad "$name: gofmt needed (make fmt): ${unformatted//$'\n'/ }"
  else
    ok "$name: gofmt"
  fi

  check "$name: go vet ${VET_FLAGS:-}" "$d" go vet "${vet_flags[@]}" ./...
  check "$name: go build" "$d" go build ./...
  check "$name: go test $TEST_FLAGS" "$d" go test "${test_flags[@]}" ./...
  check "$name: go mod tidy -diff" "$d" go mod tidy -diff

  for tags in "${build_tags[@]}"; do
    check "$name: go vet -tags $tags" "$d" go vet "${vet_flags[@]}" -tags "$tags" ./...
    check "$name: go build -tags $tags" "$d" env CGO_ENABLED=0 go build -tags "$tags" ./...
    check "$name: go test -tags $tags" "$d" env CGO_ENABLED=0 go test "${test_flags[@]}" -tags "$tags" ./...
  done

  for target in "${cross_targets[@]}"; do
    check "$name: go build GOOS=${target%/*} GOARCH=${target#*/}" "$d" \
      env CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go build ./...
  done

  # go:generate drift, when the module declares a directive: a generated
  # artefact that differs from its data file fails (go-standards §5)
  if (cd "$d" && git ls-files -z -- '*.go' | xargs -0 -r grep -l '^//go:generate' | grep -q .); then
    before=$(cd "$d" && git status --porcelain -- . | sort)
    if gen_out=$(cd "$d" && go generate ./... 2>&1); then
      after=$(cd "$d" && git status --porcelain -- . | sort)
      drift=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))
      if [[ -z "$drift" ]]; then
        ok "$name: go generate (no drift)"
      else
        bad "$name: go generate drift — commit the regenerated files:"
        printf '%s\n' "$drift" | sed 's/^/       /' >&2
      fi
    else
      bad "$name: go generate failed"
      printf '%s\n' "$gen_out" | head -6 | sed 's/^/       /' >&2
    fi
  else
    note "$name: no go:generate directive (drift check not applicable)"
  fi
done

# the structural lint: its own report lines, one gate
if "$ROOT/scripts/structlint.sh"; then
  ok "structlint"
else
  bad "structlint"
fi

echo
if [[ $fail -eq 0 ]]; then
  printf '%sconform: %d checks passed%s\n' "$OK" "$pass" "$RST"
  exit 0
fi
printf '%sconform: %d passed, %d FAILED%s\n' "$ERR" "$pass" "$fail" "$RST"
exit 1
