#!/usr/bin/env bash
# ==============================================================================
# structlint.sh — the structural lint of the Go conformance gate
# (go-standards.md §1–§3, §6, §7, §11, §13; build-and-test.md §2.2 and the
# `structure` job of §3.1). git and shell only: no Python, no network.
#
#   §1   the module path is github.com/Get-Sybers/<repo>[/<dir>], the
#        repository's name exactly (case included)
#   §2   no `replace` that points at a filesystem path in a committed go.mod
#   §3   `package main` lives under cmd/<name>/ or at a module root (the
#        one-command module); anything else is reported as layout backlog
#   §6   no exported Get* function or method — STRUCTLINT_ALLOW_GETTERS=1 for
#        a module that mirrors a foreign API for interoperability, the one
#        exception the standard grants
#   §7   no byte-identical tracked file in two places
#   §11  no third-party assertion library among the direct requirements; a
#        package without tests is reported as backlog
#   §13  the must-have files, CHANGELOG.md with an `## [Unreleased]` section
#
# [fail] exits non-zero; [warn] is backlog the gate reports but does not block.
# Usage: scripts/structlint.sh
# ==============================================================================
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.." || exit 2

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  OK=$'\033[38;5;172m' ERR=$'\033[38;5;167m' WRN=$'\033[38;5;173m' DIM=$'\033[38;5;245m' RST=$'\033[0m'
else
  OK='' ERR='' WRN='' DIM='' RST=''
fi
pass=0 fail=0 warned=0
ok() {
  printf '%s[ ok ]%s %s\n' "$OK" "$RST" "$*"
  pass=$((pass + 1))
}
bad() {
  printf '%s[fail]%s %s\n' "$ERR" "$RST" "$*" >&2
  fail=$((fail + 1))
}
warn() {
  printf '%s[warn]%s %s\n' "$WRN" "$RST" "$*"
  warned=$((warned + 1))
}
note() { printf '       %s%s%s\n' "$DIM" "$*" "$RST"; }

ORG="Get-Sybers"
EMPTY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ASSERTION_LIBS='^(github\.com/stretchr/testify|github\.com/onsi/gomega|github\.com/onsi/ginkgo|gotest\.tools|github\.com/alecthomas/assert|github\.com/matryer/is)(/|$)'

# the repository's name: GITHUB_REPOSITORY in CI, the origin remote locally
repo_name() {
  local full="${GITHUB_REPOSITORY:-}"
  if [[ -z "$full" ]]; then
    full=$(git remote get-url origin 2>/dev/null | sed -E 's#\.git$##; s#^.*[:/]([^/]+/[^/]+)$#\1#')
  fi
  printf '%s\n' "${full##*/}"
}
REPO=$(repo_name)

# ---- §1, §2, §11: every go.mod -------------------------------------------------
while IFS= read -r modfile; do
  dir=$(dirname "$modfile")
  path=$(sed -n 's/^module //p' "$modfile" | head -1)
  want="github.com/$ORG/$REPO"
  [[ "$dir" != "." ]] && want="$want/$dir"
  if [[ -z "$REPO" ]]; then
    case "$path" in
      "github.com/$ORG/"*) ok "$modfile: module path $path (repository name unknown here: prefix checked)" ;;
      *) bad "$modfile: module path $path is not under github.com/$ORG/ (go-standards §1)" ;;
    esac
  elif [[ "$path" == "$want" ]]; then
    ok "$modfile: module path $path"
  else
    bad "$modfile: module path $path — want $want (go-standards §1: github.com/$ORG/<repo>, the repository's name exactly)"
  fi

  modjson=$(cd "$dir" && go mod edit -json 2>/dev/null)
  if printf '%s\n' "$modjson" | grep -qE '"Path": "(\.|/|[A-Za-z]:\\)'; then
    bad "$modfile: a replace points at a filesystem path — a workspace convenience, never committed (go-standards §2)"
  else
    ok "$modfile: no filesystem replace"
  fi

  direct=$(printf '%s\n' "$modjson" | awk 'BEGIN { RS = "}" } /"Path":/ && !/"Indirect": true/ { if (match($0, /"Path": "[^"]+"/)) print substr($0, RSTART + 9, RLENGTH - 10) }')
  if libs=$(printf '%s\n' "$direct" | grep -E "$ASSERTION_LIBS"); then
    bad "$modfile: third-party assertion library (go-standards §11 — explicit got/want on the standard testing package): ${libs//$'\n'/ }"
  else
    ok "$modfile: no third-party assertion library"
  fi

  untested=$(cd "$dir" && go list -f '{{if and (ne .Name "main") (not .TestGoFiles) (not .XTestGoFiles)}}{{.ImportPath}}{{end}}' ./... 2>/dev/null)
  if [[ -n "$untested" ]]; then
    warn "$modfile: package(s) without tests (go-standards §11 — testing backlog): ${untested//$'\n'/ }"
  else
    ok "$modfile: every package has tests"
  fi
done < <(git ls-files -- 'go.mod' '*/go.mod')

# ---- §3 layout --------------------------------------------------------------------
stray=()
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  dir=$(dirname "$f")
  case "$dir" in
    . | cmd/* | */cmd/* | *testdata*) continue ;;
    *) ;;
  esac
  [[ -f "$dir/go.mod" ]] && continue
  stray+=("$f")
done < <(git ls-files -z -- '*.go' | xargs -0 -r grep -l '^package main$' | grep -v '_test\.go$')
if ((${#stray[@]})); then
  warn "package main outside cmd/<name>/ or a module root (go-standards §3 — layout backlog): ${stray[*]}"
else
  ok "package main only under cmd/<name>/ or at a module root"
fi

# ---- §6 naming --------------------------------------------------------------------
getters=$(git ls-files -z -- '*.go' | xargs -0 -r grep -nE '^func (\([^)]*\) )?Get[A-Z]' | grep -v '_test\.go:' || true)
if [[ -z "$getters" ]]; then
  ok "no exported Get* accessor"
elif [[ "${STRUCTLINT_ALLOW_GETTERS:-0}" == "1" ]]; then
  note "$(printf '%s\n' "$getters" | wc -l) Get* names kept: this module mirrors a foreign API, the one exception of go-standards §6"
  ok "Get* accessors (declared API mirror)"
else
  bad "exported Get* accessor(s) — a name states the verb of the work (go-standards §6):"
  printf '%s\n' "$getters" | head -10 | sed 's/^/       /' >&2
fi

# ---- §7 duplication ------------------------------------------------------------------
dups=$(git ls-files -z | xargs -0 -r sha256sum 2>/dev/null | grep -v "^$EMPTY_SHA256" \
  | awk '{ h = $1; f = substr($0, 67); c[h]++; files[h] = files[h] " " f } END { for (h in c) if (c[h] > 1) print files[h] }')
if [[ -z "$dups" ]]; then
  ok "no byte-identical file in two places"
else
  bad "byte-identical files — one home, imported (go-standards §7):"
  printf '%s\n' "$dups" | sed 's/^/       /' >&2
fi

# ---- §13 and build-and-test.md §2.1: the must-have files -------------------------------
for f in README.md CHANGELOG.md .gitignore Makefile go.mod .golangci.yml .editorconfig .gitattributes .shellcheckrc \
  .github/CODEOWNERS .github/SECURITY.md .github/dependabot.yml .github/pull_request_template.md .github/workflows/ci.yml; do
  if [[ -f "$f" ]]; then
    ok "$f"
  else
    bad "$f is missing (build-and-test.md §2, go-standards §13)"
  fi
done
if [[ -f LICENSE ]]; then
  ok "LICENSE"
else
  warn "LICENSE is missing (go-standards §13) — the licence is the owner's decision; add the file to clear this"
fi
if grep -q '^## \[Unreleased\]' CHANGELOG.md 2>/dev/null; then
  ok "CHANGELOG.md has an [Unreleased] section"
else
  bad "CHANGELOG.md has no '## [Unreleased]' section (Keep a Changelog)"
fi

echo
summary=""
((warned)) && summary=", $warned backlog warning(s)"
if [[ $fail -eq 0 ]]; then
  printf '%sstructlint: %d checks passed%s%s\n' "$OK" "$pass" "$summary" "$RST"
  exit 0
fi
printf '%sstructlint: %d passed, %d FAILED%s%s\n' "$ERR" "$pass" "$fail" "$summary" "$RST"
exit 1
