#!/usr/bin/env bash
# ==============================================================================
# go-upgrade.sh — raise the module to the highest versions its hard limits
# allow, then prove the result (go-standards.md §12).
#
# For every module (the go.work modules, or the module at the repository
# root): raise each dependency to the newest release its constraints permit
# (go get -u, which never crosses a floor or ceiling the module or its graph
# declares), raise the `go` directive to the toolchain in use, and tidy. Then
# run go-conform.sh; the changes are only sound if it passes.
#
# The hard limits — a dependency's floor, a security minimum, an API ceiling —
# are declared in go.mod (require/exclude) and are the only thing that holds
# a version back. There is no blind `-u=patch`; this resolves the true maximum.
#
# Usage: scripts/go-upgrade.sh [module-dir ...]
# ==============================================================================
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.." || exit 2
ROOT="$PWD"

TOOLVER=$(go env GOVERSION | sed 's/^go//') # e.g. 1.27.1

modules() {
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@"
  elif [[ -f go.work ]]; then
    go work edit -json | sed -n 's/.*"DiskPath": "\(.*\)".*/\1/p'
  else
    echo .
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
  [[ -f "$d/go.mod" ]] || continue
  echo ">> upgrading $name"
  (cd "$d" && go get -u ./... && go mod edit -go="$TOOLVER" && go mod tidy) || {
    echo "upgrade failed in $name" >&2
    exit 1
  }
done

# keep the workspace's own directive in step with the toolchain
[[ -f go.work ]] && go work edit -go="$TOOLVER"

echo ">> re-running conform"
exec "$ROOT/scripts/go-conform.sh"
