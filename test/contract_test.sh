#!/usr/bin/env bash
# The framework conformance smoke test for gomount — a declared argv
# deviation, so it asserts the hardening contract and the argv modes instead
# of a batch summary line. The mount and userspace verbs live in
# test/mount-test.sh and test/userspace-test.sh (they need /dev/fuse +
# mkntfs). IMAGE=<ref> reuses a built image.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_dir="$(dirname "$here")"
IMAGE="${IMAGE:-contract-test/gomount:latest}"
if [[ -z "${IMAGE_PREBUILT:-}" && "$IMAGE" == contract-test/* ]]; then
    echo "== building $IMAGE (context gomount)"
    docker build -q -t "$IMAGE" -f "$tool_dir/Dockerfile" "$tool_dir" >/dev/null
fi
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT

echo "== 1. built image identity and labels"
usr="$(docker image inspect -f '{{.Config.User}}' "$IMAGE")"
[[ "$usr" == "2000:2000" ]] || { echo "FAIL USER=$usr" >&2; exit 1; }
for L in com.get-sybers.tool com.get-sybers.hardened com.get-sybers.contract \
         org.opencontainers.image.version org.opencontainers.image.revision com.get-sybers.godfir-release; do
    v="$(docker image inspect -f "{{index .Config.Labels \"$L\"}}" "$IMAGE")"
    [[ -n "$v" && "$v" != "<no value>" ]] || { echo "FAIL label $L missing" >&2; exit 1; }
done
[[ "$(docker image inspect -f '{{index .Config.Labels "com.get-sybers.tool"}}' "$IMAGE")" == gomount ]] || { echo "FAIL tool label" >&2; exit 1; }

echo "== 2. self-declaration vs filesystem"
cid="$(docker create "$IMAGE" __export__)"
docker export "$cid" | tar -t > "$scratch/fs"
docker export "$cid" | tar -xO etc/dfir-hardened > "$scratch/decl"
docker rm -f "$cid" >/dev/null
grep -q '^schema=1$' "$scratch/decl" && grep -q '^tool=gomount$' "$scratch/decl" && grep -q 'shell=true python=false pkg_mgr=false' "$scratch/decl" \
    || { echo "FAIL declaration:"; cat "$scratch/decl"; exit 1; } >&2
grep -qE '(^|/)bin/python3' "$scratch/fs" && { echo "FAIL python present" >&2; exit 1; }
grep -qE '(^|/)(usr/)?bin/(apt-get|dpkg|sudo)$' "$scratch/fs" && { echo "FAIL apt/dpkg/sudo present" >&2; exit 1; }
grep -qE '(^|/)bin/(sh|dash)$' "$scratch/fs" || { echo "FAIL declares shell=true but no shell found" >&2; exit 1; }
grep -qE '(^|/)usr/local/bin/gomount$' "$scratch/fs" || { echo "FAIL gomount binary missing" >&2; exit 1; }

echo "== 3. argv modes"
rc=0; docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$IMAGE" >"$scratch/o1" 2>"$scratch/e1" || rc=$?
[[ "$rc" -eq 1 ]] || { echo "FAIL no-args exit $rc, want 1" >&2; cat "$scratch/e1" >&2; exit 1; }
[[ ! -s "$scratch/o1" ]] || { echo "FAIL no-args wrote to stdout" >&2; exit 1; }
rc=0; docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$IMAGE" stream /evidence/missing.E01 >"$scratch/o2" 2>"$scratch/e2" || rc=$?
[[ "$rc" -ne 0 ]] || { echo "FAIL stream of a missing image exited 0" >&2; exit 1; }
[[ ! -s "$scratch/o2" ]] || { echo "FAIL stream of a missing image wrote to stdout" >&2; exit 1; }

echo "PASS gomount contract test"
