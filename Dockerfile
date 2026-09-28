# syntax=docker/dockerfile:1
# gomount — one NTFS volume from a disk image: userspace stream/materialise/ls,
# or an unprivileged read-only FUSE mount that EXECs the distro ntfs-3g (never
# links it). DECLARED DEVIATION (docs/framework 05 §5.9): debian:trixie-slim
# runtime, shell=true declared; apt/dpkg removed, setuid stripped. Pipeline,
# build and run docs: README.md.

ARG GO_IMAGE=golang:trixie
ARG RUNTIME_IMAGE=debian:trixie-slim
ARG TOOL_VERSION=0.4.0
ARG GODFIR_REVISION=unknown
ARG GODFIR_RELEASE=dev

FROM ${GO_IMAGE} AS build
ARG TOOL_VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# static, trimmed, CGO off — gomount only execs ntfs-3g, never links it
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${TOOL_VERSION}" -o /gomount .
# sanity gate: no args must print usage and exit 1 (a panic exits differently and fails the build)
RUN /gomount >/dev/null 2>&1; [ $? -eq 1 ]

FROM ${RUNTIME_IMAGE} AS runtime
ARG DFIR_UID=2000
ARG DFIR_GID=2000
# fuse3 (fusermount3) + ntfs-3g, then the standard strip: pkg mgr, escalation
# binaries, every setuid bit (root-inside-a-userns needs no setuid fusermount3)
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends fuse3 ntfs-3g; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt /var/lib/dpkg /usr/share/doc /usr/share/man; \
    rm -f /usr/bin/apt* /usr/bin/dpkg* /usr/sbin/apt* /usr/bin/add-apt-repository \
          /usr/bin/sudo /usr/bin/su /bin/su /usr/bin/pkexec /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn \
          /usr/bin/gpasswd /usr/bin/newgrp /usr/sbin/usermod /usr/sbin/useradd /usr/sbin/userdel \
          /usr/sbin/groupmod /usr/sbin/groupadd /usr/sbin/groupdel; \
    find / -xdev -perm /6000 -type f -exec chmod a-s {} +; \
    sed -i 's|^root:\([^:]*\):0:0:[^:]*:\([^:]*\):.*$|ansible:\1:0:0:ansible:\2:/usr/sbin/nologin|' /etc/passwd; \
    sed -i 's|^root:[^:]*:|ansible:!:|' /etc/shadow; \
    sed -i 's|^root:|ansible:|' /etc/group /etc/gshadow; \
    mkdir -p /mnt/ntfs; \
    chown ${DFIR_UID}:${DFIR_GID} /mnt/ntfs; \
    printf 'schema=1\ntool=gomount\nuser=dfir uid=%s gid=%s\nstatic_binary=false\nshell=true python=false pkg_mgr=false\n' \
      "${DFIR_UID}" "${DFIR_GID}" > /etc/dfir-hardened; \
    chmod 0444 /etc/dfir-hardened
COPY --from=build /gomount /usr/local/bin/gomount
COPY --chmod=0644 contract.yml /opt/gomount/contract.yml
# the integration mount test travels with the image (any host with /dev/fuse + unpriv userns can run it)
COPY --chmod=0755 test/mount-test.sh /test/mount-test.sh

FROM scratch
COPY --from=runtime / /
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG TOOL_VERSION
ARG GODFIR_REVISION
ARG GODFIR_RELEASE
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache
# the unprivileged uid IS the unprivileged-mount path (it maps itself to root-inside-a-userns)
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/usr/local/bin/gomount"]
LABEL org.opencontainers.image.title="get-sybers/gomount" \
      org.opencontainers.image.description="Read one NTFS volume from an E01/raw disk image: stream a tar of every file to stdout, materialise artefact sets into a directory, or ls/cat/stat/tree/browse it in userspace with no privilege; or mount it read-only over FUSE + the distro ntfs-3g (a separate process, never linked) root-inside-a-user-namespace: no CAP_SYS_ADMIN, no loop device, no --privileged. debian:trixie-slim runtime (declared deviation: shell kept for the ntfs-3g helpers; apt/dpkg removed, setuid stripped), runs as uid 2000. argv-driven (streaming verbs)." \
      org.opencontainers.image.source="https://github.com/Get-Sybers/GoDFIR-toolz" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.revision="${GODFIR_REVISION}" \
      com.get-sybers.tool="gomount" \
      com.get-sybers.hardened="true" \
      com.get-sybers.contract="1" \
      com.get-sybers.godfir-release="${GODFIR_RELEASE}" \
      com.get-sybers.runtime="debian-trixie-slim (execs ntfs-3g; never links libntfs-3g)"
