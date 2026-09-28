//go:build linux

// Package userns ensures gomount runs as root INSIDE a user namespace, which is
// what lets it mount FUSE (and therefore ntfs-3g on a regular file) with no real
// privilege — no CAP_SYS_ADMIN, no setuid, no --privileged.
//
// Approach: gomount re-execs *itself* with a raw unshare of
// CLONE_NEWUSER|CLONE_NEWNS, mapping the caller's uid/gid to 0 inside the new
// namespaces. It is the pure-Go equivalent of
//
//	unshare -U -m -r -- gomount <args…>
//
// done via os/exec + syscall.SysProcAttr (Cloneflags + UidMappings/GidMappings)
// so it needs no util-linux binary. A new MOUNT namespace is REQUIRED, not
// optional: mounting FUSE needs CAP_SYS_ADMIN over the *target* mount namespace,
// and an unprivileged process only holds that for a mount namespace OWNED BY its
// own user namespace. The re-exec'd child therefore owns both, and its FUSE
// mounts live in — and only in — that mount namespace (see the visibility note
// in Ensure).
//
// Ensure is a no-op when the process already has what it needs: our own re-exec
// (an env sentinel marks it), or an environment that already placed us
// root-in-userns (rootless podman, or an outer `unshare -U -m -r`).
package userns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// sentinel marks a process this package has already re-exec'd, so the child does
// not recurse into a second, nested namespace.
const sentinel = "GOMOUNT_USERNS_BOOTSTRAPPED"

// Ensure guarantees the process is root inside a user namespace that owns its
// mount namespace. If it already is, Ensure returns nil and the caller proceeds.
// Otherwise Ensure re-execs the same binary and arguments inside fresh
// user+mount namespaces (caller mapped to root) and, in the PARENT, waits for
// that child and exits with the child's status — so on the re-exec path Ensure
// never returns in the parent.
//
// Visibility note: when Ensure creates the namespaces itself (the bare-host,
// unprivileged case), the FUSE mounts made afterward live in the child's private
// mount namespace and are not visible to unrelated processes. To browse them,
// deploy under rootless podman or an outer `unshare -U -m -r` (then Ensure
// detects it via Active() and does NOT nest, so the mount lands in the shared
// container mount namespace and is visible container-wide), or enter the child's
// namespace with `nsenter -t <pid> -m -U`.
func Ensure() error {
	if os.Getenv(sentinel) == "1" {
		return nil // we are the re-exec'd child: already root-in-userns.
	}
	if Active() && os.Geteuid() == 0 {
		return nil // rootless podman / outer unshare already placed us root-in-userns.
	}
	// In a userns but not uid 0 (e.g. a non-root container user) — or not in one at
	// all — we lack the CAP_SYS_ADMIN the FUSE mount needs, so re-exec into a fresh
	// userns that maps us to root.
	return reexec()
}

// Active reports whether the process is in a non-initial user namespace. The
// initial user namespace maps the entire uid range as "0 0 4294967295"; any
// other uid_map means we are already inside a user namespace.
func Active() bool {
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false // cannot tell (e.g. no userns support): treat as initial.
	}
	f := strings.Fields(strings.TrimSpace(string(data)))
	if len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295" {
		return false
	}
	return true
}

// reexec re-runs this binary inside fresh user+mount namespaces with the caller
// mapped to root, then blocks and mirrors the child's exit status.
func reexec() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("userns: locating own executable: %w", err)
	}
	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), sentinel+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		// false => the runtime writes "deny" to /proc/<pid>/setgroups before
		// gid_map, which is mandatory for an unprivileged gid mapping.
		GidMappingsEnableSetgroups: false,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("userns: re-exec into user+mount namespaces failed "+
			"(needs unprivileged user namespaces, Linux >= 4.18 for FUSE): %w", err)
	}
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "gomount: userns child failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
	return nil // unreachable
}
