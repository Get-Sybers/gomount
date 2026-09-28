// Package ntfs3g mounts a regular file holding a raw NTFS volume image by
// EXECing the distro ntfs-3g(8) binary (GPL-2.0) as a separate process. gomount
// stays permissively licensed: it never links libntfs-3g, it only runs the
// installed binary, so no GPL code enters the gomount address space.
//
// The mount is read-only. ntfs-3g here mounts a *regular file* (not a loop/block
// device), so the kernel mount type is "fuse" (FS_USERNS_MOUNT) rather than
// "fuseblk" — that is what lets the mount happen unprivileged inside a user
// namespace, with no CAP_SYS_ADMIN and no loop device.
package ntfs3g

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// binary is the ntfs-3g executable resolved on PATH.
const binary = "ntfs-3g"

// Opts tunes the ntfs-3g mount. The mount is forced read-only regardless of Opts.
type Opts struct {
	UID        int      // owner uid presented for every file (typically the operator's)
	GID        int      // owner gid
	Umask      string   // octal umask (e.g. "0077"); empty means "0077"
	ShowSys    bool     // show_sys_files: expose $MFT, $LogFile, … in the tree
	WinStreams bool     // streams_interface=windows: expose ADS as name:stream
	Extra      []string // extra -o options appended verbatim (advanced use)
}

// DefaultOpts returns the default mount options, owned by the current process's uid
// and gid so the operator can read every file through the mount.
func DefaultOpts() Opts {
	return Opts{
		UID:        os.Getuid(),
		GID:        os.Getgid(),
		Umask:      "0077",
		ShowSys:    true,
		WinStreams: true,
	}
}

// options renders the -o argument. "ro" is always first: the mount is read-only.
func (o Opts) options() string {
	umask := o.Umask
	if umask == "" {
		umask = "0077"
	}
	opts := []string{"ro"}
	if o.WinStreams {
		opts = append(opts, "streams_interface=windows")
	}
	if o.ShowSys {
		opts = append(opts, "show_sys_files")
	}
	opts = append(opts,
		"uid="+strconv.Itoa(o.UID),
		"gid="+strconv.Itoa(o.GID),
		"umask="+umask,
	)
	opts = append(opts, o.Extra...)
	return strings.Join(opts, ",")
}

// Available reports whether an executable ntfs-3g is on PATH. Returned as an
// error so callers can surface a clear "install the ntfs-3g package" message.
func Available() error {
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("ntfs3g: %s not found on PATH (install the ntfs-3g package): %w", binary, err)
	}
	return nil
}

// MountRO mounts the NTFS volume held in the regular file volFile at mountPoint,
// read-only, by execing ntfs-3g:
//
//	ntfs-3g <volFile> <mountPoint> -o ro,streams_interface=windows,show_sys_files,uid=…,gid=…,umask=0077
//
// It never links libntfs-3g. volFile MUST be a regular file — mounting a regular
// file (not a block/loop device) is what keeps the mount unprivileged. ntfs-3g
// forks into the background once the mount is live, so MountRO returns as soon
// as the mount is established; ntfs-3g's stderr is captured and surfaced on
// failure.
func MountRO(volFile, mountPoint string, opt Opts) error {
	if err := Available(); err != nil {
		return err
	}
	fi, err := os.Stat(volFile)
	if err != nil {
		return fmt.Errorf("ntfs3g: volume file %q: %w", volFile, err)
	}
	if !fi.Mode().IsRegular() {
		// A regular file yields kernel mount type "fuse" (unprivileged); a
		// block/loop device yields "fuseblk" and needs real privilege.
		return fmt.Errorf("ntfs3g: %q is not a regular file; a device would force the privileged fuseblk path", volFile)
	}
	if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		return fmt.Errorf("ntfs3g: mountpoint %q: %w", mountPoint, err)
	}
	args := []string{volFile, mountPoint, "-o", opt.options()}
	cmd := exec.Command(binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("ntfs3g: mount %q at %q failed: %s", volFile, mountPoint, msg)
	}
	return nil
}

// Umount unmounts the ntfs-3g mount at mountPoint (also used for the vfile FUSE
// layer — a FUSE mount is a FUSE mount). It prefers fusermount3 -u (the fuse3
// unprivileged helper), then fusermount -u, then umount(8), and runs in the
// caller's current mount namespace.
func Umount(mountPoint string) error {
	var errs []string
	for _, c := range [][]string{
		{"fusermount3", "-u", mountPoint},
		{"fusermount", "-u", mountPoint},
		{"umount", mountPoint},
	} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Sprintf("%s: %s", c[0], strings.TrimSpace(string(out))))
	}
	if len(errs) == 0 {
		return errors.New("ntfs3g: no unmount helper (fusermount3/fusermount/umount) found on PATH")
	}
	return fmt.Errorf("ntfs3g: umount %q failed: %s", mountPoint, strings.Join(errs, "; "))
}
