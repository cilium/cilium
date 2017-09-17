// +build linux

package overlay

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/docker/docker/pkg/pools"
	"github.com/docker/docker/pkg/system"
	rsystem "github.com/opencontainers/runc/libcontainer/system"
	"golang.org/x/sys/unix"
)

type copyFlags int

const (
	copyHardlink copyFlags = 1 << iota
)

func copyRegular(srcPath, dstPath string, mode os.FileMode) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = pools.Copy(dstFile, srcFile)

	return err
}

func copyXattr(srcPath, dstPath, attr string) error {
	data, err := system.Lgetxattr(srcPath, attr)
	if err != nil {
		return err
	}
	if data != nil {
		if err := system.Lsetxattr(dstPath, attr, data, 0); err != nil {
			return err
		}
	}
	return nil
}

func copyDir(srcDir, dstDir string, flags copyFlags) error {
	err := filepath.Walk(srcDir, func(srcPath string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Rebase path
		relPath, err := filepath.Rel(srcDir, srcPath)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dstDir, relPath)
		if err != nil {
			return err
		}

		stat, ok := f.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("Unable to get raw syscall.Stat_t data for %s", srcPath)
		}

		isHardlink := false

		switch f.Mode() & os.ModeType {
		case 0: // Regular file
			if flags&copyHardlink != 0 {
				isHardlink = true
				if err := os.Link(srcPath, dstPath); err != nil {
					return err
				}
			} else {
				if err := copyRegular(srcPath, dstPath, f.Mode()); err != nil {
					return err
				}
			}

		case os.ModeDir:
			if err := os.Mkdir(dstPath, f.Mode()); err != nil && !os.IsExist(err) {
				return err
			}

		case os.ModeSymlink:
			link, err := os.Readlink(srcPath)
			if err != nil {
				return err
			}

			if err := os.Symlink(link, dstPath); err != nil {
				return err
			}

		case os.ModeNamedPipe:
			fallthrough
		case os.ModeSocket:
			if rsystem.RunningInUserNS() {
				// cannot create a device if running in user namespace
				return nil
			}
			if err := unix.Mkfifo(dstPath, stat.Mode); err != nil {
				return err
			}

		case os.ModeDevice:
			if err := unix.Mknod(dstPath, stat.Mode, int(stat.Rdev)); err != nil {
				return err
			}

		default:
			return fmt.Errorf("Unknown file type for %s\n", srcPath)
		}

		// Everything below is copying metadata from src to dst. All this metadata
		// already shares an inode for hardlinks.
		if isHardlink {
			return nil
		}

		if err := os.Lchown(dstPath, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}

		if err := copyXattr(srcPath, dstPath, "security.capability"); err != nil {
			return err
		}

		// We need to copy this attribute if it appears in an overlay upper layer, as
		// this function is used to copy those. It is set by overlay if a directory
		// is removed and then re-created and should not inherit anything from the
		// same dir in the lower dir.
		if err := copyXattr(srcPath, dstPath, "trusted.overlay.opaque"); err != nil {
			return err
		}

		isSymlink := f.Mode()&os.ModeSymlink != 0

		// There is no LChmod, so ignore mode for symlink. Also, this
		// must happen after chown, as that can modify the file mode
		if !isSymlink {
			if err := os.Chmod(dstPath, f.Mode()); err != nil {
				return err
			}
		}

		// system.Chtimes doesn't support a NOFOLLOW flag atm
		if !isSymlink {
			aTime := time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
			mTime := time.Unix(int64(stat.Mtim.Sec), int64(stat.Mtim.Nsec))
			if err := system.Chtimes(dstPath, aTime, mTime); err != nil {
				return err
			}
		} else {
			ts := []syscall.Timespec{stat.Atim, stat.Mtim}
			if err := system.LUtimesNano(dstPath, ts); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
