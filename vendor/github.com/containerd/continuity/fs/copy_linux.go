package fs

import (
	"io"
	"os"
	"syscall"

	"github.com/containerd/continuity/sysx"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func copyFileInfo(fi os.FileInfo, name string) error {
	st := fi.Sys().(*syscall.Stat_t)
	if err := os.Lchown(name, int(st.Uid), int(st.Gid)); err != nil {
		if os.IsPermission(err) {
			// Normally if uid/gid are the same this would be a no-op, but some
			// filesystems may still return EPERM... for instance NFS does this.
			// In such a case, this is not an error.
			if dstStat, err2 := os.Lstat(name); err2 == nil {
				st2 := dstStat.Sys().(*syscall.Stat_t)
				if st.Uid == st2.Uid && st.Gid == st2.Gid {
					err = nil
				}
			}
		}
		if err != nil {
			return errors.Wrapf(err, "failed to chown %s", name)
		}
	}

	if (fi.Mode() & os.ModeSymlink) != os.ModeSymlink {
		if err := os.Chmod(name, fi.Mode()); err != nil {
			return errors.Wrapf(err, "failed to chmod %s", name)
		}
	}

	timespec := []unix.Timespec{unix.Timespec(StatAtime(st)), unix.Timespec(StatMtime(st))}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, name, timespec, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errors.Wrapf(err, "failed to utime %s", name)
	}

	return nil
}

func copyFileContent(dst, src *os.File) error {
	st, err := src.Stat()
	if err != nil {
		return errors.Wrap(err, "unable to stat source")
	}

	size := st.Size()
	first := true
	srcFd := int(src.Fd())
	dstFd := int(dst.Fd())

	for size > 0 {
		n, err := unix.CopyFileRange(srcFd, nil, dstFd, nil, int(size), 0)
		if err != nil {
			if (err != unix.ENOSYS && err != unix.EXDEV) || !first {
				return errors.Wrap(err, "copy file range failed")
			}

			buf := bufferPool.Get().(*[]byte)
			_, err = io.CopyBuffer(dst, src, *buf)
			bufferPool.Put(buf)
			return errors.Wrap(err, "userspace copy failed")
		}

		first = false
		size -= int64(n)
	}

	return nil
}

func copyXAttrs(dst, src string) error {
	xattrKeys, err := sysx.LListxattr(src)
	if err != nil {
		return errors.Wrapf(err, "failed to list xattrs on %s", src)
	}
	for _, xattr := range xattrKeys {
		data, err := sysx.LGetxattr(src, xattr)
		if err != nil {
			return errors.Wrapf(err, "failed to get xattr %q on %s", xattr, src)
		}
		if err := sysx.LSetxattr(dst, xattr, data, 0); err != nil {
			return errors.Wrapf(err, "failed to set xattr %q on %s", xattr, dst)
		}
	}

	return nil
}

func copyDevice(dst string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported stat type")
	}
	return unix.Mknod(dst, uint32(fi.Mode()), int(st.Rdev))
}
