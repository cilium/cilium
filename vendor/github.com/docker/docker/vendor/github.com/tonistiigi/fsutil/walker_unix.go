// +build !windows

package fsutil

import (
	"os"
	"syscall"

	"github.com/pkg/errors"
	"github.com/stevvooe/continuity/sysx"
)

func loadXattr(origpath string, stat *Stat) error {
	xattrs, err := sysx.LListxattr(origpath)
	if err != nil {
		return errors.Wrapf(err, "failed to xattr %s", origpath)
	}
	if len(xattrs) > 0 {
		m := make(map[string][]byte)
		for _, key := range xattrs {
			v, err := sysx.LGetxattr(origpath, key)
			if err == nil {
				m[key] = v
			}
		}
		stat.Xattrs = m
	}
	return nil
}

func setUnixOpt(fi os.FileInfo, stat *Stat, path string, seenFiles map[uint64]string) {
	s := fi.Sys().(*syscall.Stat_t)

	stat.Uid = s.Uid
	stat.Gid = s.Gid

	if !fi.IsDir() {
		if s.Mode&syscall.S_IFBLK != 0 ||
			s.Mode&syscall.S_IFCHR != 0 {
			stat.Devmajor = int64(major(uint64(s.Rdev)))
			stat.Devminor = int64(minor(uint64(s.Rdev)))
		}

		ino := s.Ino
		if s.Nlink > 1 {
			if oldpath, ok := seenFiles[ino]; ok {
				stat.Linkname = oldpath
				stat.Size_ = 0
			}
		}
		seenFiles[ino] = path
	}
}

func major(device uint64) uint64 {
	return (device >> 8) & 0xfff
}

func minor(device uint64) uint64 {
	return (device & 0xff) | ((device >> 12) & 0xfff00)
}
