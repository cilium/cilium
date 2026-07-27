package lumberjack

import (
	"os"
	"syscall"
)

// osChown is a var so we can mock it out during tests.
var osChown = os.Chown

func chown(name string, info os.FileInfo) error {
	return chownWithMode(name, info, info.Mode())
}

func chownWithMode(name string, info os.FileInfo, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	f.Close()
	stat := info.Sys().(*syscall.Stat_t)
	return osChown(name, int(stat.Uid), int(stat.Gid))
}
