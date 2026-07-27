//go:build !(linux || darwin || windows)

package sysfs

import (
	"github.com/tetratelabs/wazero/experimental/sys"
)

// poll implements `Poll` as documented on sys.File via a file descriptor.
func poll(uintptr, sys.Pflag, int32) (bool, sys.Errno) {
	return false, sys.ENOSYS
}
