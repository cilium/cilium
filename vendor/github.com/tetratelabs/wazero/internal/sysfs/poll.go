//go:build windows || linux || darwin

package sysfs

import (
	"github.com/tetratelabs/wazero/experimental/sys"
)

// poll implements `Poll` as documented on sys.File via a file descriptor.
func poll(fd uintptr, flag sys.Pflag, timeoutMillis int32) (ready bool, errno sys.Errno) {
	if flag != sys.POLLIN {
		return false, sys.ENOTSUP
	}
	fds := []pollFd{newPollFd(fd, _POLLIN, 0)}
	count, errno := _poll(fds, timeoutMillis)
	return count > 0, errno
}
