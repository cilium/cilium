// +build solaris

package logrus

import (
	"os"

	"github.com/noironetworks/cilium-net/common/Godeps/_workspace/src/golang.org/x/sys/unix"
)

// IsTerminal returns true if the given file descriptor is a terminal.
func IsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETA)
	return err == nil
}
