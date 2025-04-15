// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

package serveroption

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/api"
)

// WithUnixSocketListener configures a unix domain socket listener with the
// given file path. When the process runs in privileged mode, the file group
// owner is set to socketGroup.
func WithUnixSocketListener(scopedLog *slog.Logger, path string) Option {
	return func(o *Options) error {
		if o.Listener != nil {
			return fmt.Errorf("listener already configured")
		}
		socketPath := strings.TrimPrefix(path, "unix://")
		unix.Unlink(socketPath)
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		if os.Getuid() == 0 {
			if err := api.SetDefaultPermissions(scopedLog, socketPath); err != nil {
				socket.Close()
				return err
			}
		}
		o.Listener = socket
		return nil
	}
}
