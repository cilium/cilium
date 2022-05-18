// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"os"
)

// SetDefaultPermissions sets the given socket's mode to `SocketFileMode`.
func SetDefaultPermissions(socketPath string) error {
	if err := os.Chmod(socketPath, SocketFileMode); err != nil {
		return fmt.Errorf("failed while setting up file permissions for %q: %w",
			socketPath, err)
	}
	return nil
}
