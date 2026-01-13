// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import "path/filepath"

func GetSocketDir(runDir string) string {
	return filepath.Join(runDir, "envoy", "sockets")
}

func GetAccessLogSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "access_log.sock")
}

func GetXDSSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "xds.sock")
}

func GetAdminSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "admin.sock")
}
