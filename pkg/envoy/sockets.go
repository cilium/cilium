// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import "path/filepath"

func GetSocketDir(runDir string) string {
	return filepath.Join(runDir, "envoy", "sockets")
}

func getAccessLogSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "access_log.sock")
}

func getXDSSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "xds.sock")
}

func getAdminSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "admin.sock")
}
