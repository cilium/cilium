// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"path/filepath"

	"github.com/cilium/cilium/pkg/option"
)

// bpfStateDeviceDir returns the path to the per-device directory in the Cilium
// state directory, usually /var/run/cilium/bpf/<device>. It does not ensure the
// directory exists.
func bpfStateDeviceDir(device string) string {
	if device == "" {
		return ""
	}
	return filepath.Join(option.Config.StateDir, "bpf", device)
}
