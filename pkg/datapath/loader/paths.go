// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"path/filepath"

	"github.com/vishvananda/netlink"
)

// bpffsDevicesDir returns the path to the 'devices' directory on bpffs, usually
// /sys/fs/bpf/cilium/devices. It does not ensure the directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDevicesDir(base string) string {
	return filepath.Join(base, "devices")
}

// bpffsDeviceLinksDir returns the bpffs path to the per-device links directory,
// usually /sys/fs/bpf/cilium/devices/<device>/links. It does not ensure the
// directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDeviceLinksDir(base string, device netlink.Link) string {
	return filepath.Join(bpffsDevicesDir(base), device.Attrs().Name, "links")
}
