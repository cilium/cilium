// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// bpffsDevicesDir returns the path to the 'devices' directory on bpffs, usually
// /sys/fs/bpf/cilium/devices. It does not ensure the directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDevicesDir(base string) string {
	return filepath.Join(base, "devices")
}

// bpffsDeviceDir returns the path to the per-device directory on bpffs, usually
// /sys/fs/bpf/cilium/devices/<device>. It does not ensure the directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDeviceDir(base string, device netlink.Link) string {
	// If a device name contains a "." we must sanitize the string to satisfy bpffs directory path
	// requirements. The string of a directory path on bpffs is not allowed to contain any "." characters.
	// By replacing "." with "-", we circurmvent this limitation. This also introduces a small
	// risk of naming collisions, e.g "eth-0" and "eth.0" would translate to the same bpffs directory.
	// The probability of this happening in practice should be very small.
	return filepath.Join(bpffsDevicesDir(base), strings.ReplaceAll(device.Attrs().Name, ".", "-"))
}

// bpffsDeviceLinksDir returns the bpffs path to the per-device links directory,
// usually /sys/fs/bpf/cilium/devices/<device>/links. It does not ensure the
// directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsDeviceLinksDir(base string, device netlink.Link) string {
	return filepath.Join(bpffsDeviceDir(base, device), "links")
}

// bpffsEndpointsDir returns the path to the 'endpoints' directory on bpffs, usually
// /sys/fs/bpf/cilium/endpoints. It does not ensure the directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsEndpointsDir(base string) string {
	return filepath.Join(base, "endpoints")
}

// bpffsEndpointDir returns the path to the per-endpoint directory on bpffs,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>. It does not ensure the
// directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsEndpointDir(base string, ep datapath.Endpoint) string {
	return filepath.Join(bpffsEndpointsDir(base), ep.StringID())
}

// bpffsEndpointLinksDir returns the bpffs path to the per-endpoint links directory,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>/links. It does not ensure the
// directory exists.
//
// base is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func bpffsEndpointLinksDir(base string, ep datapath.Endpoint) string {
	return filepath.Join(bpffsEndpointDir(base, ep), "links")
}
