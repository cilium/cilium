// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"path/filepath"
	"strings"

	bpffs "github.com/cilium/cilium/pkg/bpf/fs"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"

	"github.com/vishvananda/netlink"
)

type BPFFS struct {
	Root string
}

func (p *BPFFS) CiliumPath() string {
	return bpffs.CiliumPath(p.Root)
}

func (p *BPFFS) TCGlobalsPath() string {
	return bpffs.TCGlobalsPath(p.Root)
}

// devicesDir returns the path to the 'devices' directory on bpffs, usually
// /sys/fs/bpf/cilium/devices. It does not ensure the directory exists.
func (p *BPFFS) devicesDir() string {
	return filepath.Join(p.CiliumPath(), "devices")
}

// DeviceDir returns the path to the per-device directory on bpffs, usually
// /sys/fs/bpf/cilium/devices/<device>. It does not ensure the directory exists.
func (p *BPFFS) DeviceDir(device netlink.Link) string {
	// If a device name contains a "." we must sanitize the string to satisfy bpffs directory path
	// requirements. The string of a directory path on bpffs is not allowed to contain any "." characters.
	// By replacing "." with "-", we circurmvent this limitation. This also introduces a small
	// risk of naming collisions, e.g "eth-0" and "eth.0" would translate to the same bpffs directory.
	// The probability of this happening in practice should be very small.
	return filepath.Join(p.devicesDir(), strings.ReplaceAll(device.Attrs().Name, ".", "-"))
}

// DeviceLinksDir returns the bpffs path to the per-device links directory,
// usually /sys/fs/bpf/cilium/devices/<device>/links. It does not ensure the
// directory exists.
func (p *BPFFS) DeviceLinksDir(device netlink.Link) string {
	return filepath.Join(p.DeviceDir(device), "links")
}

// endpointsDir returns the path to the 'endpoints' directory on bpffs, usually
// /sys/fs/bpf/cilium/endpoints. It does not ensure the directory exists.
func (p *BPFFS) endpointsDir() string {
	return filepath.Join(p.CiliumPath(), "endpoints")
}

// EndpointDir returns the path to the per-endpoint directory on bpffs,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>. It does not ensure the
// directory exists.
func (p *BPFFS) EndpointDir(ep endpoint.Endpoint) string {
	return filepath.Join(p.endpointsDir(), ep.StringID())
}

// EndpointLinksDir returns the bpffs path to the per-endpoint links directory,
// usually /sys/fs/bpf/cilium/endpoints/<endpoint-id>/links. It does not ensure the
// directory exists.
func (p *BPFFS) EndpointLinksDir(ep endpoint.Endpoint) string {
	return filepath.Join(p.EndpointDir(ep), "links")
}
