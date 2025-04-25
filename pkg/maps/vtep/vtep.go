// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// VTEP map.
	MaxEntries = defaults.MaxVTEPDevices

	// Name is the canonical name for the VTEP map on the filesystem.
	Name = "cilium_vtep_map"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct vtep_key in <bpf/lib/common.h>
type Key struct {
	IP types.IPv4 `align:"vtep_ip"`
}

func (k Key) String() string {
	return k.IP.String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

// NewKey returns an Key based on the provided IP address and mask.
func NewKey(ip net.IP) Key {
	result := Key{}

	if ip4 := ip.To4(); ip4 != nil {
		ip4.Mask(net.IPMask(option.Config.VtepCidrMask))
		copy(result.IP[:], ip4)
	}

	return result
}

// VtepEndpointInfo implements the bpf.MapValue interface. It contains the
// VTEP endpoint MAC and IP.
type VtepEndpointInfo struct {
	VtepMAC        mac.Uint64MAC `align:"vtep_mac"`
	TunnelEndpoint types.IPv4    `align:"tunnel_endpoint"`
	_              [4]byte
}

func (v *VtepEndpointInfo) String() string {
	return fmt.Sprintf("vtepmac=%s tunnelendpoint=%s",
		v.VtepMAC, v.TunnelEndpoint)
}

func (v *VtepEndpointInfo) New() bpf.MapValue { return &VtepEndpointInfo{} }

// Map represents an VTEP BPF map.
type Map struct {
	bpf.Map
}

// NewMap instantiates a Map.
func NewMap(registry *metrics.Registry, name string) *Map {
	return &Map{
		Map: *bpf.NewMap(
			name,
			ebpf.Hash,
			&Key{},
			&VtepEndpointInfo{},
			MaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

var (
	// VtepMAP is a mapping of all VTEP endpoint MAC, IPs
	vtepMAP     *Map
	vtepMapInit = &sync.Once{}
)

func VtepMap(registry *metrics.Registry) *Map {
	vtepMapInit.Do(func() {
		vtepMAP = NewMap(registry, Name)
	})
	return vtepMAP
}

// Function to update vtep map with VTEP CIDR
func UpdateVTEPMapping(logger *slog.Logger, registry *metrics.Registry, newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error {
	key := NewKey(newCIDR.IP)

	mac, err := vtepMAC.Uint64()
	if err != nil {
		return fmt.Errorf("invalid VTEP MAC: %w", err)
	}

	value := VtepEndpointInfo{
		VtepMAC: mac,
	}

	ip4 := newTunnelEndpoint.To4()
	copy(value.TunnelEndpoint[:], ip4)

	logger.Debug(
		"Updating vtep map entry",
		logfields.V4Prefix, newCIDR.IP,
		logfields.MACAddr, vtepMAC,
		logfields.Endpoint, newTunnelEndpoint,
	)

	return VtepMap(registry).Update(&key, &value)
}
