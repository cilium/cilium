// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/unix"

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

	// MapName is the canonical name for the VTEP map on the filesystem.
	MapName = "cilium_vtep_map"
)

// Map provides access to the eBPF map vtep.
type Map interface {
	Update(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error
	Delete(tunnelEndpoint net.IP) error
	Dump(hash map[string][]string) error
}

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct vtep_key in <bpf/lib/vtep.h>
type Key struct {
	IP types.IPv4 `align:"vtep_ip"`
}

func (k Key) String() string {
	return k.IP.String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

// newKey returns an Key based on the provided IP address and mask.
func newKey(ip net.IP) Key {
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
type vtepMap struct {
	logger *slog.Logger
	bpfMap *bpf.Map
}

func (m *vtepMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *vtepMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

// Function to update vtep map with VTEP CIDR
func (m *vtepMap) Update(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error {
	key := newKey(newCIDR.IP)

	mac, err := vtepMAC.Uint64()
	if err != nil {
		return fmt.Errorf("invalid VTEP MAC: %w", err)
	}

	value := VtepEndpointInfo{
		VtepMAC: mac,
	}

	ip4 := newTunnelEndpoint.To4()
	copy(value.TunnelEndpoint[:], ip4)

	m.logger.Debug(
		"Updating vtep map entry",
		logfields.V4Prefix, newCIDR.IP,
		logfields.MACAddr, vtepMAC,
		logfields.Endpoint, newTunnelEndpoint,
	)

	return m.bpfMap.Update(&key, &value)
}

func (m *vtepMap) Delete(tunnelEndpoint net.IP) error {
	key := newKey(tunnelEndpoint)
	return m.bpfMap.Delete(&key)
}

func (m *vtepMap) Dump(hash map[string][]string) error {
	return m.bpfMap.Dump(hash)
}

func newMap(logger *slog.Logger, registry *metrics.Registry) *vtepMap {
	return &vtepMap{
		bpfMap: bpf.NewMap(
			MapName,
			ebpf.Hash,
			&Key{},
			&VtepEndpointInfo{},
			MaxEntries,
			unix.BPF_F_RDONLY_PROG,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(MapName)),
		logger: logger,
	}
}

// LoadVTEPMap loads the pre-initialized vtep map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadVTEPMap(logger *slog.Logger) Map {
	return newMap(logger, nil)
}
