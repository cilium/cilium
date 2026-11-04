// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

// MapName is the canonical name for the VTEP map on the filesystem.
const MapName = "cilium_vtep_map"

// Map provides access to the eBPF map vtep.
type Map interface {
	Update(newCIDR netip.Prefix, newTunnelEndpoint netip.Addr, vtepMAC mac.MAC) error
	Delete(tunnelEndpoint netip.Addr) error
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
func newKey(addr netip.Addr) Key {
	result := Key{}

	if addr.Is4() {
		ip4 := addr.As4()
		maskBytes := option.Config.VtepCidrMask.As4()
		for i := range ip4 {
			ip4[i] &= maskBytes[i]
		}
		result.IP = ip4
	}

	return result
}

// VtepEndpointInfo implements the bpf.MapValue interface. It contains the
// VTEP endpoint MAC and IP.
type VtepEndpointInfo struct {
	VtepMAC        mac.MAC `align:"vtep_mac"`
	_              [2]byte
	TunnelEndpoint types.IPv4 `align:"tunnel_endpoint"`
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
func (m *vtepMap) Update(newCIDR netip.Prefix, newTunnelEndpoint netip.Addr, vtepMAC mac.MAC) error {
	key := newKey(newCIDR.Addr())

	value := VtepEndpointInfo{
		VtepMAC:        vtepMAC,
		TunnelEndpoint: newTunnelEndpoint.As4(),
	}

	m.logger.Debug(
		"Updating vtep map entry",
		logfields.V4Prefix, newCIDR.Addr(),
		logfields.MACAddr, vtepMAC,
		logfields.Endpoint, newTunnelEndpoint,
	)

	return m.bpfMap.Update(&key, &value)
}

func (m *vtepMap) Delete(tunnelEndpoint netip.Addr) error {
	key := newKey(tunnelEndpoint)
	return m.bpfMap.Delete(&key)
}

func (m *vtepMap) Dump(hash map[string][]string) error {
	return m.bpfMap.Dump(hash)
}

// OpenMap opens an already initialized cilium_vtep_map. Direct use of this
// outside of this package is solely for cilium-dbg.
func OpenMap(logger *slog.Logger) (Map, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, MapName), &Key{}, &VtepEndpointInfo{})
	if err != nil {
		return nil, err
	}

	return &vtepMap{logger: logger, bpfMap: m}, nil
}
