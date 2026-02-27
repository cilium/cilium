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

// Entry represents a single VTEP map entry with key and value.
type Entry struct {
	CIDR           net.IP
	PrefixLen      int
	TunnelEndpoint net.IP
	MAC            mac.MAC
}

// Map provides access to the eBPF map vtep.
type Map interface {
	Update(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error
	Delete(cidr *cidr.CIDR) error
	List() ([]Entry, error)
	Dump(hash map[string][]string) error
}

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct vtep_key in <bpf/lib/vtep.h>
// Prefixlen maps to the embedded struct bpf_lpm_trie_key (first field).
type Key struct {
	Prefixlen uint32     `align:"lpm_key"`
	IP        types.IPv4 `align:"vtep_ip"`
}

func (k Key) String() string {
	return fmt.Sprintf("%s/%d", k.IP, k.Prefixlen)
}

func (k *Key) New() bpf.MapKey { return &Key{} }

// newKey builds an LPM trie key from a net.IPNet.
// The prefix length comes from the CIDR mask, not a global config value.
func newKey(cidrNet *net.IPNet) Key {
	result := Key{}
	if ip4 := cidrNet.IP.To4(); ip4 != nil {
		ones, _ := cidrNet.Mask.Size()
		result.Prefixlen = uint32(ones)
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

// vtepMap implements Map backed by a BPF LPM trie.
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

// Update writes a VTEP entry: maps newCIDR → (tunnelEndpoint, MAC).
// Each CIDR can have a different prefix length; they coexist in the LPM trie.
func (m *vtepMap) Update(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error {
	key := newKey(newCIDR.IPNet)

	vtepMACU64, err := vtepMAC.Uint64()
	if err != nil {
		return fmt.Errorf("invalid VTEP MAC: %w", err)
	}

	value := VtepEndpointInfo{
		VtepMAC: vtepMACU64,
	}

	ip4 := newTunnelEndpoint.To4()
	if ip4 == nil {
		return fmt.Errorf("tunnel endpoint must be an IPv4 address: %s", newTunnelEndpoint)
	}
	copy(value.TunnelEndpoint[:], ip4)

	m.logger.Debug(
		"Updating vtep map entry",
		logfields.V4Prefix, newCIDR,
		logfields.MACAddr, vtepMAC,
		logfields.Endpoint, newTunnelEndpoint,
	)

	return m.bpfMap.Update(&key, &value)
}

// Delete removes the LPM trie entry for the given CIDR.
// The prefix length in the CIDR must exactly match the one used during Update.
func (m *vtepMap) Delete(cidr *cidr.CIDR) error {
	key := newKey(cidr.IPNet)
	m.logger.Debug(
		"Deleting vtep map entry",
		logfields.V4Prefix, cidr,
	)
	return m.bpfMap.Delete(&key)
}

// List returns all entries currently in the VTEP BPF map.
func (m *vtepMap) List() ([]Entry, error) {
	entries := make([]Entry, 0, MaxEntries)

	parse := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*Key)
		v := value.(*VtepEndpointInfo)

		parsedMAC, err := mac.ParseMAC(v.VtepMAC.String())
		if err != nil {
			m.logger.Warn("Failed to parse MAC from VTEP entry",
				logfields.MACAddr, v.VtepMAC.String(),
				logfields.Error, err)
			return
		}

		// Copy the IP bytes — DumpWithCallback may reuse key/value
		// pointers across iterations.
		cidrIP := make(net.IP, 4)
		copy(cidrIP, k.IP[:])
		tunnelIP := make(net.IP, 4)
		copy(tunnelIP, v.TunnelEndpoint[:])

		entries = append(entries, Entry{
			CIDR:           cidrIP,
			PrefixLen:      int(k.Prefixlen),
			TunnelEndpoint: tunnelIP,
			MAC:            parsedMAC,
		})
	}

	if err := m.bpfMap.DumpWithCallback(parse); err != nil {
		return nil, fmt.Errorf("failed to list VTEP entries: %w", err)
	}

	return entries, nil
}

func (m *vtepMap) Dump(hash map[string][]string) error {
	return m.bpfMap.Dump(hash)
}

func newMap(logger *slog.Logger, registry *metrics.Registry) *vtepMap {
	return &vtepMap{
		bpfMap: bpf.NewMap(
			MapName,
			ebpf.LPMTrie,
			&Key{},
			&VtepEndpointInfo{},
			MaxEntries,
			unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
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
