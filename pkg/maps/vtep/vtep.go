// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-vtep")

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
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	IP types.IPv4 `align:"vtep_ip"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k Key) NewValue() bpf.MapValue { return &VtepEndpointInfo{} }

func (k Key) String() string {
	return k.IP.String()
}

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
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type VtepEndpointInfo struct {
	VtepMAC        mac.Uint64MAC `align:"vtep_mac"`
	TunnelEndpoint types.IPv4    `align:"tunnel_endpoint"`
}

func (v *VtepEndpointInfo) String() string {
	return fmt.Sprintf("vtepmac=%s tunnelendpoint=%s",
		v.VtepMAC, v.TunnelEndpoint)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *VtepEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Map represents an VTEP BPF map.
type Map struct {
	bpf.Map
}

// NewMap instantiates a Map.
func NewMap(name string) *Map {
	return &Map{
		Map: *bpf.NewMap(
			name,
			bpf.MapTypeHash,
			&Key{},
			int(unsafe.Sizeof(Key{})),
			&VtepEndpointInfo{},
			int(unsafe.Sizeof(VtepEndpointInfo{})),
			MaxEntries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

var (
	// VtepMAP is a mapping of all VTEP endpoint MAC, IPs
	vtepMAP     *Map
	vtepMapInit = &sync.Once{}
)

func VtepMap() *Map {
	vtepMapInit.Do(func() {
		vtepMAP = NewMap(Name)
	})
	return vtepMAP
}

// Function to update vtep map with VTEP CIDR
func UpdateVTEPMapping(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error {
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

	log.WithFields(logrus.Fields{
		logfields.V4Prefix: newCIDR.IP,
		logfields.MACAddr:  vtepMAC,
		logfields.Endpoint: newTunnelEndpoint,
	}).Debug("Updating vtep map entry")

	return VtepMap().Update(&key, &value)
}
