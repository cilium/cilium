// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"
	"unsafe"

	lbmapTypes "github.com/cilium/cilium/pkg/maps/lbmap/types"

	"github.com/cilium/cilium/pkg/bpf"
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
)

const (
	AffinityMatchMapName = "cilium_lb_affinity_match"
	Affinity4MapName     = "cilium_lb4_affinity"
	Affinity6MapName     = "cilium_lb6_affinity"
)

var (
	// AffinityMatchMap is the BPF map to implement session affinity.
	AffinityMatchMap *bpf.Map
	Affinity4Map     *bpf.Map
	Affinity6Map     *bpf.Map
)

// initAffinity creates the BPF maps for implementing session affinity.
func initAffinity(params InitParams) {
	AffinityMapMaxEntries = params.AffinityMapMaxEntries

	AffinityMatchMap = bpf.NewMap(
		AffinityMatchMapName,
		bpf.MapTypeHash,
		&AffinityMatchKey{},
		int(unsafe.Sizeof(AffinityMatchKey{})),
		&AffinityMatchValue{},
		int(unsafe.Sizeof(AffinityMatchValue{})),
		AffinityMapMaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	).WithCache().WithPressureMetric().
		WithEvents(option.Config.GetEventBufferConfig(AffinityMatchMapName))

	if params.IPv4 {
		Affinity4Map = bpf.NewMap(
			Affinity4MapName,
			bpf.MapTypeLRUHash,
			&Affinity4Key{},
			int(unsafe.Sizeof(Affinity4Key{})),
			&AffinityValue{},
			int(unsafe.Sizeof(AffinityValue{})),
			AffinityMapMaxEntries,
			0,
			0,
			bpf.ConvertKeyValue,
		)
	}

	if params.IPv6 {
		Affinity6Map = bpf.NewMap(
			Affinity6MapName,
			bpf.MapTypeLRUHash,
			&Affinity6Key{},
			int(unsafe.Sizeof(Affinity6Key{})),
			&AffinityValue{},
			int(unsafe.Sizeof(AffinityValue{})),
			AffinityMapMaxEntries,
			0,
			0,
			bpf.ConvertKeyValue,
		)
	}
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type AffinityMatchKey lbmapTypes.AffinityMatchKey

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type AffinityMatchValue lbmapTypes.AffinityMatchValue

// NewAffinityMatchKey creates the AffinityMatch key
func NewAffinityMatchKey(revNATID uint16, backendID loadbalancer.BackendID) *AffinityMatchKey {
	return &AffinityMatchKey{
		BackendID: backendID,
		RevNATID:  revNATID,
	}
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *AffinityMatchKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *AffinityMatchValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format
func (k *AffinityMatchKey) String() string {
	kHost := k.ToHost()
	return fmt.Sprintf("%d %d", kHost.BackendID, kHost.RevNATID)
}

// String converts the value into a human readable string format
func (v *AffinityMatchValue) String() string { return "" }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *AffinityMatchKey) NewValue() bpfTypes.MapValue { return &AffinityMatchValue{} }

// ToNetwork returns the key in the network byte order
func (k *AffinityMatchKey) ToNetwork() *AffinityMatchKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork16(n.RevNATID)
	return &n
}

// ToHost returns the key in the host byte order
func (k *AffinityMatchKey) ToHost() *AffinityMatchKey {
	h := *k
	h.RevNATID = byteorder.NetworkToHost16(h.RevNATID)
	return &h
}

// Affinity4Key is the Go representation of lb4_affinity_key
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type Affinity4Key lbmapTypes.Affinity4Key

// Affinity6Key is the Go representation of lb6_affinity_key
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type Affinity6Key lbmapTypes.Affinity6Key

// AffinityValue is the Go representing of lb_affinity_value
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type AffinityValue lbmapTypes.AffinityValue

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Affinity4Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Affinity6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *AffinityValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *Affinity4Key) String() string {
	return fmt.Sprintf("%d %d %d", k.ClientID, k.NetNSCookie, k.RevNATID)
}

// String converts the key into a human readable string format.
func (k *Affinity6Key) String() string {
	return fmt.Sprintf("%d %d %d", k.ClientID, k.NetNSCookie, k.RevNATID)
}

// String converts the value into a human readable string format.
func (v *AffinityValue) String() string { return fmt.Sprintf("%d %d", v.BackendID, v.LastUsed) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Affinity4Key) NewValue() bpfTypes.MapValue { return &AffinityValue{} }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Affinity6Key) NewValue() bpfTypes.MapValue { return &AffinityValue{} }
