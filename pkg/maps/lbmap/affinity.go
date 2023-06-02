// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
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
		0,
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
			bpf.ConvertKeyValue,
		)
	}
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type AffinityMatchKey struct {
	BackendID loadbalancer.BackendID `align:"backend_id"`
	RevNATID  uint16                 `align:"rev_nat_id"`
	Pad       uint16                 `align:"pad"`
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type AffinityMatchValue struct {
	Pad uint8 `align:"pad"`
}

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
func (k *AffinityMatchKey) NewValue() bpf.MapValue { return &AffinityMatchValue{} }

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
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Affinity4Key struct {
	ClientID    uint64 `align:"client_id"`
	RevNATID    uint16 `align:"rev_nat_id"`
	NetNSCookie uint8  `align:"netns_cookie"`
	Pad1        uint8  `align:"pad1"`
	Pad2        uint32 `align:"pad2"`
}

// Affinity6Key is the Go representation of lb6_affinity_key
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Affinity6Key struct {
	ClientID    types.IPv6 `align:"client_id"`
	RevNATID    uint16     `align:"rev_nat_id"`
	NetNSCookie uint8      `align:"netns_cookie"`
	Pad1        uint8      `align:"pad1"`
	Pad2        uint32     `align:"pad2"`
}

// AffinityValue is the Go representing of lb_affinity_value
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type AffinityValue struct {
	LastUsed  uint64 `align:"last_used"`
	BackendID uint32 `align:"backend_id"`
	Pad       uint32 `align:"pad"`
}

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
func (k Affinity4Key) NewValue() bpf.MapValue { return &AffinityValue{} }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Affinity6Key) NewValue() bpf.MapValue { return &AffinityValue{} }
