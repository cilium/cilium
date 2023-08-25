// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"

	"github.com/cilium/ebpf"

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
		ebpf.Hash,
		&AffinityMatchKey{},
		&AffinityMatchValue{},
		AffinityMapMaxEntries,
		0,
	).WithCache().WithPressureMetric().
		WithEvents(option.Config.GetEventBufferConfig(AffinityMatchMapName))

	if params.IPv4 {
		Affinity4Map = bpf.NewMap(
			Affinity4MapName,
			ebpf.LRUHash,
			&Affinity4Key{},
			&AffinityValue{},
			AffinityMapMaxEntries,
			0,
		)
	}

	if params.IPv6 {
		Affinity6Map = bpf.NewMap(
			Affinity6MapName,
			ebpf.LRUHash,
			&Affinity6Key{},
			&AffinityValue{},
			AffinityMapMaxEntries,
			0,
		)
	}
}

type AffinityMatchKey struct {
	BackendID loadbalancer.BackendID `align:"backend_id"`
	RevNATID  uint16                 `align:"rev_nat_id"`
	Pad       uint16                 `align:"pad"`
}

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

// String converts the key into a human readable string format
func (k *AffinityMatchKey) String() string {
	kHost := k.ToHost()
	return fmt.Sprintf("%d %d", kHost.BackendID, kHost.RevNATID)
}

func (k *AffinityMatchKey) New() bpf.MapKey { return &AffinityMatchKey{} }

// String converts the value into a human readable string format
func (v *AffinityMatchValue) String() string    { return "" }
func (v *AffinityMatchValue) New() bpf.MapValue { return &AffinityMatchValue{} }

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
type Affinity4Key struct {
	ClientID    uint64 `align:"client_id"`
	RevNATID    uint16 `align:"rev_nat_id"`
	NetNSCookie uint8  `align:"netns_cookie"`
	Pad1        uint8  `align:"pad1"`
	Pad2        uint32 `align:"pad2"`
}

// Affinity6Key is the Go representation of lb6_affinity_key
type Affinity6Key struct {
	ClientID    types.IPv6 `align:"client_id"`
	RevNATID    uint16     `align:"rev_nat_id"`
	NetNSCookie uint8      `align:"netns_cookie"`
	Pad1        uint8      `align:"pad1"`
	Pad2        uint32     `align:"pad2"`
}

// AffinityValue is the Go representing of lb_affinity_value
type AffinityValue struct {
	LastUsed  uint64 `align:"last_used"`
	BackendID uint32 `align:"backend_id"`
	Pad       uint32 `align:"pad"`
}

// String converts the key into a human readable string format.
func (k *Affinity4Key) String() string {
	return fmt.Sprintf("%d %d %d", k.ClientID, k.NetNSCookie, k.RevNATID)
}

func (k *Affinity4Key) New() bpf.MapKey { return &Affinity4Key{} }

// String converts the key into a human readable string format.
func (k *Affinity6Key) String() string {
	return fmt.Sprintf("%d %d %d", k.ClientID, k.NetNSCookie, k.RevNATID)
}

func (k *Affinity6Key) New() bpf.MapKey { return &Affinity6Key{} }

// String converts the value into a human readable string format.
func (v *AffinityValue) String() string    { return fmt.Sprintf("%d %d", v.BackendID, v.LastUsed) }
func (v *AffinityValue) New() bpf.MapValue { return &AffinityValue{} }
