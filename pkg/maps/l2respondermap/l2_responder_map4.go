// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2respondermap

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName           = "cilium_l2_responder_v4"
	DefaultMaxEntries = 4096
)

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip net.IP, ifIndex uint32) error
	Lookup(ip net.IP, ifIndex uint32) (*L2ResponderStats, error)
	Delete(ip net.IP, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

func NewMap(lifecycle hive.Lifecycle) (Map, error) {
	return newMap(lifecycle, DefaultMaxEntries)
}

type l2ResponderMap struct {
	*ebpf.Map
}

func newMap(lifecycle hive.Lifecycle, maxEntries int) (*l2ResponderMap, error) {
	outerMap := &l2ResponderMap{}

	lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			var (
				m   *ebpf.Map
				err error
			)

			if m, err = ebpf.LoadRegisterMap(MapName); err != nil {
				m = ebpf.NewMap(&ebpf.MapSpec{
					Name:       MapName,
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(L2ResponderKey{})),
					ValueSize:  uint32(unsafe.Sizeof(L2ResponderStats{})),
					MaxEntries: uint32(maxEntries),
					Flags:      unix.BPF_F_NO_PREALLOC,
					Pinning:    ebpf.PinByName,
				})
				if err := m.OpenOrCreate(); err != nil {
					return err
				}
			}

			outerMap.Map = m

			return nil
		},
	})

	return outerMap, nil
}

// Create creates a new entry for the given IP and IfIndex tuple.
func (m *l2ResponderMap) Create(ip net.IP, ifIndex uint32) error {
	key := newAuthKey(ip, ifIndex)
	return m.Map.Update(key, L2ResponderStats{}, bpf.BPF_ANY)
}

// Delete deletes the entry associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Delete(ip net.IP, ifIndex uint32) error {
	key := newAuthKey(ip, ifIndex)
	return m.Map.Delete(key)
}

// Lookup returns the stats object associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Lookup(ip net.IP, ifIndex uint32) (*L2ResponderStats, error) {
	key := newAuthKey(ip, ifIndex)
	val := L2ResponderStats{}

	err := m.Map.Lookup(&key, &val)

	return &val, err
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an auth map.
type IterateCallback func(*L2ResponderKey, *L2ResponderStats)

// IterateWithCallback iterates through all the keys/values of an auth map,
// passing each key/value pair to the cb callback.
func (m *l2ResponderMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.IterateWithCallback(&L2ResponderKey{}, &L2ResponderStats{},
		func(k, v interface{}) {
			key := k.(*L2ResponderKey)
			value := v.(*L2ResponderStats)
			cb(key, value)
		},
	)
}

// AuthKey implements the bpf.MapKey interface.
//
// Must be in sync with struct auth_key in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type L2ResponderKey struct {
	IP      types.IPv4 `align:"ip"`
	IfIndex uint32     `align:"ifindex"`
}

func (k *L2ResponderKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (k *L2ResponderKey) NewValue() bpf.MapValue { return &L2ResponderStats{} }

func (k *L2ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", net.IP(k.IP[:]), k.IfIndex)
}

func newAuthKey(ip net.IP, ifIndex uint32) L2ResponderKey {
	return L2ResponderKey{
		IP:      types.IPv4(ip.To4()),
		IfIndex: ifIndex,
	}
}

// L2ResponderStats implements the bpf.MapValue interface.
//
// Must be in sync with struct l2_responder_v4_stats in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type L2ResponderStats struct {
	ResponsesSent uint64 `align:"responses_sent"`
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (s *L2ResponderStats) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *L2ResponderStats) String() string {
	return fmt.Sprintf("responses_sent=%q", s.ResponsesSent)
}
