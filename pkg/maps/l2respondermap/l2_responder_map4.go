// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2respondermap

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName           = "cilium_l2_responder_v4"
	DefaultMaxEntries = 4096
)

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip netip.Addr, ifIndex uint32) error
	Lookup(ip netip.Addr, ifIndex uint32) (*L2ResponderStats, error)
	Delete(ip netip.Addr, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

func NewMap(lifecycle cell.Lifecycle) (Map, error) {
	return newMap(lifecycle, DefaultMaxEntries)
}

type l2ResponderMap struct {
	*ebpf.Map
}

func newMap(lifecycle cell.Lifecycle, maxEntries int) (*l2ResponderMap, error) {
	outerMap := &l2ResponderMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
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
func (m *l2ResponderMap) Create(ip netip.Addr, ifIndex uint32) error {
	key := newL2ResponderKey(ip, ifIndex)
	return m.Map.Put(key, L2ResponderStats{})
}

// Delete deletes the entry associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Delete(ip netip.Addr, ifIndex uint32) error {
	key := newL2ResponderKey(ip, ifIndex)
	return m.Map.Delete(key)
}

// Lookup returns the stats object associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Lookup(ip netip.Addr, ifIndex uint32) (*L2ResponderStats, error) {
	key := newL2ResponderKey(ip, ifIndex)
	val := L2ResponderStats{}

	err := m.Map.Lookup(&key, &val)

	return &val, err
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a L2 responder map.
type IterateCallback func(*L2ResponderKey, *L2ResponderStats)

// IterateWithCallback iterates through all the keys/values of a L2 responder map,
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

// L2ResponderKey implements the bpf.MapKey interface.
//
// Must be in sync with struct l2_responder_v4_key in <bpf/lib/maps.h>
type L2ResponderKey struct {
	IP      types.IPv4 `align:"ip"`
	IfIndex uint32     `align:"ifindex"`
}

func (k *L2ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", net.IP(k.IP[:]), k.IfIndex)
}

func newL2ResponderKey(ip netip.Addr, ifIndex uint32) L2ResponderKey {
	return L2ResponderKey{
		IP:      types.IPv4(ip.As4()),
		IfIndex: ifIndex,
	}
}

// L2ResponderStats implements the bpf.MapValue interface.
//
// Must be in sync with struct l2_responder_v4_stats in <bpf/lib/maps.h>
type L2ResponderStats struct {
	ResponsesSent uint64 `align:"responses_sent"`
}

func (s *L2ResponderStats) String() string {
	return fmt.Sprintf("responses_sent=%q", s.ResponsesSent)
}
